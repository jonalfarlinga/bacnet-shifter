// Package shifter is the proxy: the site client, discovery, the consumer
// dispatch, and the translation between them.
//
// The site side is the library's client, opened read-only under no-write.
// Every I-Am it hears gives the device its pseudonyms in the table, one
// read of the device's name, and an announcement on the consumer side. The
// consumer side is the server package; the shifter is its handler, and
// answers each request from the table, or forwards it to the site through
// the client and translates what comes back.
package shifter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/survey"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
	"github.com/jonalfarlinga/bacnet-shifter/internal/translate"
)

// Defaults for what the configuration leaves unset.
const (
	DefaultWhoIsInterval  = time.Second
	DefaultRecent         = 10 * time.Minute
	DefaultCOVLifetime    = 5 * time.Minute
	DefaultCOVMaxLifetime = 24 * time.Hour
)

// Config is what the shifter runs with. The caller fills in where the two
// sockets are; the shifter sets what it needs on them.
type Config struct {
	// Site is the configuration of the site client: Local, BindAny,
	// Broadcast, Exclude, ForeignDevice, Timeout, Retries,
	// MaxRequestsPerSec and OnPacket are the caller's. The shifter sets
	// ReadOnly, OnIAm, MaxInFlightNet and Logger.
	Site client.Config
	// Add is the addresses read at start, for devices no Who-Is reaches.
	Add []client.Address
	// WhoIsInterval bounds how often a consumer's Who-Is is forwarded.
	WhoIsInterval time.Duration
	// COVLifetime is the lifetime of the shifter's own subscriptions.
	COVLifetime time.Duration
	// MaxInFlightNet is the client's in-flight limit per routed network.
	MaxInFlightNet int
	// Writer sends the writes of full-service to the site; nil is
	// the site client. The tests put a fake here to inject the site's
	// answers.
	Writer SiteWriter
	// Survey is the daily survey of the site's addresses (survey.go); nil
	// runs none.
	Survey *SurveyConfig

	// Consumer is the configuration of the consumer socket: Local,
	// BindAny, Broadcast, Exclude, Timeout, Retries and OnPacket are the
	// caller's. The shifter sets Logger.
	Consumer server.Config
	// Recent is how long a consumer counts as recent, to be told of a new
	// device by unicast.
	Recent time.Duration
	// COVMaxLifetime is the ceiling on a consumer's subscription.
	COVMaxLifetime time.Duration

	Control  control.Level
	Reserved control.Reserved
	// Replaced is the properties whose string values are replaced.
	Replaced map[uint32]bool
	// Table is the open table, which carries V.
	Table  *table.Table
	Logger *slog.Logger
}

// Shifter is the running proxy.
type Shifter struct {
	cfg   Config
	log   *slog.Logger
	table *table.Table
	site  *client.Client
	srv   *server.Server
	rules translate.Rules
	// writer sends the writes to the site (write.go).
	writer SiteWriter

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// slots bounds how many devices are being identified at once.
	slots chan struct{}
	// cov is the COV fan-out (cov.go).
	cov *covState

	mu sync.Mutex
	// heard is the devices announced this run.
	heard map[uint32]bool
	// recent is when each consumer was last heard from.
	recent    map[string]recentPeer
	lastWhoIs time.Time
	// surveying is the survey running now, which hears the I-Ams too.
	surveying *survey.Survey
}

type recentPeer struct {
	peer server.Peer
	at   time.Time
}

// Start opens both sockets, announces the virtual networks and sends the
// first Who-Is.
func Start(cfg Config) (*Shifter, error) {
	if cfg.Table == nil {
		return nil, errors.New("no table")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.WhoIsInterval <= 0 {
		cfg.WhoIsInterval = DefaultWhoIsInterval
	}
	if cfg.Recent <= 0 {
		cfg.Recent = DefaultRecent
	}
	if cfg.COVLifetime <= 0 {
		cfg.COVLifetime = DefaultCOVLifetime
	}
	if cfg.COVMaxLifetime <= 0 {
		cfg.COVMaxLifetime = DefaultCOVMaxLifetime
	}
	if cfg.MaxInFlightNet <= 0 {
		cfg.MaxInFlightNet = client.DefaultMaxInFlightNet
	}
	if cfg.Replaced == nil {
		var err error
		if cfg.Replaced, err = control.ParseReplaced(control.DefaultReplacedNames); err != nil {
			return nil, err
		}
	}
	s := &Shifter{
		cfg: cfg, log: cfg.Logger, table: cfg.Table,
		slots:  make(chan struct{}, 4),
		heard:  map[uint32]bool{},
		recent: map[string]recentPeer{},
		cov:    newCOVState(),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.rules = translate.Rules{
		Device: func(real uint32) (uint32, bool) {
			d, err := s.table.Reference(real)
			if err != nil {
				s.log.Error("table", "error", err)
				return 0, false
			}
			return d.Virtual, true
		},
		Known:   s.table.Known,
		Network: s.table.VirtualNetwork,
		DeviceMAC: func(real uint32) ([]byte, bool) {
			d, err := s.table.Reference(real)
			return d.VirtualMAC(), err == nil
		},
		MACAt: func(net uint16, mac []byte) ([]byte, bool) {
			d, ok := s.table.AtReal(net, mac)
			if !ok {
				return nil, false
			}
			return d.VirtualMAC(), true
		},
		OnUnmapped: func(net uint16, mac []byte) {
			s.log.Info("an address in a value names no device the table knows; rewritten to the broadcast", "network", net, "mac", fmt.Sprintf("%x", mac))
		},
	}

	cfg.Site.ReadOnly = cfg.Control == control.NoWrite
	cfg.Site.OnIAm = s.onIAm
	cfg.Site.Logger = cfg.Logger.With("side", "site")
	inFlight := cfg.MaxInFlightNet
	cfg.Site.MaxInFlightNet = func(uint16) int { return inFlight }
	cfg.Consumer.Logger = cfg.Logger.With("side", "consumer")

	srv, err := server.Open(cfg.Consumer, s)
	if err != nil {
		return nil, fmt.Errorf("consumer socket: %w", err)
	}
	s.srv = srv
	site, err := client.Open(cfg.Site)
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("site client: %w", err)
	}
	s.site = site
	s.writer = cfg.Writer
	if s.writer == nil {
		s.writer = site
	}
	s.log.Info("shifter started", "site", site.Local(), "consumer", srv.Local(), "control", cfg.Control, "network", s.table.V())

	// A router announces itself and its networks when it comes up.
	s.announceRouter(s.table.VirtualNetworks())
	s.mu.Lock()
	s.lastWhoIs = time.Now()
	s.mu.Unlock()
	if err := site.WhoIs(); err != nil {
		s.log.Warn("the first Who-Is was not sent", "error", err)
	}
	for _, addr := range cfg.Add {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.probe(addr)
		}()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.covSweeper()
	}()
	s.startSurveys()
	return s, nil
}

// Close stops both sides and saves the table. Every upstream subscription
// is cancelled first, since the client's Close does not.
func (s *Shifter) Close() error {
	s.covCloseAll()
	s.cancel()
	err := s.srv.Close()
	if cerr := s.site.Close(); err == nil {
		err = cerr
	}
	s.wg.Wait()
	if serr := s.table.Save(); err == nil {
		err = serr
	}
	return err
}

// ConsumerAddr is the address consumers reach the shifter at.
func (s *Shifter) ConsumerAddr() netip.AddrPort { return s.srv.Local() }

// SiteAddr is the address the shifter reaches the site from.
func (s *Shifter) SiteAddr() netip.AddrPort { return s.site.Local() }

// Table is the shifter's table.
func (s *Shifter) Table() *table.Table { return s.table }

// ---- the site side ---------------------------------------------------------

// onIAm runs on the client's read loop and must not block. A running
// survey hears every I-Am too.
func (s *Shifter) onIAm(dev client.Device) {
	s.mu.Lock()
	sv := s.surveying
	s.mu.Unlock()
	if sv != nil {
		sv.Hear(dev)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case s.slots <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		defer func() { <-s.slots }()
		s.discovered(dev)
	}()
}

// probe reads what an I-Am would have said about the device at an address
// the configuration lists.
func (s *Shifter) probe(addr client.Address) {
	ctx, cancel := context.WithTimeout(s.ctx, time.Minute)
	defer cancel()
	dev, err := s.site.Probe(ctx, addr, 0)
	if err != nil {
		s.log.Warn("the device at an added address did not answer", "address", addr, "error", err)
		return
	}
	s.discovered(dev)
}

// discovered gives a device heard from the site its pseudonyms, reads its
// name, and announces it on the consumer side the first time this run.
func (s *Shifter) discovered(dev client.Device) {
	if dev.Addr.Net != 0 {
		n, created, err := s.table.EnsureNetwork(dev.Addr.Net)
		if err != nil {
			s.log.Error("table", "error", err)
			return
		}
		if created {
			s.log.Info("site network", "real", n.Number, "virtual", n.Virtual)
			s.announceRouter([]uint16{n.Virtual})
		}
	}
	seen, err := s.table.EnsureDevice(dev)
	if err != nil {
		s.log.Error("table", "error", err)
		return
	}
	d := seen.Device
	vnet, _ := s.table.VirtualAddress(d)
	if seen.Duplicate {
		s.log.Warn("a second device claims an instance already heard at another address; the first keeps it", "instance", dev.Instance, "address", dev.Addr, "first", d.Address)
		return
	}
	if seen.Moved {
		s.log.Warn("device address changed", "instance", dev.Instance, "address", dev.Addr)
	}
	obj := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeDevice, InstanceNumber: dev.Instance}
	if _, named := s.table.Name(dev.Instance, obj); !named || seen.Created {
		ctx, cancel := context.WithTimeout(s.ctx, time.Minute)
		values, err := s.site.ReadProperty(ctx, dev.Addr, client.ObjectID{Type: objects.ObjectTypeDevice, Instance: dev.Instance}, objects.PropertyIdObjectName)
		cancel()
		switch {
		case err != nil:
			s.log.Warn("the device's name could not be read", "instance", dev.Instance, "address", dev.Addr, "error", err)
		case len(values) == 1 && values[0].Kind == client.KindString:
			if _, err := s.table.EnsureName(dev.Instance, obj, values[0].Str); err != nil {
				s.log.Error("table", "error", err)
			}
		}
	}
	s.mu.Lock()
	first := !s.heard[dev.Instance]
	s.heard[dev.Instance] = true
	s.mu.Unlock()
	if first {
		if s.cfg.Control >= control.FullService {
			// The client's guard takes a write only to a device switched
			// to writable; below full-service none is, so the guard still
			// refuses whatever the dispatch did.
			instance := dev.Instance
			if err := s.site.SetWritable(client.SourceRule{Instance: &instance}, true); err != nil {
				s.log.Error("the device could not be switched writable", "instance", dev.Instance, "error", err)
			}
		}
		name, _ := s.table.Name(dev.Instance, obj)
		s.log.Info("device", "real", dev.Instance, "name", name.Real, "address", dev.Addr,
			"virtual", d.Virtual, "pseudonym", name.Pseudonym, "network", vnet, "mac", fmt.Sprintf("%04x", d.MAC), "new", seen.Created)
		s.announce(d)
	}
}

// source is the virtual address a device's messages come from.
func (s *Shifter) source(d table.Device) server.Source {
	net, mac := s.table.VirtualAddress(d)
	return server.Source{Net: net, MAC: mac}
}

// iAm is the I-Am of a virtual device: the real device's max-APDU and
// vendor, and its segmentation downgraded to what the shifter accepts.
func (s *Shifter) iAm(d table.Device) []objects.APDUPayload {
	maxAPDU := d.MaxAPDU
	if maxAPDU == 0 {
		maxAPDU = server.MaxAPDU
	}
	seg := d.Segmentation
	switch seg {
	case 0:
		seg = 1 // both: transmit
	case 2:
		seg = 3 // receive: none
	}
	return services.IAmObjects(d.Virtual, maxAPDU, seg, d.VendorID)
}

// announce tells the consumer side of a device: one routed I-Am, broadcast
// on the consumer subnet and unicast to every recent consumer.
func (s *Shifter) announce(d table.Device) {
	src, payload := s.source(d), s.iAm(d)
	if err := s.srv.BroadcastUnconfirmed(src, services.ServiceUnconfirmedIAm, payload); err != nil {
		s.log.Warn("announcement not sent", "error", err)
	}
	for _, p := range s.recentPeers() {
		s.srv.Unconfirmed(p, src, services.ServiceUnconfirmedIAm, payload)
	}
}

// announceRouter tells the consumer side which networks the shifter routes
// to.
func (s *Shifter) announceRouter(nets []uint16) {
	data := plumbing.NetworksData(nets...)
	s.srv.BroadcastNetworkMessage(plumbing.NetMsgIAmRouterToNetwork, data)
	for _, p := range s.recentPeers() {
		s.srv.NetworkMessage(p.IP, plumbing.NetMsgIAmRouterToNetwork, data)
	}
}

// forwardWhoIs sends a Who-Is to the site on a consumer's behalf, unless
// one went within the interval.
func (s *Shifter) forwardWhoIs() {
	now := time.Now()
	s.mu.Lock()
	due := now.Sub(s.lastWhoIs) >= s.cfg.WhoIsInterval
	if due {
		s.lastWhoIs = now
	}
	s.mu.Unlock()
	if due {
		if err := s.site.WhoIs(); err != nil {
			s.log.Warn("Who-Is not forwarded", "error", err)
		}
	}
}

// ---- consumers -------------------------------------------------------------

func (s *Shifter) noteConsumer(p server.Peer) {
	s.mu.Lock()
	s.recent[p.Key()] = recentPeer{peer: p, at: time.Now()}
	s.mu.Unlock()
}

func (s *Shifter) recentPeers() []server.Peer {
	cutoff := time.Now().Add(-s.cfg.Recent)
	s.mu.Lock()
	defer s.mu.Unlock()
	var peers []server.Peer
	for key, r := range s.recent {
		if r.at.Before(cutoff) {
			delete(s.recent, key)
			continue
		}
		peers = append(peers, r.peer)
	}
	return peers
}

// rejectNetwork tells a consumer the shifter routes to no such network.
func (s *Shifter) rejectNetwork(to netip.AddrPort, dnet uint16) {
	s.log.Debug("rejected a message to a network the shifter does not route to", "to", to, "network", dnet)
	s.srv.NetworkMessage(to, plumbing.NetMsgRejectMessageToNetwork, []byte{1, byte(dnet >> 8), byte(dnet)})
}

// target finds the device a request's envelope names, or says why there is
// none: a request with no destination network, a broadcast, or an address
// nobody is at gets nothing; an unknown network a reject.
func (s *Shifter) target(env server.Envelope) (server.Source, table.Device, bool) {
	dest, ok := env.Dest()
	if !ok {
		if env.HasDest && !env.Global() && !s.table.IsVirtualNetwork(env.DNET) {
			s.rejectNetwork(env.Peer.IP, env.DNET)
		}
		return server.Source{}, table.Device{}, false
	}
	if !s.table.IsVirtualNetwork(dest.Net) {
		s.rejectNetwork(env.Peer.IP, dest.Net)
		return server.Source{}, table.Device{}, false
	}
	dev, ok := s.table.At(dest.Net, dest.MAC)
	if !ok {
		s.log.Debug("dropped a request for an address nobody is at", "from", env.Peer, "network", dest.Net, "mac", fmt.Sprintf("%x", dest.MAC))
		return server.Source{}, table.Device{}, false
	}
	return dest, dev, true
}

// Network implements server.Handler: the shifter answers
// Who-Is-Router-To-Network for the networks it routes to and nothing else.
func (s *Shifter) Network(env server.Envelope, m *plumbing.NetworkMessage) {
	s.noteConsumer(env.Peer)
	if m.Type != plumbing.NetMsgWhoIsRouterToNetwork {
		s.log.Debug("dropped a network layer message", "from", env.Peer, "type", fmt.Sprintf("%#x", m.Type))
		return
	}
	asked, err := m.Networks()
	if err != nil {
		return
	}
	nets := s.table.VirtualNetworks()
	if len(asked) == 1 {
		if !s.table.IsVirtualNetwork(asked[0]) {
			return
		}
		nets = asked
	}
	s.srv.NetworkMessage(env.Peer.IP, plumbing.NetMsgIAmRouterToNetwork, plumbing.NetworksData(nets...))
}

// Unconfirmed implements server.Handler.
func (s *Shifter) Unconfirmed(env server.Envelope, apdu *plumbing.APDU) {
	s.noteConsumer(env.Peer)
	switch apdu.Service {
	case services.ServiceUnconfirmedWhoIs:
		s.whoIs(env, apdu)
	case services.ServiceUnconfirmedWhoHas:
		s.whoHas(env, apdu)
	default:
		s.log.Debug("dropped an unconfirmed request", "from", env.Peer, "service", control.UnconfirmedServiceName(apdu.Service))
	}
}

// selectDevices lists the devices a Who-Is or Who-Has envelope addresses.
func (s *Shifter) selectDevices(env server.Envelope) []table.Device {
	switch {
	case !env.HasDest || env.Global():
		return s.table.Devices(0)
	case !s.table.IsVirtualNetwork(env.DNET):
		s.rejectNetwork(env.Peer.IP, env.DNET)
		return nil
	case len(env.DADR) == 0:
		return s.table.Devices(env.DNET)
	}
	if d, ok := s.table.At(env.DNET, env.DADR); ok {
		return []table.Device{d}
	}
	return nil
}

func tagsOf(apdu *plumbing.APDU) []*objects.Object {
	tags := make([]*objects.Object, 0, len(apdu.Objects))
	for _, p := range apdu.Objects {
		if t, ok := p.(*objects.Object); ok {
			tags = append(tags, t)
		}
	}
	return tags
}

func isContext(t *objects.Object, number uint8) bool {
	return t.TagClass && t.Kind == objects.TagPrimitive && t.TagNumber == number
}

func uintOf(t *objects.Object) uint32 {
	var v uint32
	for _, b := range t.Data {
		v = v<<8 | uint32(b)
	}
	return v
}

// whoIs answers with one routed I-Am per device the envelope and the range
// select, and forwards a Who-Is to the site.
func (s *Shifter) whoIs(env server.Envelope, apdu *plumbing.APDU) {
	low, high := uint32(0), uint32(translate.Wildcard)
	if tags := tagsOf(apdu); len(tags) == 2 && isContext(tags[0], 0) && isContext(tags[1], 1) {
		low, high = uintOf(tags[0]), uintOf(tags[1])
	}
	for _, d := range s.selectDevices(env) {
		if d.Virtual < low || d.Virtual > high {
			continue
		}
		s.srv.Unconfirmed(env.Peer, s.source(d), services.ServiceUnconfirmedIAm, s.iAm(d))
	}
	s.forwardWhoIs()
}

// whoHas answers from the table with an I-Have for each object the request
// names, by pseudonym or by identifier, on the devices the envelope and the
// range select. It is never forwarded.
func (s *Shifter) whoHas(env server.Envelope, apdu *plumbing.APDU) {
	req := services.UnconfirmedWhoHas{APDU: apdu}
	dec, err := req.Decode()
	if err != nil {
		s.log.Debug("dropped a Who-Has that could not be decoded", "from", env.Peer, "error", err)
		return
	}
	var names []table.Name
	switch {
	case dec.ObjectID == nil:
		names = s.table.NamesByPseudonym(dec.ObjectName)
	case dec.ObjectID.ObjectType == objects.ObjectTypeDevice:
		if d, ok := s.table.ByVirtual(dec.ObjectID.InstanceNumber); ok {
			if n, ok := s.table.Name(d.Instance, objects.ObjectIdentifier{ObjectType: objects.ObjectTypeDevice, InstanceNumber: d.Instance}); ok {
				names = []table.Name{n}
			}
		}
	default:
		names = s.table.NamesOf(*dec.ObjectID)
	}
	selected := map[uint32]table.Device{}
	for _, d := range s.selectDevices(env) {
		selected[d.Instance] = d
	}
	for _, n := range names {
		d, ok := selected[n.Device]
		if !ok || (dec.HasLimits && (d.Virtual < dec.LowLimit || d.Virtual > dec.HighLimit)) {
			continue
		}
		obj := n.Object()
		if obj.ObjectType == objects.ObjectTypeDevice {
			obj.InstanceNumber = d.Virtual
		}
		s.srv.Unconfirmed(env.Peer, s.source(d), services.ServiceUnconfirmedIHave, []objects.APDUPayload{
			objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, d.Virtual),
			objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, obj.ObjectType, obj.InstanceNumber),
			objects.EncString(n.Pseudonym),
		})
	}
}

// Confirmed implements server.Handler: the level decides, then the service.
func (s *Shifter) Confirmed(req *server.Request) {
	s.noteConsumer(req.Peer)
	from, dev, ok := s.target(req.Envelope)
	if !ok {
		req.Drop()
		return
	}
	if ans := s.cfg.Control.Confirmed(req.Service); !ans.Forward {
		s.refuse(req, from, ans)
		return
	}
	if s.cfg.Control.ReservedService(req.Service, s.cfg.Reserved) {
		s.refuse(req, from, control.Denied)
		return
	}
	switch req.Service {
	case services.ServiceConfirmedReadProperty:
		s.readProperty(req, from, dev)
	case services.ServiceConfirmedReadPropMultiple:
		s.readPropertyMultiple(req, from, dev)
	case services.ServiceConfirmedReadRange:
		s.readRange(req, from, dev)
	case services.ServiceConfirmedSubscribeCOV:
		s.subscribeCOV(req, from, dev)
	case services.ServiceConfirmedWriteProperty:
		s.writeProperty(req, from, dev)
	default:
		// A service the level forwards but this milestone does not build.
		s.refuse(req, from, control.Denied)
	}
}

// refuse answers a request with its documented refusal and logs it.
func (s *Shifter) refuse(req *server.Request, from server.Source, ans control.Answer) {
	attrs := []any{"from", req.Peer, "service", control.ServiceName(req.Service), "control", s.cfg.Control}
	if len(req.Tags) >= 1 {
		if id, ok := translate.ObjectID(req.Tags[0]); ok {
			attrs = append(attrs, "object", fmt.Sprintf("%s %d", objects.ObjectTypeName(id.ObjectType), id.InstanceNumber))
		}
	}
	if len(req.Tags) >= 2 && isContext(req.Tags[1], 1) {
		attrs = append(attrs, "property", control.PropertyName(uintOf(req.Tags[1])))
	}
	if ans.Reject {
		s.log.Info("refused with a Reject", append(attrs, "reason", objects.RejectReasonMap[ans.Reason])...)
		req.Reject(from, ans.Reason)
		return
	}
	s.log.Info("refused with an Error", append(attrs, "class", client.ErrorClassName(uint32(ans.Class)), "code", client.ErrorCodeName(uint32(ans.Code)))...)
	req.Error(from, uint32(ans.Class), uint32(ans.Code))
}

// fault answers a request as the site's outcome says.
func (s *Shifter) fault(req *server.Request, from server.Source, err error) {
	var (
		be *client.BACnetError
		re *client.RejectError
		ae *client.AbortError
	)
	attrs := []any{"from", req.Peer, "service", control.ServiceName(req.Service), "error", err}
	switch {
	case errors.As(err, &be):
		req.Error(from, be.Class, be.Code)
	case errors.As(err, &re):
		req.Reject(from, re.Reason)
	case errors.As(err, &ae):
		req.Abort(from, ae.Reason)
	case errors.Is(err, client.ErrResponseTooLarge):
		s.log.Warn("the site's reply was too long to reassemble", attrs...)
		req.Abort(from, objects.AbortReasonBufferOverflow)
	case errors.Is(err, client.ErrTimeout), errors.Is(err, client.ErrNetworkUnreachable):
		s.log.Debug("no answer from the site; the consumer gets none", attrs...)
		req.Drop()
	case errors.Is(err, client.ErrClosed), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		req.Drop()
	case errors.Is(err, client.ErrServiceNotAllowed), errors.Is(err, client.ErrSourceDenied):
		s.log.Error("the library's guard refused a request the dispatch let through", attrs...)
		req.Error(from, uint32(objects.ErrorClassServices), uint32(objects.ErrorCodeServiceRequestDenied))
	default:
		s.log.Warn("the site's reply could not be read", attrs...)
		req.Abort(from, objects.AbortReasonOther)
	}
}

// upstreamObject maps the object identifier of a request to the real one:
// a device object by its virtual instance. ok is false for a virtual
// instance the shifter never issued, which the consumer is told does not
// exist rather than being passed to the site.
func (s *Shifter) upstreamObject(id objects.ObjectIdentifier) (objects.ObjectIdentifier, bool) {
	if !translate.IsDevice(id) {
		return id, true
	}
	d, ok := s.table.ByVirtual(id.InstanceNumber)
	if !ok {
		return id, false
	}
	id.InstanceNumber = d.Instance
	return id, true
}

// downstreamObject maps a real object identifier the site echoed to the
// consumer's: a device object by its virtual instance.
func (s *Shifter) downstreamObject(id objects.ObjectIdentifier) objects.ObjectIdentifier {
	if translate.IsDevice(id) {
		if v, ok := s.rules.Device(id.InstanceNumber); ok {
			id.InstanceNumber = v
		}
	}
	return id
}

// downstream translates the values of one property of one real object on
// their way to the consumer: device identifiers and addresses by rule, and
// the strings of a replaced property through the table.
func (s *Shifter) downstream(dev table.Device, obj objects.ObjectIdentifier, prop uint32, values []client.Value) []client.Value {
	values = s.rules.Values(values)
	if prop == uint32(objects.PropertyIdDeviceAddressBinding) {
		values = s.rules.AddressBindings(values)
	}
	if !s.cfg.Replaced[prop] {
		return values
	}
	key := obj
	if key.ObjectType == objects.ObjectTypeDevice && key.InstanceNumber == translate.Wildcard {
		key.InstanceNumber = dev.Instance
	}
	return translate.ReplaceStrings(values, func(str string) string {
		var (
			p   string
			err error
		)
		if prop == uint32(objects.PropertyIdObjectName) {
			p, err = s.table.EnsureName(dev.Instance, key, str)
		} else {
			p, err = s.table.EnsureText(dev.Instance, key, prop, str)
		}
		if err != nil {
			s.log.Error("table", "error", err)
		}
		return p
	})
}

func toClientID(id objects.ObjectIdentifier) client.ObjectID {
	return client.ObjectID{Type: id.ObjectType, Instance: id.InstanceNumber}
}

// encodeValues is translate.Encode as a payload.
func encodeValues(values []client.Value) []objects.APDUPayload {
	tags := translate.Encode(values)
	payload := make([]objects.APDUPayload, len(tags))
	for i, t := range tags {
		payload[i] = t
	}
	return payload
}

func toObjectID(id client.ObjectID) objects.ObjectIdentifier {
	return objects.ObjectIdentifier{ObjectType: id.Type, InstanceNumber: id.Instance}
}

// readHeader parses the object [0], property [1] and optional index [2] a
// read starts with. ans says how to refuse a request that has them wrong.
func readHeader(tags []*objects.Object) (obj objects.ObjectIdentifier, prop uint32, index *uint32, ans *control.Answer) {
	if len(tags) < 2 {
		return obj, 0, nil, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
	}
	id, ok := translate.ObjectID(tags[0])
	if !ok || !isContext(tags[0], 0) || !isContext(tags[1], 1) || len(tags[1].Data) == 0 || len(tags[1].Data) > 4 {
		return obj, 0, nil, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType}
	}
	prop = uintOf(tags[1])
	if len(tags) > 2 && isContext(tags[2], 2) {
		i := uintOf(tags[2])
		index = &i
	}
	if prop > 0xFFFF {
		// The client's read methods take a 16-bit property identifier.
		return obj, 0, nil, &control.RejectOther
	}
	return id, prop, index, nil
}

// readProperty forwards a ReadProperty and answers with the translated
// value.
func (s *Shifter) readProperty(req *server.Request, from server.Source, dev table.Device) {
	obj, prop, index, ans := readHeader(req.Tags)
	if ans != nil {
		s.refuse(req, from, *ans)
		return
	}
	real, ok := s.upstreamObject(obj)
	if !ok {
		s.log.Info("read of a device the shifter never issued", "from", req.Peer, "object", obj.InstanceNumber)
		req.Error(from, uint32(objects.ErrorClassObject), uint32(control.ErrorCodeUnknownObject))
		return
	}
	to := dev.Address.Client()
	var (
		values []client.Value
		err    error
	)
	if index != nil {
		values, err = s.site.ReadPropertyIndex(s.ctx, to, toClientID(real), uint16(prop), *index)
	} else {
		values, err = s.site.ReadProperty(s.ctx, to, toClientID(real), uint16(prop))
	}
	if err != nil {
		s.fault(req, from, err)
		return
	}
	values = s.downstream(dev, real, prop, values)
	echo := obj
	if echo.ObjectType == objects.ObjectTypeDevice && echo.InstanceNumber == translate.Wildcard {
		echo.InstanceNumber = dev.Virtual
	}
	tags := []*objects.Object{
		objects.EncObjectIdentifier(true, 0, echo.ObjectType, echo.InstanceNumber),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(prop))),
	}
	if index != nil {
		tags = append(tags, objects.ContextTag(2, objects.EncUnsignedInteger(uint(*index))))
	}
	tags = append(tags, objects.EncOpeningTag(3))
	tags = append(tags, translate.Encode(values)...)
	tags = append(tags, objects.EncClosingTag(3))
	req.ComplexACK(from, tags)
}

// rpmSpec is one object of a ReadPropertyMultiple request.
type rpmSpec struct {
	obj   objects.ObjectIdentifier // as the consumer gave it
	real  objects.ObjectIdentifier
	props []uint32
	// unknown marks a device object the shifter never issued: answered
	// locally with unknown-object for each property.
	unknown bool
}

// parseRPM reads the request: for each object its identifier [0] and,
// between tags 1, properties [0] with perhaps an index [1].
func parseRPM(tags []*objects.Object) ([]rpmSpec, *control.Answer) {
	var specs []rpmSpec
	for len(tags) > 0 {
		if len(tags) < 3 {
			return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
		}
		id, ok := translate.ObjectID(tags[0])
		if !ok || !isContext(tags[0], 0) || tags[1].Kind != objects.TagOpening || tags[1].TagNumber != 1 {
			return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType}
		}
		spec := rpmSpec{obj: id}
		tags = tags[2:]
		for {
			if len(tags) == 0 {
				return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
			}
			if tags[0].Kind == objects.TagClosing {
				tags = tags[1:]
				break
			}
			if !isContext(tags[0], 0) || len(tags[0].Data) == 0 || len(tags[0].Data) > 4 {
				return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType}
			}
			prop := uintOf(tags[0])
			if prop > 0xFFFF {
				return nil, &control.RejectOther
			}
			spec.props = append(spec.props, prop)
			tags = tags[1:]
			if len(tags) > 0 && isContext(tags[0], 1) {
				// An array index on a property: not split, not forwarded
				// (decision 2).
				return nil, &control.RejectOther
			}
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
	}
	return specs, nil
}

// readPropertyMultiple forwards a ReadPropertyMultiple and answers with the
// translated results.
func (s *Shifter) readPropertyMultiple(req *server.Request, from server.Source, dev table.Device) {
	specs, ans := parseRPM(req.Tags)
	if ans != nil {
		s.refuse(req, from, *ans)
		return
	}
	var forward []client.ReadSpec
	for i := range specs {
		real, ok := s.upstreamObject(specs[i].obj)
		specs[i].real, specs[i].unknown = real, !ok
		if ok {
			rs := client.ReadSpec{Object: toClientID(real)}
			for _, p := range specs[i].props {
				rs.Props = append(rs.Props, uint16(p))
			}
			forward = append(forward, rs)
		}
	}
	var results []client.ObjectResult
	if len(forward) > 0 {
		var err error
		results, err = s.site.ReadPropertyMultiple(s.ctx, dev.Address.Client(), forward)
		if err != nil {
			s.fault(req, from, err)
			return
		}
	}
	var tags []*objects.Object
	for _, r := range results {
		real := toObjectID(r.Object)
		echo := s.downstreamObject(real)
		tags = append(tags, objects.EncObjectIdentifier(true, 0, echo.ObjectType, echo.InstanceNumber), objects.EncOpeningTag(1))
		for _, p := range r.Props {
			tags = append(tags, objects.ContextTag(2, objects.EncUnsignedInteger(uint(p.ID))))
			if p.Index != nil {
				tags = append(tags, objects.ContextTag(3, objects.EncUnsignedInteger(uint(*p.Index))))
			}
			if p.Err != nil {
				class, code := uint32(objects.ErrorClassServices), uint32(control.ErrorCodeOther)
				var be *client.BACnetError
				if errors.As(p.Err, &be) {
					class, code = be.Class, be.Code
				}
				tags = append(tags, objects.EncOpeningTag(5), objects.EncEnumerated(class), objects.EncEnumerated(code), objects.EncClosingTag(5))
				continue
			}
			tags = append(tags, objects.EncOpeningTag(4))
			tags = append(tags, translate.Encode(s.downstream(dev, real, p.ID, p.Values))...)
			tags = append(tags, objects.EncClosingTag(4))
		}
		tags = append(tags, objects.EncClosingTag(1))
	}
	for _, spec := range specs {
		if !spec.unknown {
			continue
		}
		s.log.Info("read of a device the shifter never issued", "from", req.Peer, "object", spec.obj.InstanceNumber)
		tags = append(tags, objects.EncObjectIdentifier(true, 0, spec.obj.ObjectType, spec.obj.InstanceNumber), objects.EncOpeningTag(1))
		for _, p := range spec.props {
			tags = append(tags, objects.ContextTag(2, objects.EncUnsignedInteger(uint(p))),
				objects.EncOpeningTag(5), objects.EncEnumerated(uint32(objects.ErrorClassObject)), objects.EncEnumerated(uint32(control.ErrorCodeUnknownObject)), objects.EncClosingTag(5))
		}
		tags = append(tags, objects.EncClosingTag(1))
	}
	req.ComplexACK(from, tags)
}

// readRange forwards a ReadRange and answers with the translated items.
func (s *Shifter) readRange(req *server.Request, from server.Source, dev table.Device) {
	obj, prop, index, ans := readHeader(req.Tags)
	if ans != nil {
		s.refuse(req, from, *ans)
		return
	}
	rest := req.Tags[2:]
	if index != nil {
		rest = rest[1:]
	}
	rr := client.ReadRangeRequest{Object: toClientID(obj), Property: uint16(prop), Index: index}
	switch {
	case len(rest) == 0:
	case len(rest) == 4 && rest[0].Kind == objects.TagOpening && (rest[0].TagNumber == 3 || rest[0].TagNumber == 6) &&
		rest[3].Kind == objects.TagClosing && rest[3].TagNumber == rest[0].TagNumber:
		start, count := translate.DecodePrimitive(rest[1]), translate.DecodePrimitive(rest[2])
		if start.Kind != client.KindUnsigned || count.Kind != client.KindSigned {
			s.refuse(req, from, control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType})
			return
		}
		rr.Range = client.Range{Kind: client.RangePosition, Start: uint32(start.Uint), Count: int32(count.Int)}
		if rest[0].TagNumber == 6 {
			rr.Range.Kind = client.RangeSequence
		}
	case rest[0].Kind == objects.TagOpening && rest[0].TagNumber == 7:
		// A range by time: the client does not send one.
		s.refuse(req, from, control.RejectOther)
		return
	default:
		s.refuse(req, from, control.Answer{Reject: true, Reason: objects.RejectReasonInvalidTag})
		return
	}
	real, ok := s.upstreamObject(obj)
	if !ok {
		req.Error(from, uint32(objects.ErrorClassObject), uint32(control.ErrorCodeUnknownObject))
		return
	}
	rr.Object = toClientID(real)
	res, err := s.site.ReadRange(s.ctx, dev.Address.Client(), rr)
	if err != nil {
		s.fault(req, from, err)
		return
	}
	echo := s.downstreamObject(toObjectID(res.Object))
	tags := []*objects.Object{
		objects.EncObjectIdentifier(true, 0, echo.ObjectType, echo.InstanceNumber),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(res.Property))),
	}
	if res.Index != nil {
		tags = append(tags, objects.ContextTag(2, objects.EncUnsignedInteger(uint(*res.Index))))
	}
	tags = append(tags,
		objects.ContextTag(3, objects.EncBitString([]bool{res.FirstItem, res.LastItem, res.MoreItems})),
		objects.ContextTag(4, objects.EncUnsignedInteger(uint(res.ItemCount))),
		objects.EncOpeningTag(5))
	tags = append(tags, translate.Encode(s.downstream(dev, toObjectID(res.Object), res.Property, res.Items))...)
	tags = append(tags, objects.EncClosingTag(5))
	if res.FirstSequence != nil {
		tags = append(tags, objects.ContextTag(6, objects.EncUnsignedInteger(uint(*res.FirstSequence))))
	}
	req.ComplexACK(from, tags)
}

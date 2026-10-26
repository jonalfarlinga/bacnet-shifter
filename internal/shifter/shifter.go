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
	"strings"
	"sync"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/audit"
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

	DefaultMaxSubscriptionsPerSource = 256
	DefaultMaxSubscriptionsPerDevice = 16
	DefaultMaxSubscriptions          = 2048
	DefaultMaxNewDevicesPerMinute    = 60
)

// requestMargin is added to the site's timeout and retries for the deadline
// of each request a consumer causes.
const requestMargin = 2 * time.Second

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
	// MaxSubscriptionsPerDevice bounds the shifter's own subscriptions to
	// one site device, MaxSubscriptions those to the whole site; beyond
	// either a consumer's SubscribeCOV is refused. 0 is the default.
	MaxSubscriptionsPerDevice int
	MaxSubscriptions          int
	// MaxNewDevicesPerMinute bounds the devices admitted to the table from
	// I-Ams; beyond it an I-Am for an unknown instance is dropped until the
	// window passes. 0 is the default, below 0 no bound.
	MaxNewDevicesPerMinute int

	// Consumer is the configuration of the consumer socket: Local,
	// BindAny, Broadcast, Exclude, Timeout, Retries, OnPacket and the
	// bounds (MaxInFlight, MaxRPSPerSource, MaxSources, SegmentTimeout)
	// are the caller's. The shifter sets Logger, and keeps its own
	// per-source state within MaxSources.
	Consumer server.Config
	// Recent is how long a consumer counts as recent, to be told of a new
	// device by unicast.
	Recent time.Duration
	// COVMaxLifetime is the ceiling on a consumer's subscription.
	COVMaxLifetime time.Duration
	// MaxSubscriptionsPerSource bounds the subscriptions one consumer may
	// hold; beyond it its SubscribeCOV is refused. 0 is the default.
	MaxSubscriptionsPerSource int

	// Control is the global level, the ceiling, and the level the site
	// client is opened for. Peers gives consumers a level each, by source
	// prefix, the first match winning; a consumer matching none is served
	// at Control. No entry may be above Control.
	Control  control.Level
	Peers    []Peer
	Reserved control.Reserved
	// WriteAllow is the write allow list; nil covers nothing, so that
	// full-service writes nothing until the operator lists what may be.
	WriteAllow control.WriteAllow
	// Audit is the audit log; nil records nothing.
	Audit *audit.Log
	// PassThrough is the properties whose character strings cross as they
	// are; every other string is replaced. Hidden is the object types that
	// do not exist on the consumer side; nil is control.DefaultHidden.
	// Strict replaces the version strings too and sends vendor identifier
	// 0.
	PassThrough map[uint32]bool
	Hidden      map[uint16]bool
	Strict      bool
	// Table is the open table, which carries V.
	Table  *table.Table
	Logger *slog.Logger
}

// Peer is one entry of the per-consumer levels: the consumers whose source
// is within Prefix are served at Control.
type Peer struct {
	Prefix  netip.Prefix
	Control control.Level
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
	// requestTimeout is the deadline of each request to the site a
	// consumer causes: the site's timeout and retries, plus a margin.
	requestTimeout time.Duration
	// admission rations the devices admitted to the table from I-Ams;
	// nil when unbounded.
	admission *admission
	// recent is when each consumer was last heard from with a confirmed
	// request; whoIsAnswered when each source was last sent a burst of
	// I-Ams. Both hold at most Consumer.MaxSources entries.
	recent        *server.Bounded[recentPeer]
	whoIsAnswered *server.Bounded[time.Time]

	mu sync.Mutex
	// heard is the devices announced this run.
	heard     map[uint32]bool
	lastWhoIs time.Time
	// objectLists is each device's object list with the hidden objects
	// left out, as read from the site within objectListTTL: an indexed
	// read of the list is answered from it, so that the count and the
	// elements agree.
	objectLists map[uint32]objectList
	// surveying is the survey running now, which hears the I-Ams too.
	surveying *survey.Survey
	// dropped counts the I-Ams not admitted and the moves refused.
	droppedIAms, refusedMoves int
}

type recentPeer struct {
	peer server.Peer
	at   time.Time
}

// objectListTTL is how long a device's object list is answered from the
// last read of it.
const objectListTTL = 30 * time.Second

type objectList struct {
	ids []client.ObjectID
	at  time.Time
}

// admission is the token bucket new devices are admitted through: a
// bucket of perMinute tokens, refilled at that rate.
type admission struct {
	mu        sync.Mutex
	perMinute float64
	tokens    float64
	last      time.Time
}

func newAdmission(perMinute int) *admission {
	return &admission{perMinute: float64(perMinute), tokens: float64(perMinute), last: time.Now()}
}

// take takes a token, and reports false when there is none.
func (a *admission) take() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.tokens = min(a.perMinute, a.tokens+now.Sub(a.last).Minutes()*a.perMinute)
	a.last = now
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
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
	if cfg.Hidden == nil {
		cfg.Hidden = control.DefaultHidden()
	}
	for _, p := range cfg.Peers {
		if !p.Prefix.IsValid() {
			return nil, fmt.Errorf("consumer.peers: %v is not a prefix", p.Prefix)
		}
		if p.Control > cfg.Control {
			return nil, fmt.Errorf("consumer.peers: %v at %s is above control %s, the ceiling", p.Prefix, p.Control, cfg.Control)
		}
	}
	if cfg.MaxSubscriptionsPerSource <= 0 {
		cfg.MaxSubscriptionsPerSource = DefaultMaxSubscriptionsPerSource
	}
	if cfg.MaxSubscriptionsPerDevice <= 0 {
		cfg.MaxSubscriptionsPerDevice = DefaultMaxSubscriptionsPerDevice
	}
	if cfg.MaxSubscriptions <= 0 {
		cfg.MaxSubscriptions = DefaultMaxSubscriptions
	}
	if cfg.MaxNewDevicesPerMinute == 0 {
		cfg.MaxNewDevicesPerMinute = DefaultMaxNewDevicesPerMinute
	}
	if cfg.Consumer.MaxSources <= 0 {
		cfg.Consumer.MaxSources = server.DefaultMaxSources
	}
	// The site client's own defaults, for the deadline of each request.
	siteTimeout, siteRetries := cfg.Site.Timeout, cfg.Site.Retries
	if siteTimeout <= 0 {
		siteTimeout = 3 * time.Second
	}
	if siteRetries < 0 {
		siteRetries = 0
	}
	s := &Shifter{
		cfg: cfg, log: cfg.Logger, table: cfg.Table,
		slots:          make(chan struct{}, 4),
		heard:          map[uint32]bool{},
		objectLists:    map[uint32]objectList{},
		recent:         server.NewBounded[recentPeer](cfg.Consumer.MaxSources),
		whoIsAnswered:  server.NewBounded[time.Time](cfg.Consumer.MaxSources),
		cov:            newCOVState(cfg.MaxSubscriptionsPerSource, cfg.MaxSubscriptionsPerDevice, cfg.MaxSubscriptions, cfg.Consumer.MaxSources),
		requestTimeout: siteTimeout*time.Duration(siteRetries+1) + requestMargin,
	}
	if cfg.MaxNewDevicesPerMinute > 0 {
		s.admission = newAdmission(cfg.MaxNewDevicesPerMinute)
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
	s.log.Info("shifter started", "site", site.Local(), "consumer", srv.Local(), "control", cfg.Control, "network", s.table.V(), "peers", len(cfg.Peers), "writes_allowed", len(cfg.WriteAllow))
	if len(cfg.Consumer.Allow) == 0 {
		s.log.Warn("consumer.allow is empty: every source that reaches the consumer socket is served; set it to the tunnel's prefix before the shifter is relied on as a boundary")
	}
	s.cfg.Audit.Record(audit.Entry{Event: audit.EventStart, Control: cfg.Control.String(),
		Detail: fmt.Sprintf("consumer.allow %v, %d peers %s, %d writes.allow entries", cfg.Consumer.Allow, len(cfg.Peers), describePeers(cfg.Peers), len(cfg.WriteAllow))})
	s.spawn("audit of dropped sources", nil, s.auditDropped)

	// A router announces itself and its networks when it comes up.
	s.announceRouter(s.table.VirtualNetworks())
	s.mu.Lock()
	s.lastWhoIs = time.Now()
	s.mu.Unlock()
	if err := site.WhoIs(); err != nil {
		s.log.Warn("the first Who-Is was not sent", "error", err)
	}
	for _, addr := range cfg.Add {
		s.spawn("probe", []any{"address", addr}, func() { s.probe(addr) })
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
	if serr := s.table.Close(); err == nil {
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

// Dropped is what the shifter and its server refused: the server's counts,
// the I-Ams not admitted to the table, and the moves refused because the
// old address still answered.
func (s *Shifter) Dropped() (srv server.Dropped, iAms, moves int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv.Dropped(), s.droppedIAms, s.refusedMoves
}

// requestCtx is the context of one request to the site on a consumer's
// behalf: it ends with the shifter, or when the site's timeout and retries
// plus a margin have passed, so that a request waiting in the client's
// token bucket gives up rather than queuing forever.
func (s *Shifter) requestCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.ctx, s.requestTimeout)
}

// spawn runs f on a goroutine of the shifter's, under a recover: a panic
// is logged with what the goroutine was doing and lost with it, and the
// shifter goes on.
func (s *Shifter) spawn(what string, attrs []any, f func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("a goroutine panicked; its work is dropped", append([]any{"doing", what, "panic", r}, attrs...)...)
			}
		}()
		f()
	}()
}

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
	s.spawn("discovery", []any{"instance", dev.Instance, "address", dev.Addr}, func() {
		select {
		case s.slots <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		defer func() { <-s.slots }()
		s.discovered(dev)
	})
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

// admit says whether an I-Am may change the table: a device the table
// knows always may; an unknown one takes a token of the admission rate,
// and is dropped without one. A device heard this run at another address
// is confirmed first: the old address is probed, and the new one is taken
// only when the old is silent (S2 of the threat model).
func (s *Shifter) admit(dev client.Device) bool {
	rec, known := s.table.Device(dev.Instance)
	if !known || rec.Referenced {
		if !s.admission.take() {
			s.mu.Lock()
			s.droppedIAms++
			s.mu.Unlock()
			s.log.Warn("an I-Am for a new device was dropped: too many new devices this minute", "instance", dev.Instance, "address", dev.Addr)
			return false
		}
		return true
	}
	old := rec.Address.Client()
	if rec.Address == table.AddressOf(dev.Addr) || rec.Address.IsZero() || s.table.Heard(dev.Instance) {
		return true
	}
	// A known instance from a new address, not heard this run: ask the old
	// address whether it is still there before believing the new one.
	ctx, cancel := s.requestCtx()
	defer cancel()
	_, err := s.site.ReadProperty(ctx, old, client.ObjectID{Type: objects.ObjectTypeDevice, Instance: dev.Instance}, objects.PropertyIdObjectIdentifier)
	silent := errors.Is(err, client.ErrTimeout) || errors.Is(err, client.ErrNetworkUnreachable)
	if silent {
		s.log.Warn("device address changed: the old address is silent, the new one is taken", "instance", dev.Instance, "old", old, "new", dev.Addr)
		return true
	}
	s.mu.Lock()
	s.refusedMoves++
	s.mu.Unlock()
	s.log.Warn("an I-Am claims a known instance from a new address, but the old address still answers; the new one is not taken", "instance", dev.Instance, "old", old, "new", dev.Addr, "answer", err)
	return false
}

// discovered gives a device heard from the site its pseudonyms, reads its
// name, and announces it on the consumer side the first time this run.
func (s *Shifter) discovered(dev client.Device) {
	if !s.admit(dev) {
		return
	}
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
		ctx, cancel := s.requestCtx()
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
	vendor := d.VendorID
	if s.cfg.Strict {
		vendor = 0
	}
	return services.IAmObjects(d.Virtual, maxAPDU, seg, vendor)
}

// hidden reports whether an object is of a type that does not exist on
// the consumer side.
func (s *Shifter) hidden(id objects.ObjectIdentifier) bool { return s.cfg.Hidden[id.ObjectType] }

// refuseHidden answers a request naming a hidden object as one naming no
// object at all, and logs it: the consumer must not learn the type exists.
func (s *Shifter) refuseHidden(req *server.Request, from server.Source, id objects.ObjectIdentifier) {
	s.log.Info("refused a request for a hidden object", "from", req.Peer, "service", control.ServiceName(req.Service), "object", objectName(id))
	s.unknownObject(req, from, table.Device{}, "hidden object")
}

// unknownObject answers a request as one naming no object, and records
// why: a hidden object, or a device instance the shifter never issued.
func (s *Shifter) unknownObject(req *server.Request, from server.Source, dev table.Device, why string) {
	e := s.auditEntry(req, dev, audit.EventRefused)
	e.Outcome, e.Detail = "Error object unknown-object", why
	s.cfg.Audit.Record(e)
	req.Error(from, uint32(objects.ErrorClassObject), uint32(control.ErrorCodeUnknownObject))
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

// noteConsumer marks a consumer recent. Only a confirmed request earns it:
// a Who-Is from a spoofed source would otherwise make the shifter unicast
// every announcement there.
func (s *Shifter) noteConsumer(p server.Peer) {
	s.recent.Put(p.Key(), recentPeer{peer: p, at: time.Now()})
}

func (s *Shifter) recentPeers() []server.Peer {
	cutoff := time.Now().Add(-s.cfg.Recent)
	var peers []server.Peer
	s.recent.Each(func(_ string, r recentPeer) bool {
		if r.at.Before(cutoff) {
			return false
		}
		peers = append(peers, r.peer)
		return true
	})
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
// select, and forwards a Who-Is to the site. A source is sent one burst of
// I-Ams per WhoIsInterval at most: a Who-Is costs the sender one datagram
// and would otherwise cost whoever it names as its source one per device.
func (s *Shifter) whoIs(env server.Envelope, apdu *plumbing.APDU) {
	defer s.forwardWhoIs()
	// The source is marked before the burst, under the lock, so that a
	// burst of Who-Is handled at once cannot each find it unmarked.
	key, now := env.Peer.Key(), time.Now()
	s.mu.Lock()
	last, answered := s.whoIsAnswered.Get(key)
	due := !answered || now.Sub(last) >= s.cfg.WhoIsInterval
	if due {
		s.whoIsAnswered.Put(key, now)
	}
	s.mu.Unlock()
	if !due {
		s.log.Debug("a Who-Is within the interval of the last burst to its source goes unanswered", "from", env.Peer)
		return
	}
	low, high := uint32(0), uint32(translate.Wildcard)
	if tags := tagsOf(apdu); len(tags) == 2 && isContext(tags[0], 0) && isContext(tags[1], 1) {
		low, high = uintOf(tags[0]), uintOf(tags[1])
	}
	sent := 0
	for _, d := range s.selectDevices(env) {
		if d.Virtual < low || d.Virtual > high {
			continue
		}
		s.srv.Unconfirmed(env.Peer, s.source(d), services.ServiceUnconfirmedIAm, s.iAm(d))
		sent++
	}
	if sent == 0 {
		// An empty answer cost nothing: the next Who-Is may be answered.
		s.whoIsAnswered.Delete(key)
	}
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
	case s.cfg.Hidden[dec.ObjectID.ObjectType]:
		s.log.Info("a Who-Has for a hidden object finds nothing", "from", env.Peer, "object", objectName(*dec.ObjectID))
		return
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
		if !ok || s.cfg.Hidden[n.Type] || (dec.HasLimits && (d.Virtual < dec.LowLimit || d.Virtual > dec.HighLimit)) {
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

// peerOf is the Peers entry a consumer's source is within, if any, and
// the level it is served at: the entry's, or the global one. A routed
// consumer is judged by its router's address, which is what the tunnel
// identifies.
func (s *Shifter) peerOf(p server.Peer) (prefix string, level control.Level) {
	for _, e := range s.cfg.Peers {
		if e.Prefix.Contains(p.IP.Addr()) {
			return e.Prefix.String(), e.Control
		}
	}
	return "", s.cfg.Control
}

// levelOf is the level a consumer is served at.
func (s *Shifter) levelOf(p server.Peer) control.Level {
	_, level := s.peerOf(p)
	return level
}

func describePeers(peers []Peer) string {
	if len(peers) == 0 {
		return "[]"
	}
	parts := make([]string, len(peers))
	for i, p := range peers {
		parts[i] = fmt.Sprintf("%v=%s", p.Prefix, p.Control)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// auditEntry starts an audit line for a request: the consumer, its peer
// entry and level, the service, the device, and the object and property
// when the request's tags start with them.
func (s *Shifter) auditEntry(req *server.Request, dev table.Device, event string) audit.Entry {
	prefix, level := s.peerOf(req.Peer)
	e := audit.Entry{Event: event, Peer: req.Peer.String(), Prefix: prefix, Control: level.String(),
		Service: control.ServiceName(req.Service), Device: dev.Virtual, Real: dev.Instance}
	// A read, a write and a range start with the object [0], the property
	// [1] and perhaps an index [2]; a subscription with the process [0]
	// and the object [1].
	objTag, propTag := 0, 1
	if req.Service == services.ServiceConfirmedSubscribeCOV {
		objTag, propTag = 1, -1
	}
	if len(req.Tags) > objTag {
		if id, ok := translate.ObjectID(req.Tags[objTag]); ok {
			e.Object = objectName(id)
		}
	}
	if propTag >= 0 && len(req.Tags) > propTag && isContext(req.Tags[propTag], 1) {
		e.Property = control.PropertyName(uintOf(req.Tags[propTag]))
		if len(req.Tags) > propTag+1 && isContext(req.Tags[propTag+1], 2) {
			i := uintOf(req.Tags[propTag+1])
			e.Index = &i
		}
	}
	return e
}

// auditDropped records, once a minute, the datagrams consumer.allow
// dropped since the last line, with the sources, until the shifter
// closes.
func (s *Shifter) auditDropped() {
	if s.cfg.Audit == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-ticker.C:
		case <-s.ctx.Done():
			return
		}
		n, sources := s.srv.AllowDropped()
		if n == last {
			continue
		}
		s.cfg.Audit.Record(audit.Entry{Event: audit.EventDropped, Outcome: fmt.Sprintf("%d dropped", n-last), Detail: "sources: " + strings.Join(sources, " ")})
		last = n
	}
}

// Confirmed implements server.Handler: the consumer's level decides, then
// the service.
func (s *Shifter) Confirmed(req *server.Request) {
	s.noteConsumer(req.Peer)
	from, dev, ok := s.target(req.Envelope)
	if !ok {
		req.Drop()
		return
	}
	level := s.levelOf(req.Peer)
	if ans := level.Confirmed(req.Service); !ans.Forward {
		s.refuse(req, from, ans)
		return
	}
	if level.ReservedService(req.Service, s.cfg.Reserved) {
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

// refuse answers a request with its documented refusal, logs it, and
// records it in the audit log with why as the detail.
func (s *Shifter) refuse(req *server.Request, from server.Source, ans control.Answer) {
	s.refuseFor(req, from, ans, table.Device{}, "")
}

// answerName names a refusal for the audit record.
func answerName(ans control.Answer) string {
	if ans.Reject {
		return "Reject " + objects.RejectReasonMap[ans.Reason]
	}
	return "Error " + client.ErrorClassName(uint32(ans.Class)) + " " + client.ErrorCodeName(uint32(ans.Code))
}

func (s *Shifter) refuseFor(req *server.Request, from server.Source, ans control.Answer, dev table.Device, why string) {
	e := s.auditEntry(req, dev, audit.EventRefused)
	e.Outcome, e.Detail = answerName(ans), why
	s.cfg.Audit.Record(e)
	attrs := []any{"from", req.Peer, "service", control.ServiceName(req.Service), "control", s.levelOf(req.Peer)}
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
	case errors.Is(err, client.ErrServiceNotAllowed):
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

// objectListLike are the properties that list objects, and from which the
// hidden objects are left out: the object-list and structured-object-list
// of a device, the subordinate-list of a Structured View, the
// list-of-group-members of a Group.
var objectListLike = map[uint32]bool{
	uint32(objects.PropertyIdObjectList):           true,
	uint32(objects.PropertyIdStructuredObjectList): true,
	uint32(objects.PropertyIdSubordinateList):      true,
	uint32(objects.PropertyIdListOfGroupMembers):   true,
}

// downstream translates the values of one property of one real object on
// their way to the consumer: device identifiers and addresses by rule, the
// hidden objects left out of a list of objects, the vendor identifier
// blanked under the strict profile, and every character string through
// the table unless the property passes.
func (s *Shifter) downstream(dev table.Device, obj objects.ObjectIdentifier, prop uint32, values []client.Value) []client.Value {
	values = s.rules.Values(values)
	if prop == uint32(objects.PropertyIdDeviceAddressBinding) {
		values = s.rules.AddressBindings(values)
	}
	if objectListLike[prop] {
		values = translate.DropObjects(values, s.cfg.Hidden)
	}
	if s.cfg.Strict && prop == uint32(objects.PropertyIdVendorIdentifier) {
		values = translate.ReplaceUnsigned(values, 0)
	}
	if control.Passes(prop, s.cfg.PassThrough, s.cfg.Strict) {
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
	if s.hidden(obj) {
		s.refuseHidden(req, from, obj)
		return
	}
	real, ok := s.upstreamObject(obj)
	if !ok {
		s.log.Info("read of a device the shifter never issued", "from", req.Peer, "object", obj.InstanceNumber)
		s.unknownObject(req, from, dev, "unissued device")
		return
	}
	to := dev.Address.Client()
	var (
		values []client.Value
		err    error
	)
	ctx, cancel := s.requestCtx()
	defer cancel()
	switch {
	case translate.IsDevice(real) && prop == uint32(objects.PropertyIdObjectList):
		// The list with the hidden objects left out, whole or by index,
		// so that the count and the elements agree.
		values, err = s.objectListValues(ctx, dev, index)
	case index != nil:
		values, err = s.site.ReadPropertyIndex(ctx, to, toClientID(real), uint16(prop), *index)
	default:
		values, err = s.site.ReadProperty(ctx, to, toClientID(real), uint16(prop))
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

// objectListValues answers a read of a device's object-list, whole or by
// index, from the list as the site gives it with the hidden objects left
// out. The list is read through the client, which reads it element by
// element where the device cannot segment, and kept for objectListTTL so
// that a consumer reading it element by element costs the site one read of
// it, not one per element. Element 0 is the count.
func (s *Shifter) objectListValues(ctx context.Context, dev table.Device, index *uint32) ([]client.Value, error) {
	s.mu.Lock()
	cached, ok := s.objectLists[dev.Instance]
	s.mu.Unlock()
	if !ok || time.Since(cached.at) > objectListTTL {
		ids, err := s.site.ReadObjectList(ctx, client.Device{Instance: dev.Instance, Addr: dev.Address.Client(), MaxAPDU: dev.MaxAPDU, Segmentation: dev.Segmentation}, nil)
		if err != nil {
			return nil, err
		}
		kept := ids[:0]
		for _, id := range ids {
			if !s.cfg.Hidden[id.Type] {
				kept = append(kept, id)
			}
		}
		cached = objectList{ids: kept, at: time.Now()}
		s.mu.Lock()
		s.objectLists[dev.Instance] = cached
		s.mu.Unlock()
	}
	if index == nil {
		values := make([]client.Value, len(cached.ids))
		for i, id := range cached.ids {
			values[i] = client.Value{Kind: client.KindObjectID, Object: id}
		}
		return values, nil
	}
	switch {
	case *index == 0:
		return []client.Value{{Kind: client.KindUnsigned, Uint: uint64(len(cached.ids))}}, nil
	case int(*index) <= len(cached.ids):
		return []client.Value{{Kind: client.KindObjectID, Object: cached.ids[*index-1]}}, nil
	}
	return nil, &client.BACnetError{Class: uint32(objects.ErrorClassProperty), Code: uint32(control.ErrorCodeInvalidArrayIndex)}
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
				if tags[0].TagNumber != 1 {
					return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidTag}
				}
				if len(spec.props) == 0 {
					return nil, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
				}
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
		if s.hidden(specs[i].obj) {
			s.log.Info("refused a request for a hidden object", "from", req.Peer, "service", control.ServiceName(req.Service), "object", objectName(specs[i].obj))
			ok = false
		}
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
		ctx, cancel := s.requestCtx()
		defer cancel()
		var err error
		results, err = s.site.ReadPropertyMultiple(ctx, dev.Address.Client(), forward)
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
		if !s.hidden(spec.obj) {
			s.log.Info("read of a device the shifter never issued", "from", req.Peer, "object", spec.obj.InstanceNumber)
		}
		tags = append(tags, objects.EncObjectIdentifier(true, 0, spec.obj.ObjectType, spec.obj.InstanceNumber), objects.EncOpeningTag(1))
		for _, p := range spec.props {
			tags = append(tags, objects.ContextTag(2, objects.EncUnsignedInteger(uint(p))),
				objects.EncOpeningTag(5), objects.EncEnumerated(uint32(objects.ErrorClassObject)), objects.EncEnumerated(uint32(control.ErrorCodeUnknownObject)), objects.EncClosingTag(5))
		}
		tags = append(tags, objects.EncClosingTag(1))
	}
	req.ComplexACK(from, tags)
}

// parseReadRange reads a ReadRange: the object [0], property [1] and
// optional index [2] of a read, then nothing, a range by position between
// tags 3 or by sequence between tags 6, each a start and a signed count, or
// a range by time between tags 7, which the client does not send. ans says
// how to refuse a request that has them wrong. The object is as the
// consumer gave it.
func parseReadRange(tags []*objects.Object) (rr client.ReadRangeRequest, ans *control.Answer) {
	obj, prop, index, ans := readHeader(tags)
	if ans != nil {
		return rr, ans
	}
	rest := tags[2:]
	if index != nil {
		rest = rest[1:]
	}
	rr = client.ReadRangeRequest{Object: toClientID(obj), Property: uint16(prop), Index: index}
	switch {
	case len(rest) == 0:
	case len(rest) == 4 && rest[0].Kind == objects.TagOpening && (rest[0].TagNumber == 3 || rest[0].TagNumber == 6) &&
		rest[3].Kind == objects.TagClosing && rest[3].TagNumber == rest[0].TagNumber:
		start, count := translate.DecodePrimitive(rest[1]), translate.DecodePrimitive(rest[2])
		if start.Kind != client.KindUnsigned || count.Kind != client.KindSigned {
			return rr, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType}
		}
		rr.Range = client.Range{Kind: client.RangePosition, Start: uint32(start.Uint), Count: int32(count.Int)}
		if rest[0].TagNumber == 6 {
			rr.Range.Kind = client.RangeSequence
		}
	case rest[0].Kind == objects.TagOpening && rest[0].TagNumber == 7:
		return rr, &control.RejectOther
	default:
		return rr, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidTag}
	}
	return rr, nil
}

// readRange forwards a ReadRange and answers with the translated items.
func (s *Shifter) readRange(req *server.Request, from server.Source, dev table.Device) {
	rr, ans := parseReadRange(req.Tags)
	if ans != nil {
		s.refuse(req, from, *ans)
		return
	}
	if s.hidden(toObjectID(rr.Object)) {
		s.refuseHidden(req, from, toObjectID(rr.Object))
		return
	}
	real, ok := s.upstreamObject(toObjectID(rr.Object))
	if !ok {
		s.unknownObject(req, from, dev, "unissued device")
		return
	}
	rr.Object = toClientID(real)
	ctx, cancel := s.requestCtx()
	defer cancel()
	res, err := s.site.ReadRange(ctx, dev.Address.Client(), rr)
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

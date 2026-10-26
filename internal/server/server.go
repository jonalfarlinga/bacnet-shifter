// Package server is the shifter's consumer-facing socket: it
// parses what consumers send, hands each request to a handler, and offers
// the handler what a BACnet server needs to answer: a reply with the
// consumer's invoke ID, segmented to the consumer's max APDU; an Error,
// Reject or Abort; unconfirmed messages and network-layer messages from a
// virtual source; and a confirmed request to a consumer with its SimpleACK
// awaited, for confirmed notifications.
//
// The server knows nothing of pseudonyms or levels. It parses BVLC, NPDU
// and APDU generically with the plumbing codecs, so that it sees every
// service, those the library has no type for included. It speaks as a
// router: a reply or a notification goes out with the virtual network and
// MAC of the device it is from as the NPDU's source, and a consumer that is
// itself behind a router is answered through that router, with the
// consumer's network and MAC as the destination.
//
// The server serves only the sources within Config.Allow, when it is set,
// and bounds what a source can make it do: a token bucket per source
// rations the requests it takes, a semaphore caps the confirmed requests
// handled at once, a segmented reply is aborted when its acknowledgements
// stop, and a handler that panics loses one message. Config has the bounds
// and their defaults; Dropped counts what they refused.
//
// The station, dispatch and segmentation code is copied from client/sim and
// reshaped for the shifter. It stays here: the library handles the plumbing,
// and its only server code is the sim fixture and the examples. A fix to the
// segmentation and send core the two copies share is checked against the
// other.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
)

// DefaultWindow is the segment window the server proposes.
const DefaultWindow = 4

// MaxAPDU is the most the server puts in one APDU.
const MaxAPDU = 1476

// maxAPDUSizes are the sizes a confirmed request's max-APDU code stands for.
var maxAPDUSizes = []int{50, 128, 206, 480, 1024, 1476}

// BVLC functions the server answers besides the two that carry an NPDU.
const (
	bvlcFuncRegisterForeignDevice = 0x05
	bvlcResultRegisterNAK         = 0x0030
)

// Defaults for the bounds in Config.
const (
	DefaultMaxInFlight     = 64
	DefaultMaxRPSPerSource = 20
	DefaultMaxSources      = 1024
	DefaultSegmentTimeout  = 4 * time.Second
)

// Config says where the server listens and what it proposes.
type Config struct {
	// Local is the address the socket is bound to, or with BindAny, the
	// port of the wildcard address; it is the address the server's own
	// broadcasts come back from, and are dropped.
	Local   netip.AddrPort
	BindAny bool
	// Broadcast is where the server's broadcasts go.
	Broadcast netip.AddrPort
	// Exclude drops datagrams from these subnets, as the client does.
	Exclude []netip.Prefix
	// Allow, when set, is the source prefixes served: a datagram from any
	// other source is dropped before it is parsed, counted, and logged at
	// Debug once per source per minute. Empty serves every source.
	Allow []netip.Prefix

	// Timeout is how long a confirmed request to a consumer waits for its
	// acknowledgement, and Retries how often it is sent again.
	Timeout time.Duration
	Retries int
	// Window is the segment window proposed for a segmented reply.
	Window uint8

	// MaxInFlight is the most confirmed requests handled at once; beyond
	// it a request is dropped. 0 is DefaultMaxInFlight, below 0 no bound.
	MaxInFlight int
	// MaxRPSPerSource is the confirmed requests, unconfirmed requests and
	// network messages taken from one source in a second, with a burst of
	// the same; beyond it a datagram is dropped before it is parsed
	// further. 0 is DefaultMaxRPSPerSource, below 0 no bound.
	MaxRPSPerSource float64
	// MaxSources is how many sources the rate limit tracks; the one heard
	// longest ago is forgotten for a new one. 0 is DefaultMaxSources.
	MaxSources int
	// SegmentTimeout is how long a segmented reply waits for the next
	// Segment-ACK before it is aborted. 0 is DefaultSegmentTimeout.
	SegmentTimeout time.Duration

	// OnPacket is told of every datagram sent and received, before anything
	// is done with it, for the leak test and the frames log.
	OnPacket func(client.PacketEvent)
	Logger   *slog.Logger
}

// Peer is who a message is exchanged with: the datagram's address and, for
// a consumer behind a router, its network and MAC, with IP the router's.
type Peer struct {
	IP  netip.AddrPort
	Net uint16
	MAC []byte
}

// Routed reports whether the peer is behind a router.
func (p Peer) Routed() bool { return p.Net != 0 }

func (p Peer) String() string {
	if !p.Routed() {
		return p.IP.String()
	}
	return fmt.Sprintf("network %d MAC %x via %s", p.Net, p.MAC, p.IP)
}

// Key is what a peer is known by: a routed one by its network and MAC, so
// that its requests match whichever router carries them.
func (p Peer) Key() string {
	if p.Routed() {
		return fmt.Sprintf("%d/%x", p.Net, p.MAC)
	}
	return p.IP.String()
}

// Source is the virtual device a message is from: its network and MAC. The
// zero Source is the router itself, which has no network address of its
// own.
type Source struct {
	Net uint16
	MAC []byte
}

func (s Source) key() string { return fmt.Sprintf("%d/%x", s.Net, s.MAC) }

// Envelope is what the NPDU says about where a message came from and where
// it is for.
type Envelope struct {
	Peer Peer
	// Broadcast says the datagram was an Original-Broadcast-NPDU.
	Broadcast bool
	// HasDest says the NPDU names a destination network: DNET, and DADR
	// unless the message is a broadcast on that network.
	HasDest bool
	DNET    uint16
	DADR    []byte
}

// Global reports whether the message was addressed to every network.
func (e Envelope) Global() bool { return e.HasDest && e.DNET == 0xFFFF }

// Dest is the virtual device the message was addressed to, as a Source for
// the reply, and false when it names none.
func (e Envelope) Dest() (Source, bool) {
	if !e.HasDest || e.DNET == 0xFFFF || len(e.DADR) == 0 {
		return Source{}, false
	}
	return Source{Net: e.DNET, MAC: e.DADR}, true
}

// Request is one confirmed request from a consumer. The handler answers it
// with exactly one of the reply methods, or Drops it.
type Request struct {
	Envelope
	Service  uint8
	InvokeID uint8
	// MaxAPDU is the most the consumer takes in one APDU, SegmentsAccepted
	// whether it takes a segmented reply, and MaxSegments how many segments
	// at most, 0 for no limit stated.
	MaxAPDU          int
	SegmentsAccepted bool
	MaxSegments      int
	Tags             []*objects.Object

	s    *Server
	key  txKey
	done atomic.Bool
}

// Reply is what a confirmed request to a consumer came back with.
type Reply struct {
	// Type is the PDU type: SimpleAck, ComplexAck, Error, Reject or Abort.
	Type    uint8
	Service uint8
	Reason  uint8
	Tags    []*objects.Object
}

// Handler is what the shifter implements. Confirmed and Unconfirmed run on
// a goroutine of their own for each message; Network runs on the read loop
// and must not block.
type Handler interface {
	Confirmed(req *Request)
	Unconfirmed(env Envelope, apdu *plumbing.APDU)
	Network(env Envelope, m *plumbing.NetworkMessage)
}

// txKey identifies a transaction with a consumer: the consumer, the virtual
// device the request is addressed to, and the invoke ID. The destination is
// part of it because a consumer reuses invoke IDs across the devices it
// talks to.
type txKey struct {
	peer   string
	dest   string
	invoke uint8
}

type segmented struct {
	to       Peer
	from     Source
	service  uint8
	segments [][]byte
	// timer aborts the reply when the next Segment-ACK is late.
	timer *time.Timer
}

// Dropped counts what the server refused to handle.
type Dropped struct {
	// InFlight is the confirmed requests dropped at MaxInFlight, Rate the
	// datagrams dropped by the per-source rate limit, Panics the handler
	// calls that panicked and were recovered, Allow the datagrams from
	// sources outside Allow.
	InFlight, Rate, Panics, Allow uint64
}

// Server owns the consumer socket.
type Server struct {
	cfg  Config
	conn *net.UDPConn
	log  *slog.Logger
	h    Handler
	// inFlight is the semaphore under MaxInFlight; nil when unbounded.
	inFlight chan struct{}
	limiter  *limiter

	droppedInFlight, droppedRate, panics, droppedAllow atomic.Uint64
	// allowLogged is when each source outside Allow was last logged.
	allowLogged *Bounded[time.Time]

	mu sync.Mutex
	// pending is the confirmed requests the handler has not answered yet:
	// a retransmission of one is dropped.
	pending map[txKey]bool
	// sending is the segmented replies still going out.
	sending map[txKey]*segmented
	// invokes is the last invoke ID of a confirmed request to each peer,
	// and unacked the requests waiting for their acknowledgement.
	invokes map[string]uint8
	unacked map[txKey]chan *plumbing.APDU

	closed chan struct{}
	done   chan struct{}
}

// Open binds the socket and starts serving.
func Open(cfg Config, h Handler) (*Server, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.MaxInFlight == 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.MaxRPSPerSource == 0 {
		cfg.MaxRPSPerSource = DefaultMaxRPSPerSource
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultMaxSources
	}
	if cfg.SegmentTimeout <= 0 {
		cfg.SegmentTimeout = DefaultSegmentTimeout
	}
	bind := cfg.Local
	if cfg.BindAny {
		bind = netip.AddrPortFrom(netip.IPv4Unspecified(), cfg.Local.Port())
	}
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(bind))
	if err != nil {
		return nil, err
	}
	if !cfg.Local.IsValid() || cfg.Local.Port() == 0 {
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			cfg.Local = netip.AddrPortFrom(la.AddrPort().Addr().Unmap(), la.AddrPort().Port())
		}
	}
	s := &Server{
		cfg: cfg, conn: conn, log: cfg.Logger, h: h,
		pending: map[txKey]bool{}, sending: map[txKey]*segmented{},
		invokes: map[string]uint8{}, unacked: map[txKey]chan *plumbing.APDU{},
		closed: make(chan struct{}), done: make(chan struct{}),
	}
	if cfg.MaxInFlight > 0 {
		s.inFlight = make(chan struct{}, cfg.MaxInFlight)
	}
	if cfg.MaxRPSPerSource > 0 {
		s.limiter = newLimiter(cfg.MaxRPSPerSource, cfg.MaxSources)
	}
	s.allowLogged = NewBounded[time.Time](cfg.MaxSources)
	go s.readLoop()
	return s, nil
}

// Local is the address the server sends from.
func (s *Server) Local() netip.AddrPort { return s.cfg.Local }

// Dropped is what the server has refused to handle since it opened.
func (s *Server) Dropped() Dropped {
	return Dropped{InFlight: s.droppedInFlight.Load(), Rate: s.droppedRate.Load(), Panics: s.panics.Load(), Allow: s.droppedAllow.Load()}
}

// AllowDropped is how many datagrams Allow dropped since the server
// opened, and the sources dropped most recently.
func (s *Server) AllowDropped() (uint64, []string) {
	var sources []string
	s.allowLogged.Each(func(key string, _ time.Time) bool {
		sources = append(sources, key)
		return true
	})
	return s.droppedAllow.Load(), sources
}

// allowed reports whether a source is served: any when Allow is empty,
// otherwise one within a listed prefix. A source that is not is counted
// and logged at Debug once a minute.
func (s *Server) allowed(src netip.AddrPort) bool {
	if len(s.cfg.Allow) == 0 {
		return true
	}
	for _, p := range s.cfg.Allow {
		if p.Contains(src.Addr()) {
			return true
		}
	}
	s.droppedAllow.Add(1)
	key := src.Addr().String()
	now := time.Now()
	if last, ok := s.allowLogged.Get(key); !ok || now.Sub(last) >= time.Minute {
		s.allowLogged.Put(key, now)
		s.log.Debug("dropped a datagram from a source outside consumer.allow", "from", src)
	}
	return false
}

// Close stops the server.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
	}
	close(s.closed)
	err := s.conn.Close()
	<-s.done
	s.mu.Lock()
	for key, tx := range s.sending {
		tx.timer.Stop()
		delete(s.sending, key)
	}
	s.mu.Unlock()
	return err
}

// guard runs a handler call under a recover: a panic in it is logged with
// the datagram's source and counted, and that one message is lost, as the
// plan has it; the server goes on.
func (s *Server) guard(what string, from Peer, f func()) {
	defer func() {
		if r := recover(); r != nil {
			s.panics.Add(1)
			s.log.Error("a handler panicked; the message is dropped", "handler", what, "from", from, "panic", r)
		}
	}()
	f()
}

// ---- receiving -------------------------------------------------------------

func (s *Server) readLoop() {
	defer close(s.done)
	buf := make([]byte, 2048)
	failures := 0
	for {
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if failures++; failures > 100 {
				time.Sleep(50 * time.Millisecond)
			}
			continue
		}
		failures = 0
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		raw := append([]byte(nil), buf[:n]...)
		if s.cfg.OnPacket != nil {
			s.cfg.OnPacket(client.PacketEvent{Time: time.Now(), Inbound: true, Peer: src, Data: raw})
		}
		if src == s.cfg.Local {
			continue
		}
		if s.excluded(src.Addr()) {
			s.log.Debug("dropped a datagram from another adapter's subnet", "from", src)
			continue
		}
		if !s.allowed(src) {
			continue
		}
		s.handle(src, raw)
	}
}

func (s *Server) excluded(addr netip.Addr) bool {
	for _, p := range s.cfg.Exclude {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// handle parses one datagram and dispatches it.
func (s *Server) handle(src netip.AddrPort, raw []byte) {
	var bvlc plumbing.BVLC
	if err := bvlc.UnmarshalBinary(raw); err != nil || bvlc.Type != plumbing.BVLCType {
		s.log.Debug("dropped a datagram that is not BACnet/IP", "from", src)
		return
	}
	switch bvlc.Function {
	case plumbing.BVLCFuncUnicast, plumbing.BVLCFuncBroadcast:
	case bvlcFuncRegisterForeignDevice:
		s.log.Debug("refused a foreign device registration: the shifter is not a BBMD", "from", src)
		s.sendBVLC(src, plumbing.NewBVLCResult(bvlcResultRegisterNAK))
		return
	default:
		s.log.Debug("dropped a BVLC function the server does not take", "from", src, "function", fmt.Sprintf("%#x", bvlc.Function))
		return
	}
	offset := bvlc.MarshalLen()
	var npdu plumbing.NPDU
	if err := npdu.UnmarshalBinary(raw[offset:]); err != nil {
		s.log.Debug("dropped a datagram with a bad NPDU", "from", src, "error", err)
		return
	}
	env := Envelope{Peer: Peer{IP: src}, Broadcast: bvlc.Function == plumbing.BVLCFuncBroadcast}
	if npdu.Control&0x08 != 0 {
		env.Peer.Net, env.Peer.MAC = npdu.SNET, npdu.SADR
	}
	if npdu.Control&0x20 != 0 {
		env.HasDest, env.DNET, env.DADR = true, npdu.DNET, npdu.DADR
	}
	offset += npdu.MarshalLen()
	b := raw[offset:]
	isReply := npdu.Control&plumbing.NetworkLayerMessage == 0 && len(b) > 0 && b[0]>>4 >= plumbing.SimpleAck
	// A reply is to a request of the server's own and is matched to it; the
	// rest is work a source asks for, and is rationed per source.
	if !isReply && !s.limiter.allow(env.Peer.Key()) {
		s.droppedRate.Add(1)
		s.log.Debug("dropped a datagram over the source's rate", "from", env.Peer)
		return
	}
	if npdu.Control&plumbing.NetworkLayerMessage != 0 {
		var m plumbing.NetworkMessage
		if err := m.UnmarshalBinary(raw); err != nil {
			s.log.Debug("dropped a network layer message that could not be parsed", "from", src, "error", err)
			return
		}
		s.guard("network", env.Peer, func() { s.h.Network(env, &m) })
		return
	}
	if len(b) == 0 {
		return
	}
	switch b[0] >> 4 {
	case plumbing.ConfirmedReq:
		s.confirmed(env, b)
	case plumbing.UnConfirmedReq:
		var apdu plumbing.APDU
		if err := apdu.UnmarshalBinary(b); err != nil {
			s.log.Debug("dropped an unconfirmed request that could not be parsed", "from", env.Peer, "error", err)
			return
		}
		go s.guard("unconfirmed", env.Peer, func() { s.h.Unconfirmed(env, &apdu) })
	case plumbing.SimpleAck, plumbing.ComplexAck, plumbing.Error, plumbing.Reject, plumbing.Abort, plumbing.SegmentAck:
		var apdu plumbing.APDU
		if err := apdu.UnmarshalBinary(b); err != nil {
			s.log.Debug("dropped a reply that could not be parsed", "from", env.Peer, "error", err)
			return
		}
		s.reply(env, &apdu)
	default:
		s.log.Debug("dropped an APDU of an unknown type", "from", env.Peer, "type", b[0]>>4)
	}
}

// confirmed parses a confirmed request by hand, so that a service the
// library has no type for is seen like any other, and hands it to the
// handler unless it is a retransmission of one still being answered.
func (s *Server) confirmed(env Envelope, b []byte) {
	if len(b) < 4 {
		return
	}
	flags := b[0] & 0xF
	maxSeg, maxSize := b[1]>>4, b[1]&0xF
	invoke := b[2]
	dest, _ := env.Dest()
	from := dest
	if flags&0x8 != 0 {
		// A segmented request: not taken in v1.
		s.log.Debug("aborted a segmented request", "from", env.Peer, "invoke", invoke)
		s.sendAPDU(env.Peer, from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: invoke, Reason: objects.AbortReasonSegmentationNotSupported})
		return
	}
	req := &Request{
		Envelope: env, Service: b[3], InvokeID: invoke, s: s,
		SegmentsAccepted: flags&0x2 != 0, MaxAPDU: MaxAPDU,
	}
	if int(maxSize) < len(maxAPDUSizes) {
		req.MaxAPDU = maxAPDUSizes[maxSize]
	}
	if maxSeg >= 1 && maxSeg <= 6 {
		req.MaxSegments = 1 << maxSeg
	}
	for offset := 4; offset < len(b); {
		tag, n, err := objects.DecodeTag(b[offset:])
		if err != nil {
			s.log.Debug("rejected a request with a bad tag", "from", env.Peer, "service", req.Service, "error", err)
			s.sendAPDU(env.Peer, from, &plumbing.APDU{Type: plumbing.Reject, InvokeID: invoke, Reason: objects.RejectReasonInvalidTag})
			return
		}
		req.Tags = append(req.Tags, tag)
		offset += n
	}
	req.key = txKey{peer: env.Peer.Key(), dest: dest.key(), invoke: invoke}
	s.mu.Lock()
	if s.pending[req.key] {
		s.mu.Unlock()
		s.log.Debug("dropped a retransmission of a request still being answered", "from", env.Peer, "invoke", invoke, "service", req.Service)
		return
	}
	s.pending[req.key] = true
	s.mu.Unlock()
	release := func() {}
	if s.inFlight != nil {
		select {
		case s.inFlight <- struct{}{}:
			release = func() { <-s.inFlight }
		default:
			req.Drop()
			s.droppedInFlight.Add(1)
			s.log.Debug("dropped a request: too many being handled", "from", env.Peer, "invoke", invoke, "service", req.Service)
			return
		}
	}
	go func() {
		defer release()
		// A handler that panicked never answered: the request ends here, so
		// that its pending entry does not outlive it.
		defer req.Drop()
		s.guard("confirmed", env.Peer, func() { s.h.Confirmed(req) })
	}()
}

// reply takes a PDU a consumer sent in answer to the server: the
// acknowledgement of a confirmed request, or the Segment-ACK or Abort of a
// segmented reply in progress.
func (s *Server) reply(env Envelope, a *plumbing.APDU) {
	dest, _ := env.Dest()
	key := txKey{peer: env.Peer.Key(), dest: dest.key(), invoke: a.InvokeID}
	switch a.Type {
	case plumbing.SegmentAck:
		s.continueReply(key, a)
		return
	case plumbing.Abort:
		s.mu.Lock()
		tx, sending := s.sending[key]
		if sending {
			tx.timer.Stop()
			delete(s.sending, key)
		}
		s.mu.Unlock()
		if sending {
			return
		}
	}
	s.mu.Lock()
	ch := s.unacked[key]
	s.mu.Unlock()
	if ch == nil {
		s.log.Debug("dropped a reply for no request of the server's", "from", env.Peer, "type", a.Type, "invoke", a.InvokeID)
		return
	}
	select {
	case ch <- a:
	default:
	}
}

// ---- sending ---------------------------------------------------------------

// npduFor builds the NPDU of a message to a peer from a virtual source.
func npduFor(to Peer, from Source, expectingReply bool) *plumbing.NPDU {
	npdu := plumbing.NewNPDU(false, to.Routed(), from.Net != 0, expectingReply)
	if to.Routed() {
		npdu.DNET, npdu.DLEN, npdu.DADR, npdu.Hop = to.Net, uint8(len(to.MAC)), to.MAC, 255
	}
	if from.Net != 0 {
		npdu.SNET, npdu.SLEN, npdu.SADR = from.Net, uint8(len(from.MAC)), from.MAC
	}
	return npdu
}

// send writes one datagram. It is the only place the server writes to the
// network.
func (s *Server) send(to netip.AddrPort, b []byte) error {
	if s.cfg.OnPacket != nil {
		s.cfg.OnPacket(client.PacketEvent{Time: time.Now(), Peer: to, Data: b})
	}
	_, err := s.conn.WriteToUDPAddrPort(b, to)
	return err
}

func (s *Server) sendBVLC(to netip.AddrPort, msg plumbing.BACnet) error {
	b, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	return s.send(to, b)
}

// sendAPDU unicasts one APDU to a peer from a virtual source.
func (s *Server) sendAPDU(to Peer, from Source, a *plumbing.APDU) error {
	return s.sendFrame(to.IP, plumbing.BVLCFuncUnicast, npduFor(to, from, a.Type == plumbing.ConfirmedReq), a)
}

func (s *Server) sendFrame(to netip.AddrPort, function uint8, npdu *plumbing.NPDU, a *plumbing.APDU) error {
	bvlc := plumbing.NewBVLC(function)
	total := bvlc.MarshalLen() + npdu.MarshalLen() + a.MarshalLen()
	if total > 0xFFFF {
		return fmt.Errorf("a frame of %d bytes is too long", total)
	}
	bvlc.Length = uint16(total)
	b := make([]byte, total)
	bvlc.MarshalTo(b)
	npdu.MarshalTo(b[bvlc.MarshalLen():])
	if err := a.MarshalTo(b[bvlc.MarshalLen()+npdu.MarshalLen():]); err != nil {
		return err
	}
	return s.send(to, b)
}

// Unconfirmed unicasts an unconfirmed request to a peer from a virtual
// source: an I-Am, an I-Have, a notification.
func (s *Server) Unconfirmed(to Peer, from Source, service uint8, payload []objects.APDUPayload) error {
	return s.sendAPDU(to, from, plumbing.NewAPDU(plumbing.UnConfirmedReq, service, payload))
}

// BroadcastUnconfirmed broadcasts an unconfirmed request on the consumer
// subnet from a virtual source, as a router does with a message from one of
// its networks.
func (s *Server) BroadcastUnconfirmed(from Source, service uint8, payload []objects.APDUPayload) error {
	if !s.cfg.Broadcast.IsValid() {
		return nil
	}
	a := plumbing.NewAPDU(plumbing.UnConfirmedReq, service, payload)
	return s.sendFrame(s.cfg.Broadcast, plumbing.BVLCFuncBroadcast, npduFor(Peer{}, from, false), a)
}

// NetworkMessage unicasts a network layer message from the router itself.
func (s *Server) NetworkMessage(to netip.AddrPort, msgType uint8, data []byte) error {
	m := plumbing.NewNetworkMessage(plumbing.NewBVLC(plumbing.BVLCFuncUnicast), plumbing.NewNPDU(false, false, false, false), msgType, data)
	return s.sendBVLC(to, m)
}

// BroadcastNetworkMessage broadcasts a network layer message from the
// router itself.
func (s *Server) BroadcastNetworkMessage(msgType uint8, data []byte) error {
	if !s.cfg.Broadcast.IsValid() {
		return nil
	}
	m := plumbing.NewNetworkMessage(plumbing.NewBVLC(plumbing.BVLCFuncBroadcast), plumbing.NewNPDU(false, false, false, false), msgType, data)
	return s.sendBVLC(s.cfg.Broadcast, m)
}

// Confirmed sends a confirmed request to a peer from a virtual source and
// waits for its answer, sending it again up to Retries times when none
// comes. It is what a confirmed notification takes.
func (s *Server) Confirmed(ctx context.Context, to Peer, from Source, service uint8, payload []objects.APDUPayload) (*Reply, error) {
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, service, payload)
	req.MaxSize = 5
	ch := make(chan *plumbing.APDU, 4)
	s.mu.Lock()
	id := s.invokes[to.Key()]
	for range 256 {
		id++
		if _, used := s.unacked[txKey{peer: to.Key(), dest: from.key(), invoke: id}]; !used {
			break
		}
	}
	s.invokes[to.Key()] = id
	key := txKey{peer: to.Key(), dest: from.key(), invoke: id}
	s.unacked[key] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.unacked, key)
		s.mu.Unlock()
	}()
	req.InvokeID = id

	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		if err := s.sendAPDU(to, from, req); err != nil {
			return nil, err
		}
		timer := time.NewTimer(s.cfg.Timeout)
		select {
		case a := <-ch:
			timer.Stop()
			r := &Reply{Type: a.Type, Service: a.Service, Reason: a.Reason}
			for _, p := range a.Objects {
				if t, ok := p.(*objects.Object); ok {
					r.Tags = append(r.Tags, t)
				}
			}
			return r, nil
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-s.closed:
			timer.Stop()
			return nil, client.ErrClosed
		}
	}
	return nil, client.ErrTimeout
}

// ---- replies ---------------------------------------------------------------

// finish ends the request's pending entry. It reports false when the
// request was answered before.
func (r *Request) finish() bool {
	if !r.done.CompareAndSwap(false, true) {
		return false
	}
	r.s.mu.Lock()
	delete(r.s.pending, r.key)
	r.s.mu.Unlock()
	return true
}

// Drop ends the request without a reply, as a device that does not answer.
func (r *Request) Drop() { r.finish() }

// SimpleACK answers the request with a SimpleACK from a virtual source.
func (r *Request) SimpleACK(from Source) error {
	if !r.finish() {
		return nil
	}
	return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.SimpleAck, InvokeID: r.InvokeID, Service: r.Service})
}

// Error answers the request with an Error of the class and code.
func (r *Request) Error(from Source, class, code uint32) error {
	if !r.finish() {
		return nil
	}
	a := plumbing.NewAPDU(plumbing.Error, r.Service, []objects.APDUPayload{objects.EncEnumerated(class), objects.EncEnumerated(code)})
	a.InvokeID = r.InvokeID
	return r.s.sendAPDU(r.Peer, from, a)
}

// Reject answers the request with a Reject.
func (r *Request) Reject(from Source, reason uint8) error {
	if !r.finish() {
		return nil
	}
	return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.Reject, InvokeID: r.InvokeID, Reason: reason})
}

// Abort answers the request with a server Abort.
func (r *Request) Abort(from Source, reason uint8) error {
	if !r.finish() {
		return nil
	}
	return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: r.InvokeID, Reason: reason})
}

// ComplexACK answers the request with the tags, in one APDU when they fit
// what the consumer takes, in segments when they do not and the consumer
// takes segments, and with an Abort otherwise.
func (r *Request) ComplexACK(from Source, tags []*objects.Object) error {
	if !r.finish() {
		return nil
	}
	var payload []byte
	for _, t := range tags {
		b, err := t.MarshalBinary()
		if err != nil {
			return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: r.InvokeID, Reason: objects.AbortReasonOther})
		}
		payload = append(payload, b...)
	}
	limit := min(r.MaxAPDU, MaxAPDU)
	if 3+len(payload) <= limit {
		ack := plumbing.NewAPDU(plumbing.ComplexAck, r.Service, nil)
		ack.InvokeID = r.InvokeID
		for _, t := range tags {
			ack.Objects = append(ack.Objects, t)
		}
		return r.s.sendAPDU(r.Peer, from, ack)
	}
	if !r.SegmentsAccepted {
		return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: r.InvokeID, Reason: objects.AbortReasonSegmentationNotSupported})
	}
	tx := &segmented{to: r.Peer, from: from, service: r.Service}
	for chunk := limit - 5; len(payload) > 0; {
		n := min(chunk, len(payload))
		tx.segments = append(tx.segments, payload[:n])
		payload = payload[n:]
	}
	if r.MaxSegments > 0 && len(tx.segments) > r.MaxSegments {
		return r.s.sendAPDU(r.Peer, from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: r.InvokeID, Reason: objects.AbortReasonBufferOverflow})
	}
	r.s.mu.Lock()
	tx.timer = time.AfterFunc(r.s.cfg.SegmentTimeout, func() { r.s.segmentTimeout(r.key, tx) })
	r.s.sending[r.key] = tx
	r.s.mu.Unlock()
	// The first segment goes out alone; the rest follow the acknowledgements.
	return r.s.sendSegments(r.key, tx, 0, 1)
}

// segmentTimeout aborts a segmented reply whose consumer stopped
// acknowledging, so that the sending map holds nothing forever.
func (s *Server) segmentTimeout(key txKey, tx *segmented) {
	s.mu.Lock()
	if s.sending[key] != tx {
		s.mu.Unlock()
		return
	}
	delete(s.sending, key)
	s.mu.Unlock()
	s.log.Debug("aborted a segmented reply: no Segment-ACK in time", "to", tx.to, "invoke", key.invoke)
	s.sendAPDU(tx.to, tx.from, &plumbing.APDU{Type: plumbing.Abort, Flags: 0x1, InvokeID: key.invoke, Reason: objects.AbortReasonTSMTimeout})
}

func (s *Server) sendSegments(key txKey, tx *segmented, from, count int) error {
	for i := from; i < from+count && i < len(tx.segments); i++ {
		seg := &plumbing.APDU{
			Type:               plumbing.ComplexAck,
			Flags:              0x8,
			InvokeID:           key.invoke,
			SequenceNumber:     uint8(i),
			ProposedWindowSize: s.cfg.Window,
			Service:            tx.service,
			Payload:            tx.segments[i],
		}
		if i < len(tx.segments)-1 {
			seg.Flags |= 0x4
		}
		if err := s.sendAPDU(tx.to, tx.from, seg); err != nil {
			return err
		}
	}
	return nil
}

// continueReply sends the segments that follow the one a Segment-ACK
// acknowledges, a window of them as the acknowledgement sizes it.
func (s *Server) continueReply(key txKey, ack *plumbing.APDU) {
	s.mu.Lock()
	tx := s.sending[key]
	next := int(ack.SequenceNumber) + 1
	if tx != nil {
		if next >= len(tx.segments) {
			tx.timer.Stop()
			delete(s.sending, key)
			tx = nil
		} else {
			tx.timer.Reset(s.cfg.SegmentTimeout)
		}
	}
	s.mu.Unlock()
	if tx != nil {
		s.sendSegments(key, tx, next, max(1, int(ack.ActualWindowSize)))
	}
}

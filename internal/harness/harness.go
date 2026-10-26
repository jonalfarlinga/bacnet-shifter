// Package harness runs the simulated site, the shifter and a consumer on
// loopback for the tests: client/sim as the site, the shifter with both
// sockets on 127.0.0.1, a client.Client as the consumer with the shifter's
// consumer address as its broadcast, recorders on every socket, and a raw
// sender for the services the consumer client's guard will not send.
package harness

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/client/sim"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
)

// Recorder keeps every datagram a socket sent and received.
type Recorder struct {
	mu     sync.Mutex
	events []client.PacketEvent
}

// OnPacket is the recorder's hook.
func (r *Recorder) OnPacket(e client.PacketEvent) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

// Events is a copy of what was recorded.
func (r *Recorder) Events() []client.PacketEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]client.PacketEvent(nil), r.events...)
}

// Sent is the datagrams the socket sent.
func (r *Recorder) Sent() [][]byte {
	var out [][]byte
	for _, e := range r.Events() {
		if !e.Inbound {
			out = append(out, e.Data)
		}
	}
	return out
}

// Options says what to run.
type Options struct {
	// Stations is the site; nil runs sim.Default().
	Stations [][]*sim.Device
	// ForeignDevice registers the site client with the first station as a
	// BBMD, as for sim.RemoteSite.
	ForeignDevice bool
	Control       control.Level
	// DataDir holds the key and table; a temporary directory if empty.
	DataDir string
	// Network is V; 9000 if 0.
	Network uint16
	Logger  *slog.Logger
	// WhoIsInterval, if set, replaces the shifter's default.
	WhoIsInterval time.Duration
	// Writer replaces the site client as the shifter's writer; nil keeps
	// the client. The tests of the write path's translation and of the
	// site's answers use a FakeWriter.
	Writer shifter.SiteWriter
	// Survey, if set, is the shifter's survey configuration.
	Survey *shifter.SurveyConfig
	// Configure, if set, adjusts the shifter's configuration before it
	// starts: the bounds, mostly. The bench's own default lifts the
	// per-source rate limit, since the consumer client reads from one
	// address as fast as loopback allows; Configure runs after it.
	Configure func(cfg *shifter.Config)
}

// Bench is a running site, shifter and consumer.
type Bench struct {
	t        *testing.T
	Sim      *sim.Network
	Shifter  *shifter.Shifter
	Consumer *client.Client
	// SiteRec records the shifter's site socket, ServerRec the shifter's
	// consumer socket, and ConsumerRec the consumer client's socket.
	SiteRec, ServerRec, ConsumerRec *Recorder
	DataDir                         string
	Key                             pseudonym.Key

	mu    sync.Mutex
	found map[uint32]client.Device
	// direct is a client straight to the sim, opened on demand.
	direct      *client.Client
	directFound map[uint32]client.Device
}

// Start runs the bench. It is closed when the test ends.
func Start(t *testing.T, opts Options) *Bench {
	t.Helper()
	if opts.Stations == nil {
		opts.Stations = sim.Default()
	}
	if opts.Network == 0 {
		opts.Network = 9000
	}
	if opts.DataDir == "" {
		opts.DataDir = t.TempDir()
	}
	b := &Bench{t: t, DataDir: opts.DataDir, SiteRec: &Recorder{}, ServerRec: &Recorder{}, ConsumerRec: &Recorder{},
		found: map[uint32]client.Device{}, directFound: map[uint32]client.Device{}}

	network, err := sim.StartDevices(opts.Stations)
	if err != nil {
		t.Fatal(err)
	}
	b.Sim = network

	key, _, err := pseudonym.LoadOrCreate(filepath.Join(opts.DataDir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	b.Key = key
	tb, err := table.Open(filepath.Join(opts.DataDir, "table.json"), pseudonym.New(key), opts.Network)
	if err != nil {
		t.Fatal(err)
	}
	siteCfg := client.Config{
		Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: network.Addr(),
		Timeout: time.Second, Retries: 1, MaxRequestsPerSec: -1, OnPacket: b.SiteRec.OnPacket,
	}
	if opts.ForeignDevice {
		siteCfg.ForeignDevice = &client.ForeignDeviceConfig{BBMD: network.Addr(), TTL: time.Minute}
	}
	cfg := shifter.Config{
		Site: siteCfg,
		Consumer: server.Config{
			Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: 500 * time.Millisecond, Retries: 1, OnPacket: b.ServerRec.OnPacket,
			MaxRPSPerSource: -1,
		},
		Control: opts.Control, Reserved: control.DefaultReserved(), Table: tb, Logger: opts.Logger,
		WhoIsInterval: opts.WhoIsInterval, Writer: opts.Writer, Survey: opts.Survey,
	}
	if opts.Configure != nil {
		opts.Configure(&cfg)
	}
	sh, err := shifter.Start(cfg)
	if err != nil {
		network.Close()
		t.Fatal(err)
	}
	b.Shifter = sh

	consumer, err := client.Open(client.Config{
		Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: sh.ConsumerAddr(),
		Timeout: time.Second, Retries: 1, MaxRequestsPerSec: -1, OnPacket: b.ConsumerRec.OnPacket,
		OnIAm: func(d client.Device) {
			b.mu.Lock()
			b.found[d.Instance] = d
			b.mu.Unlock()
		},
	})
	if err != nil {
		sh.Close()
		network.Close()
		t.Fatal(err)
	}
	b.Consumer = consumer
	t.Cleanup(b.Close)
	return b
}

// Close stops everything, in the order the test needs: the consumer, the
// shifter, the direct client, the sim.
func (b *Bench) Close() {
	if b.Consumer != nil {
		b.Consumer.Close()
		b.Consumer = nil
	}
	if b.Shifter != nil {
		b.Shifter.Close()
		b.Shifter = nil
	}
	if b.direct != nil {
		b.direct.Close()
		b.direct = nil
	}
	if b.Sim != nil {
		b.Sim.Close()
		b.Sim = nil
	}
}

// NewConsumer opens another consumer client on loopback, with a function
// that gives the devices it has heard.
func (b *Bench) NewConsumer() (*client.Client, func() map[uint32]client.Device) {
	b.t.Helper()
	var mu sync.Mutex
	found := map[uint32]client.Device{}
	c, err := client.Open(client.Config{
		Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: b.Shifter.ConsumerAddr(),
		Timeout: time.Second, Retries: 1, MaxRequestsPerSec: -1,
		OnIAm: func(d client.Device) {
			mu.Lock()
			found[d.Instance] = d
			mu.Unlock()
		},
	})
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { c.Close() })
	return c, func() map[uint32]client.Device {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[uint32]client.Device, len(found))
		for k, v := range found {
			out[k] = v
		}
		return out
	}
}

// Heard is the devices the consumer has heard, by virtual instance.
func (b *Bench) Heard() map[uint32]client.Device {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[uint32]client.Device, len(b.found))
	for k, v := range b.found {
		out[k] = v
	}
	return out
}

// AwaitDevices sends Who-Is until the consumer has heard n devices, or
// fails after the wait.
func (b *Bench) AwaitDevices(n int, wait time.Duration) map[uint32]client.Device {
	b.t.Helper()
	deadline := time.Now().Add(wait)
	for {
		if err := b.Consumer.WhoIs(); err != nil {
			b.t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
		if heard := b.Heard(); len(heard) >= n {
			return heard
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("the consumer heard %d devices in %s, want %d", len(b.Heard()), wait, n)
		}
	}
}

// Direct is a client straight to the sim, for reads to compare with, and
// the devices it heard by real instance.
func (b *Bench) Direct() (*client.Client, map[uint32]client.Device) {
	b.t.Helper()
	b.mu.Lock()
	c := b.direct
	b.mu.Unlock()
	if c == nil {
		var err error
		c, err = client.Open(client.Config{
			Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: b.Sim.Addr(),
			Timeout: 2 * time.Second, Retries: 1, MaxRequestsPerSec: -1,
			OnIAm: func(d client.Device) {
				b.mu.Lock()
				b.directFound[d.Instance] = d
				b.mu.Unlock()
			},
		})
		if err != nil {
			b.t.Fatal(err)
		}
		b.mu.Lock()
		b.direct = c
		b.mu.Unlock()
		if err := c.WhoIs(); err != nil {
			b.t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[uint32]client.Device, len(b.directFound))
	for k, v := range b.directFound {
		out[k] = v
	}
	return c, out
}

// Ctx is a context that ends with the test.
func (b *Bench) Ctx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	b.t.Cleanup(cancel)
	return ctx
}

// ---- the fake site writer --------------------------------------------------

// WriteCall is one WriteProperty a FakeWriter was asked to send.
type WriteCall struct {
	To       client.Address
	Object   client.ObjectID
	Property uint16
	Value    []*objects.Object
	Priority uint8
}

// FakeWriter stands in for the library client's WriteProperty: it records
// each call and answers with the error set, nil being the site's
// SimpleACK.
type FakeWriter struct {
	mu    sync.Mutex
	calls []WriteCall
	err   error
}

// WriteProperty implements shifter.SiteWriter.
func (f *FakeWriter) WriteProperty(_ context.Context, to client.Address, obj client.ObjectID, prop uint16, value []*objects.Object, priority uint8) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, WriteCall{To: to, Object: obj, Property: prop, Value: append([]*objects.Object(nil), value...), Priority: priority})
	return f.err
}

// SetErr sets what every call returns from now on.
func (f *FakeWriter) SetErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// Calls is a copy of what was recorded.
func (f *FakeWriter) Calls() []WriteCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]WriteCall(nil), f.calls...)
}

// ---- the raw sender --------------------------------------------------------

// Raw is a socket that sends frames built with plumbing and reads what
// comes back, for the services the consumer client will not send.
type Raw struct {
	Conn *net.UDPConn
}

// Received is one datagram the raw sender read.
type Received struct {
	From netip.AddrPort
	BVLC plumbing.BVLC
	NPDU plumbing.NPDU
	// APDU is set for an application message, Network for a network layer
	// message.
	APDU    *plumbing.APDU
	Network *plumbing.NetworkMessage
}

// NewRaw opens a raw sender on loopback.
func NewRaw(t *testing.T) *Raw {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Raw{Conn: conn}
}

// Local is the sender's address.
func (r *Raw) Local() netip.AddrPort {
	ap := r.Conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// NPDUTo builds the NPDU of a message to a routed destination, from a
// routed source when snet is not 0.
func NPDUTo(dnet uint16, dadr []byte, snet uint16, sadr []byte, expectingReply bool) *plumbing.NPDU {
	npdu := plumbing.NewNPDU(false, true, snet != 0, expectingReply)
	npdu.DNET, npdu.DLEN, npdu.DADR, npdu.Hop = dnet, uint8(len(dadr)), dadr, 255
	if snet != 0 {
		npdu.SNET, npdu.SLEN, npdu.SADR = snet, uint8(len(sadr)), sadr
	}
	return npdu
}

// Send sends one APDU in a unicast envelope.
func (r *Raw) Send(t *testing.T, to netip.AddrPort, npdu *plumbing.NPDU, a *plumbing.APDU) {
	t.Helper()
	bvlc := plumbing.NewBVLC(plumbing.BVLCFuncUnicast)
	b := make([]byte, bvlc.MarshalLen()+npdu.MarshalLen()+a.MarshalLen())
	bvlc.Length = uint16(len(b))
	bvlc.MarshalTo(b)
	npdu.MarshalTo(b[bvlc.MarshalLen():])
	if err := a.MarshalTo(b[bvlc.MarshalLen()+npdu.MarshalLen():]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Conn.WriteToUDPAddrPort(b, to); err != nil {
		t.Fatal(err)
	}
}

// SendIAm sends an I-Am for a device instance from the raw socket, as a
// site device would: a unicast to the shifter's site socket, with no
// routing. The shifter then takes the raw socket for the device's address.
func (r *Raw) SendIAm(t *testing.T, to netip.AddrPort, instance uint32) {
	t.Helper()
	r.Send(t, to, plumbing.NewNPDU(false, false, false, false),
		plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedIAm, services.IAmObjects(instance, 1476, 3, 999)))
}

// AnswerWithError makes the raw socket stand in for a site device that
// answers every confirmed request with the Error given, until the socket
// is closed. It is for a device that must answer but need not have
// anything: a device whose address is probed, a flood of devices whose
// names are read. The socket cannot be read by the test while it runs.
func (r *Raw) AnswerWithError(t *testing.T, class, code uint32) {
	t.Helper()
	go func() {
		buf := make([]byte, 2048)
		for {
			r.Conn.SetReadDeadline(time.Time{})
			n, from, err := r.Conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var bvlc plumbing.BVLC
			var npdu plumbing.NPDU
			if bvlc.UnmarshalBinary(buf[:n]) != nil || npdu.UnmarshalBinary(buf[bvlc.MarshalLen():n]) != nil || npdu.Control&plumbing.NetworkLayerMessage != 0 {
				continue
			}
			var a plumbing.APDU
			if a.UnmarshalBinary(buf[bvlc.MarshalLen()+npdu.MarshalLen():n]) != nil || a.Type != plumbing.ConfirmedReq {
				continue
			}
			reply := plumbing.NewAPDU(plumbing.Error, a.Service, []objects.APDUPayload{objects.EncEnumerated(class), objects.EncEnumerated(code)})
			reply.InvokeID = a.InvokeID
			out := plumbing.NewBVLC(plumbing.BVLCFuncUnicast)
			back := plumbing.NewNPDU(false, false, false, false)
			b := make([]byte, out.MarshalLen()+back.MarshalLen()+reply.MarshalLen())
			out.Length = uint16(len(b))
			out.MarshalTo(b)
			back.MarshalTo(b[out.MarshalLen():])
			if reply.MarshalTo(b[out.MarshalLen()+back.MarshalLen():]) != nil {
				continue
			}
			r.Conn.WriteToUDPAddrPort(b, from)
		}
	}()
}

// SendNetwork sends one network layer message.
func (r *Raw) SendNetwork(t *testing.T, to netip.AddrPort, msgType uint8, data []byte) {
	t.Helper()
	m := plumbing.NewNetworkMessage(plumbing.NewBVLC(plumbing.BVLCFuncUnicast), plumbing.NewNPDU(false, false, false, false), msgType, data)
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Conn.WriteToUDPAddrPort(b, to); err != nil {
		t.Fatal(err)
	}
}

// Receive reads one datagram, or returns nil when none comes within the
// wait.
func (r *Raw) Receive(t *testing.T, wait time.Duration) *Received {
	t.Helper()
	buf := make([]byte, 2048)
	r.Conn.SetReadDeadline(time.Now().Add(wait))
	n, from, err := r.Conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil
	}
	rcv := &Received{From: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
	if err := rcv.BVLC.UnmarshalBinary(buf[:n]); err != nil {
		t.Fatal(err)
	}
	offset := rcv.BVLC.MarshalLen()
	if err := rcv.NPDU.UnmarshalBinary(buf[offset:n]); err != nil {
		t.Fatal(err)
	}
	if rcv.NPDU.Control&plumbing.NetworkLayerMessage != 0 {
		rcv.Network = &plumbing.NetworkMessage{}
		if err := rcv.Network.UnmarshalBinary(buf[:n]); err != nil {
			t.Fatal(err)
		}
		return rcv
	}
	offset += rcv.NPDU.MarshalLen()
	rcv.APDU = &plumbing.APDU{}
	if err := rcv.APDU.UnmarshalBinary(buf[offset:n]); err != nil {
		t.Fatal(err)
	}
	return rcv
}

// Drain reads and discards whatever is waiting.
func (r *Raw) Drain(t *testing.T) {
	t.Helper()
	for r.Receive(t, 50*time.Millisecond) != nil {
	}
}

// Exchange sends and reads the first reply.
func (r *Raw) Exchange(t *testing.T, to netip.AddrPort, npdu *plumbing.NPDU, a *plumbing.APDU, wait time.Duration) *Received {
	t.Helper()
	r.Send(t, to, npdu, a)
	return r.Receive(t, wait)
}

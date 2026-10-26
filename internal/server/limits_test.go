package server

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"
)

// The bounded map keeps at most its size, forgetting the entry used
// longest ago, and Get counts as use.
func TestBounded(t *testing.T) {
	b := NewBounded[int](3)
	b.Put("a", 1)
	b.Put("b", 2)
	b.Put("c", 3)
	b.Get("a") // a is now the most recent; b the oldest
	b.Put("d", 4)
	if _, ok := b.Get("b"); ok {
		t.Error("b, the oldest, survived the fourth entry")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := b.Get(k); !ok {
			t.Errorf("%s was lost", k)
		}
	}
	if n := b.Len(); n != 3 {
		t.Errorf("%d entries, want 3", n)
	}
	b.Each(func(k string, v int) bool { return k != "c" })
	if _, ok := b.Get("c"); ok || b.Len() != 2 {
		t.Error("Each did not delete c")
	}
	b.Delete("a")
	if b.Len() != 1 {
		t.Error("Delete did not delete a")
	}
}

// The limiter gives each source its burst and then its rate, and forgets
// the oldest source past the bound.
func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(10, 2)
	l.now = func() time.Time { return now }
	for i := range 10 {
		if !l.allow("x") {
			t.Fatalf("request %d of the burst was refused", i)
		}
	}
	if l.allow("x") {
		t.Error("the eleventh request in the same instant was allowed")
	}
	now = now.Add(100 * time.Millisecond)
	if !l.allow("x") || l.allow("x") {
		t.Error("a tenth of a second refills one token, not two")
	}
	l.allow("y")
	l.allow("z") // x, the oldest, is forgotten
	if !l.allow("x") {
		t.Error("a forgotten source does not start over with a full bucket")
	}
	var none *limiter
	if !none.allow("anyone") {
		t.Error("no limiter refuses")
	}
}

// slow is a handler that holds each request until released.
type slow struct {
	srv     *Server
	calls   atomic.Int32
	release chan struct{}
	panics  bool
}

func (h *slow) Confirmed(req *Request) {
	h.calls.Add(1)
	if h.panics {
		panic("a handler bug")
	}
	<-h.release
	dest, _ := req.Dest()
	req.SimpleACK(dest)
}

func (h *slow) Unconfirmed(env Envelope, apdu *plumbing.APDU) {
	if h.panics {
		panic("an unconfirmed handler bug")
	}
	if apdu.Service == services.ServiceUnconfirmedWhoIs {
		h.srv.Unconfirmed(env.Peer, device, services.ServiceUnconfirmedIAm, services.IAmObjects(4242, 1476, 0, 999))
	}
}

func (h *slow) Network(env Envelope, m *plumbing.NetworkMessage) {
	if h.panics {
		panic("a network handler bug")
	}
}

func openWith(t *testing.T, cfg Config, h Handler) *Server {
	t.Helper()
	cfg.Local = netip.MustParseAddrPort("127.0.0.1:0")
	srv, err := Open(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func subscribeAPDU(invoke uint8) *plumbing.APDU {
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedSubscribeCOV, services.COVObjects(1, objects.ObjectTypeAnalogInput, 1, false, 60))
	req.InvokeID, req.MaxSize = invoke, 5
	req.SetAPDUFlags(true, false, false)
	return req
}

// Beyond MaxInFlight a confirmed request is dropped, counted, and its
// pending entry does not linger; once a handler finishes, the next request
// is taken.
func TestInFlightCap(t *testing.T) {
	h := &slow{release: make(chan struct{})}
	srv := openWith(t, Config{Timeout: 200 * time.Millisecond, MaxInFlight: 2, MaxRPSPerSource: -1}, h)
	h.srv = srv
	raw := newRaw(t)
	npdu := npduTo(9000, []byte{0, 1}, 0, nil)
	for i := uint8(1); i <= 4; i++ {
		raw.send(t, srv.Local(), npdu, subscribeAPDU(i))
	}
	time.Sleep(100 * time.Millisecond)
	if n := h.calls.Load(); n != 2 {
		t.Errorf("the handler got %d requests, want 2", n)
	}
	if d := srv.Dropped(); d.InFlight != 2 {
		t.Errorf("%d dropped at the cap, want 2", d.InFlight)
	}
	srv.mu.Lock()
	pending := len(srv.pending)
	srv.mu.Unlock()
	if pending != 2 {
		t.Errorf("%d pending entries, want 2: the dropped ones must not linger", pending)
	}
	close(h.release)
	for i := 0; i < 2; i++ {
		if reply := raw.receive(t, time.Second); reply == nil || reply.Type != plumbing.SimpleAck {
			t.Fatalf("reply %d: %+v", i, reply)
		}
	}
	raw.send(t, srv.Local(), npdu, subscribeAPDU(9))
	if reply := raw.receive(t, time.Second); reply == nil || reply.Type != plumbing.SimpleAck || reply.InvokeID != 9 {
		t.Errorf("after the handlers finished: %+v", reply)
	}
}

// A source gets its burst and no more within the second; a reply is never
// rationed; another source has a bucket of its own.
func TestRatePerSource(t *testing.T) {
	h := &slow{release: make(chan struct{})}
	close(h.release)
	srv := openWith(t, Config{Timeout: 200 * time.Millisecond, MaxRPSPerSource: 5}, h)
	h.srv = srv
	raw := newRaw(t)
	whoIs := plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil)
	plain := plumbing.NewNPDU(false, false, false, false)
	for range 8 {
		raw.send(t, srv.Local(), plain, whoIs)
	}
	got := 0
	for raw.receive(t, 200*time.Millisecond) != nil {
		got++
	}
	if got != 5 {
		t.Errorf("%d I-Ams to a source that sent 8 Who-Is in a burst, want 5", got)
	}
	if d := srv.Dropped(); d.Rate != 3 {
		t.Errorf("%d dropped by the rate limit, want 3", d.Rate)
	}
	other := newRaw(t)
	other.send(t, srv.Local(), plain, whoIs)
	if other.receive(t, time.Second) == nil {
		t.Error("another source was rationed with the first")
	}
	// A Segment-ACK is a reply: it passes the limit, and is dropped for
	// matching nothing, rather than counted.
	raw.send(t, srv.Local(), plain, &plumbing.APDU{Type: plumbing.SegmentAck, InvokeID: 1})
	if d := srv.Dropped(); d.Rate != 3 {
		t.Errorf("a reply was rationed: %d dropped", d.Rate)
	}
}

// A segmented reply whose consumer stops acknowledging is aborted after
// SegmentTimeout and forgotten.
func TestSegmentTimeout(t *testing.T) {
	h := &canned{listSize: 500}
	srv := openWith(t, Config{Timeout: 200 * time.Millisecond, SegmentTimeout: 300 * time.Millisecond, MaxRPSPerSource: -1}, h)
	h.srv = srv
	raw := newRaw(t)
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectList))
	req.InvokeID, req.MaxSize = 9, 5
	req.SetAPDUFlags(true, false, false)
	first := raw.exchange(t, srv.Local(), npduTo(9000, []byte{0, 1}, 0, nil), req)
	if first == nil || first.Type != plumbing.ComplexAck || first.Flags&0x8 == 0 {
		t.Fatalf("got %+v, want the first segment", first)
	}
	srv.mu.Lock()
	held := len(srv.sending)
	srv.mu.Unlock()
	if held != 1 {
		t.Fatalf("%d segmented replies held, want 1", held)
	}
	abort := raw.receive(t, time.Second)
	if abort == nil || abort.Type != plumbing.Abort || abort.Reason != objects.AbortReasonTSMTimeout || abort.InvokeID != 9 {
		t.Errorf("got %+v, want a server Abort, TSM timeout", abort)
	}
	srv.mu.Lock()
	held = len(srv.sending)
	srv.mu.Unlock()
	if held != 0 {
		t.Errorf("%d segmented replies still held after the timeout", held)
	}
}

// A handler that panics loses that one message and nothing else: the
// request's pending entry and in-flight slot are released, the panic is
// counted, and the server goes on serving.
func TestRecovery(t *testing.T) {
	h := &slow{release: make(chan struct{}), panics: true}
	close(h.release)
	srv := openWith(t, Config{Timeout: 200 * time.Millisecond, MaxInFlight: 1, MaxRPSPerSource: -1}, h)
	h.srv = srv
	raw := newRaw(t)
	npdu := npduTo(9000, []byte{0, 1}, 0, nil)
	plain := plumbing.NewNPDU(false, false, false, false)
	raw.send(t, srv.Local(), npdu, subscribeAPDU(1))
	raw.send(t, srv.Local(), plain, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil))
	b, _ := plumbing.NewNetworkMessage(plumbing.NewBVLC(plumbing.BVLCFuncUnicast), plumbing.NewNPDU(false, false, false, false), plumbing.NetMsgWhoIsRouterToNetwork, nil).MarshalBinary()
	raw.conn.WriteToUDPAddrPort(b, srv.Local())
	deadline := time.Now().Add(2 * time.Second)
	for srv.Dropped().Panics < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d := srv.Dropped(); d.Panics != 3 {
		t.Fatalf("%d panics recovered, want 3", d.Panics)
	}
	srv.mu.Lock()
	pending := len(srv.pending)
	srv.mu.Unlock()
	if pending != 0 || len(srv.inFlight) != 0 {
		t.Errorf("after the panic: %d pending, %d in flight", pending, len(srv.inFlight))
	}
	h.panics = false
	raw.send(t, srv.Local(), npdu, subscribeAPDU(2))
	if reply := raw.receive(t, time.Second); reply == nil || reply.Type != plumbing.SimpleAck {
		t.Errorf("after the panic the server answered %+v", reply)
	}
}

// Close with a segmented reply in progress stops its timer and sends
// nothing more.
func TestCloseWithSegments(t *testing.T) {
	h := &canned{listSize: 500}
	srv := openWith(t, Config{Timeout: 200 * time.Millisecond, SegmentTimeout: 200 * time.Millisecond, MaxRPSPerSource: -1}, h)
	h.srv = srv
	c, err := client.Open(client.Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: srv.Local(), Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	raw := newRaw(t)
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectList))
	req.InvokeID, req.MaxSize = 9, 5
	req.SetAPDUFlags(true, false, false)
	if first := raw.exchange(t, srv.Local(), npduTo(9000, []byte{0, 1}, 0, nil), req); first == nil {
		t.Fatal("no first segment")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); srv.Close() }()
	wg.Wait()
	if reply := raw.receive(t, 400*time.Millisecond); reply != nil {
		t.Errorf("after Close the server sent %+v", reply)
	}
	_ = context.Background()
}

// With Allow set, a datagram from a source outside it is dropped before
// parsing and counted; one within it is served; with Allow empty every
// source is.
func TestAllowList(t *testing.T) {
	h := &slow{release: make(chan struct{})}
	close(h.release)
	whoIs := plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil)
	plain := plumbing.NewNPDU(false, false, false, false)
	for _, tc := range []struct {
		name   string
		allow  []netip.Prefix
		served bool
	}{
		{"empty serves everyone", nil, true},
		{"loopback is within", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8")}, true},
		{"loopback is outside", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false},
	} {
		srv := openWith(t, Config{Timeout: 200 * time.Millisecond, MaxRPSPerSource: -1, Allow: tc.allow}, h)
		h.srv = srv
		raw := newRaw(t)
		raw.send(t, srv.Local(), plain, whoIs)
		raw.send(t, srv.Local(), plain, whoIs)
		got := raw.receive(t, 300*time.Millisecond) != nil
		if got != tc.served {
			t.Errorf("%s: served %t, want %t", tc.name, got, tc.served)
		}
		want := uint64(0)
		if !tc.served {
			want = 2
		}
		if d := srv.Dropped(); d.Allow != want {
			t.Errorf("%s: %d dropped by the allow list, want %d", tc.name, d.Allow, want)
		}
		srv.Close()
	}
}

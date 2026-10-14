package server

import (
	"context"
	"errors"
	"net"
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

// canned is a handler that answers as one device on virtual network 9000
// at MAC 00 01: its object list is long enough to segment, and it takes
// subscriptions.
type canned struct {
	srv      *Server
	calls    atomic.Int32
	delay    time.Duration
	listSize int
}

var device = Source{Net: 9000, MAC: []byte{0, 1}}

func (h *canned) Confirmed(req *Request) {
	h.calls.Add(1)
	time.Sleep(h.delay)
	dest, _ := req.Dest()
	switch req.Service {
	case services.ServiceConfirmedReadProperty:
		if len(req.Tags) < 2 {
			req.Reject(dest, objects.RejectReasonMissingRequiredParameter)
			return
		}
		id, _ := objects.DecObjectIdentifier(req.Tags[0])
		prop, _ := objects.DecUnsignedInteger(req.Tags[1])
		tags := []*objects.Object{
			objects.EncObjectIdentifier(true, 0, id.ObjectType, id.InstanceNumber),
			objects.ContextTag(1, objects.EncUnsignedInteger(uint(prop))),
			objects.EncOpeningTag(3),
		}
		switch uint16(prop) {
		case objects.PropertyIdObjectName:
			tags = append(tags, objects.EncString("DEV-canned"))
		case objects.PropertyIdObjectList:
			for i := 0; i < h.listSize; i++ {
				tags = append(tags, objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeAnalogInput, uint32(i)))
			}
		default:
			req.Error(dest, uint32(objects.ErrorClassProperty), 32)
			return
		}
		req.ComplexACK(dest, append(tags, objects.EncClosingTag(3)))
	case services.ServiceConfirmedSubscribeCOV:
		req.SimpleACK(dest)
	case 99:
		req.Drop()
	default:
		req.Reject(dest, objects.RejectReasonUnrecognizedService)
	}
}

func (h *canned) Unconfirmed(env Envelope, apdu *plumbing.APDU) {
	if apdu.Service == services.ServiceUnconfirmedWhoIs {
		h.srv.Unconfirmed(env.Peer, device, services.ServiceUnconfirmedIAm, services.IAmObjects(4242, 1476, 0, 999))
	}
}

func (h *canned) Network(env Envelope, m *plumbing.NetworkMessage) {
	if m.Type == plumbing.NetMsgWhoIsRouterToNetwork {
		h.srv.NetworkMessage(env.Peer.IP, plumbing.NetMsgIAmRouterToNetwork, plumbing.NetworksData(9000))
	}
}

func start(t *testing.T, h *canned) (*Server, *client.Client, client.Device) {
	t.Helper()
	srv, err := Open(Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: 200 * time.Millisecond, Retries: 1}, h)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	t.Cleanup(func() { srv.Close() })

	var mu sync.Mutex
	var found []client.Device
	c, err := client.Open(client.Config{
		Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: srv.Local(), Timeout: 500 * time.Millisecond, Retries: 1,
		OnIAm: func(d client.Device) { mu.Lock(); found = append(found, d); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.WhoIs(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(found)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no I-Am arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	return srv, c, found[0]
}

var deviceObject = client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 4242}

// A client on loopback discovers the virtual device through the server's
// routed I-Am, reads from it, gets its errors, and reads a reply long enough
// to segment.
func TestReadsAndSegments(t *testing.T) {
	h := &canned{listSize: 500}
	_, c, dev := start(t, h)
	if dev.Instance != 4242 || dev.Addr.Net != 9000 || string(dev.Addr.MAC) != "\x00\x01" {
		t.Fatalf("the device is %+v, want 4242 at (9000, 0001)", dev)
	}
	if _, ok := c.Routes()[9000]; !ok {
		t.Error("the route to 9000 was not learned from the I-Am")
	}
	ctx := context.Background()
	values, err := c.ReadProperty(ctx, dev.Addr, deviceObject, objects.PropertyIdObjectName)
	if err != nil || len(values) != 1 || values[0].Str != "DEV-canned" {
		t.Fatalf("name: %+v, %v", values, err)
	}
	_, err = c.ReadProperty(ctx, dev.Addr, deviceObject, objects.PropertyIdDescription)
	var be *client.BACnetError
	if !errors.As(err, &be) || be.Class != uint32(objects.ErrorClassProperty) || be.Code != 32 {
		t.Errorf("an unknown property gave %v, want property: unknown property", err)
	}
	values, err = c.ReadProperty(ctx, dev.Addr, deviceObject, objects.PropertyIdObjectList)
	if err != nil || len(values) != 500 {
		t.Fatalf("object list: %d values, %v", len(values), err)
	}
	// A reply the client cannot take in one segment is aborted and the
	// server forgets it.
	_, err = c.ReadPropertyMultiple(ctx, dev.Addr, []client.ReadSpec{{Object: deviceObject, Props: []uint16{objects.PropertyIdObjectName}}})
	var re *client.RejectError
	if !errors.As(err, &re) {
		t.Errorf("an unhandled service gave %v, want a Reject", err)
	}
	if n := len(h.srv.sending); n != 0 {
		t.Errorf("%d segmented replies still held", n)
	}
}

// A client that cannot take segments gets an Abort for a long reply.
func TestNoSegments(t *testing.T) {
	h := &canned{listSize: 500}
	srv, _, _ := start(t, h)
	raw := newRaw(t)
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectList))
	req.InvokeID, req.MaxSize = 9, 5 // no SA flag
	reply := raw.exchange(t, srv.Local(), npduTo(9000, []byte{0, 1}, 0, nil), req)
	if reply == nil || reply.Type != plumbing.Abort || reply.Reason != objects.AbortReasonSegmentationNotSupported || reply.Flags&0x1 == 0 {
		t.Errorf("got %+v, want a server Abort, segmentation not supported", reply)
	}
}

// A confirmed notification to a subscribed client is acknowledged, and one
// to nobody times out.
func TestConfirmedNotification(t *testing.T) {
	h := &canned{}
	srv, c, dev := start(t, h)
	ctx := context.Background()
	got := make(chan client.COVNotification, 4)
	object := client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 1}
	if _, err := c.SubscribeCOV(ctx, dev.Addr, object, client.COVOptions{Confirmed: true, ProcessID: 7}, func(n client.COVNotification) { got <- n }); err != nil {
		t.Fatal(err)
	}
	payload := []objects.APDUPayload{
		objects.ContextTag(0, objects.EncUnsignedInteger(7)),
		objects.EncObjectIdentifier(true, 1, objects.ObjectTypeDevice, 4242),
		objects.EncObjectIdentifier(true, 2, object.Type, object.Instance),
		objects.ContextTag(3, objects.EncUnsignedInteger(60)),
		objects.EncOpeningTag(4),
		objects.ContextTag(0, objects.EncUnsignedInteger(uint(objects.PropertyIdPresentValue))),
		objects.EncOpeningTag(2), objects.EncReal(1.5), objects.EncClosingTag(2),
		objects.EncClosingTag(4),
	}
	reply, err := srv.Confirmed(ctx, Peer{IP: c.Local()}, device, services.ServiceConfirmedCOVNotification, payload)
	if err != nil || reply.Type != plumbing.SimpleAck {
		t.Fatalf("notification: %+v, %v", reply, err)
	}
	select {
	case n := <-got:
		if !n.Confirmed || n.ProcessID != 7 || n.Device != 4242 {
			t.Errorf("delivered %+v", n)
		}
	case <-time.After(time.Second):
		t.Error("the notification was not delivered")
	}
	// Process 8 is nobody's: no acknowledgement, two sends, a timeout.
	payload[0] = objects.ContextTag(0, objects.EncUnsignedInteger(8))
	start := time.Now()
	_, err = srv.Confirmed(ctx, Peer{IP: c.Local()}, device, services.ServiceConfirmedCOVNotification, payload)
	if !errors.Is(err, client.ErrTimeout) || time.Since(start) < 350*time.Millisecond {
		t.Errorf("unacknowledged notification: %v after %s", err, time.Since(start))
	}
	if n := len(srv.unacked); n != 0 {
		t.Errorf("%d notifications still waiting", n)
	}
}

// A request from a consumer behind a router is answered through the router,
// with the consumer's network and MAC as the destination and the virtual
// device as the source.
func TestRoutedConsumer(t *testing.T) {
	h := &canned{}
	srv, _, _ := start(t, h)
	raw := newRaw(t)
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectName))
	req.InvokeID, req.MaxSize = 3, 5
	req.SetAPDUFlags(true, false, false)
	npdu := npduTo(9000, []byte{0, 1}, 77, []byte{0x0A})
	reply := raw.exchange(t, srv.Local(), npdu, req)
	if reply == nil || reply.Type != plumbing.ComplexAck || reply.InvokeID != 3 {
		t.Fatalf("got %+v", reply)
	}
	back := raw.lastNPDU
	if back.Control&0x20 == 0 || back.DNET != 77 || string(back.DADR) != "\x0A" {
		t.Errorf("the reply's destination is %+v, want network 77 MAC 0a", back)
	}
	if back.Control&0x08 == 0 || back.SNET != 9000 || string(back.SADR) != "\x00\x01" {
		t.Errorf("the reply's source is %+v, want network 9000 MAC 0001", back)
	}
	if raw.lastFrom != srv.Local() {
		t.Errorf("the reply came from %v, want the server", raw.lastFrom)
	}
}

// A retransmission of a request the handler is still answering is not
// handed to the handler again; once answered, a request with the same
// invoke ID is new; and the same invoke ID to another device is another
// request.
func TestDuplicates(t *testing.T) {
	h := &canned{delay: 300 * time.Millisecond}
	srv, _, _ := start(t, h)
	raw := newRaw(t)
	h.calls.Store(0)
	req := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectName))
	req.InvokeID, req.MaxSize = 5, 5
	req.SetAPDUFlags(true, false, false)
	npdu := npduTo(9000, []byte{0, 1}, 0, nil)
	raw.send(t, srv.Local(), npdu, req)
	raw.send(t, srv.Local(), npdu, req)
	raw.send(t, srv.Local(), npduTo(9000, []byte{0, 2}, 0, nil), req)
	time.Sleep(100 * time.Millisecond)
	if n := h.calls.Load(); n != 2 {
		t.Errorf("the handler was called %d times, want 2: once per device", n)
	}
	if reply := raw.receive(t, time.Second); reply == nil {
		t.Fatal("no reply to the first request")
	}
	raw.receive(t, 500*time.Millisecond)
	raw.send(t, srv.Local(), npdu, req)
	if reply := raw.receive(t, time.Second); reply == nil {
		t.Fatal("no reply to the request sent again after the answer")
	}
	if n := h.calls.Load(); n != 3 {
		t.Errorf("the handler was called %d times, want 3", n)
	}
}

// A segmented request is aborted, a bad tag rejected, a foreign device
// registration NAKed.
func TestRefusals(t *testing.T) {
	h := &canned{}
	srv, _, _ := start(t, h)
	raw := newRaw(t)
	npdu := npduTo(9000, []byte{0, 1}, 0, nil)
	seg := &plumbing.APDU{Type: plumbing.ConfirmedReq, Flags: 0x8, MaxSize: 5, InvokeID: 1, Service: 12, Payload: []byte{1}}
	if reply := raw.exchange(t, srv.Local(), npdu, seg); reply == nil || reply.Type != plumbing.Abort || reply.Reason != objects.AbortReasonSegmentationNotSupported {
		t.Errorf("segmented request got %+v", reply)
	}
	bad := plumbing.NewAPDU(plumbing.ConfirmedReq, 12, []objects.APDUPayload{&rawTag{[]byte{0x07}}}) // an application tag with length field 7
	bad.InvokeID, bad.MaxSize = 2, 5
	if reply := raw.exchange(t, srv.Local(), npdu, bad); reply == nil || reply.Type != plumbing.Reject || reply.Reason != objects.RejectReasonInvalidTag {
		t.Errorf("bad tag got %+v", reply)
	}
	b, _ := plumbing.NewRegisterForeignDevice(60).MarshalBinary()
	raw.conn.WriteToUDPAddrPort(b, srv.Local())
	buf := make([]byte, 64)
	raw.conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := raw.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	var result plumbing.BVLCResult
	if err := result.UnmarshalBinary(buf[:n]); err != nil || result.ResultCode != bvlcResultRegisterNAK {
		t.Errorf("registration got %x, %v, want the NAK", buf[:n], err)
	}
}

// ---- a raw sender ----------------------------------------------------------

type rawTag struct{ b []byte }

func (r *rawTag) UnmarshalBinary([]byte) error   { return nil }
func (r *rawTag) MarshalBinary() ([]byte, error) { return r.b, nil }
func (r *rawTag) MarshalTo(b []byte) error       { copy(b, r.b); return nil }
func (r *rawTag) MarshalLen() int                { return len(r.b) }

type raw struct {
	conn     *net.UDPConn
	lastNPDU plumbing.NPDU
	lastFrom netip.AddrPort
}

func newRaw(t *testing.T) *raw {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &raw{conn: conn}
}

func npduTo(dnet uint16, dadr []byte, snet uint16, sadr []byte) *plumbing.NPDU {
	npdu := plumbing.NewNPDU(false, true, snet != 0, true)
	npdu.DNET, npdu.DLEN, npdu.DADR, npdu.Hop = dnet, uint8(len(dadr)), dadr, 255
	if snet != 0 {
		npdu.SNET, npdu.SLEN, npdu.SADR = snet, uint8(len(sadr)), sadr
	}
	return npdu
}

func (r *raw) send(t *testing.T, to netip.AddrPort, npdu *plumbing.NPDU, a *plumbing.APDU) {
	t.Helper()
	bvlc := plumbing.NewBVLC(plumbing.BVLCFuncUnicast)
	b := make([]byte, bvlc.MarshalLen()+npdu.MarshalLen()+a.MarshalLen())
	bvlc.Length = uint16(len(b))
	bvlc.MarshalTo(b)
	npdu.MarshalTo(b[bvlc.MarshalLen():])
	if err := a.MarshalTo(b[bvlc.MarshalLen()+npdu.MarshalLen():]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.conn.WriteToUDPAddrPort(b, to); err != nil {
		t.Fatal(err)
	}
}

func (r *raw) receive(t *testing.T, wait time.Duration) *plumbing.APDU {
	t.Helper()
	buf := make([]byte, 2048)
	r.conn.SetReadDeadline(time.Now().Add(wait))
	n, from, err := r.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil
	}
	r.lastFrom = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	var bvlc plumbing.BVLC
	if err := bvlc.UnmarshalBinary(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if err := r.lastNPDU.UnmarshalBinary(buf[bvlc.MarshalLen():n]); err != nil {
		t.Fatal(err)
	}
	var a plumbing.APDU
	if err := a.UnmarshalBinary(buf[bvlc.MarshalLen()+r.lastNPDU.MarshalLen() : n]); err != nil {
		t.Fatal(err)
	}
	return &a
}

func (r *raw) exchange(t *testing.T, to netip.AddrPort, npdu *plumbing.NPDU, a *plumbing.APDU) *plumbing.APDU {
	t.Helper()
	r.send(t, to, npdu, a)
	return r.receive(t, time.Second)
}

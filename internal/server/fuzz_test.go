package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"
)

// frame marshals one BACnet/IP datagram.
func frame(function uint8, npdu *plumbing.NPDU, a *plumbing.APDU) []byte {
	bvlc := plumbing.NewBVLC(function)
	b := make([]byte, bvlc.MarshalLen()+npdu.MarshalLen()+a.MarshalLen())
	bvlc.Length = uint16(len(b))
	bvlc.MarshalTo(b)
	npdu.MarshalTo(b[bvlc.MarshalLen():])
	a.MarshalTo(b[bvlc.MarshalLen()+npdu.MarshalLen():])
	return b
}

// seeds is a valid datagram of each kind the server takes.
func seeds() [][]byte {
	plain := plumbing.NewNPDU(false, false, false, false)
	routed := npduTo(9000, []byte{0, 1}, 0, nil)
	viaRouter := npduTo(9000, []byte{0, 1}, 77, []byte{0x0A})
	read := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectList))
	read.InvokeID, read.MaxSize = 3, 5
	read.SetAPDUFlags(true, false, false)
	sub := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedSubscribeCOV, services.COVObjects(1, objects.ObjectTypeAnalogInput, 1, false, 60))
	sub.InvokeID, sub.MaxSize = 4, 5
	segmented := &plumbing.APDU{Type: plumbing.ConfirmedReq, Flags: 0x8, MaxSize: 5, InvokeID: 1, Service: 12, Payload: []byte{1}}
	net, _ := plumbing.NewNetworkMessage(plumbing.NewBVLC(plumbing.BVLCFuncUnicast), plumbing.NewNPDU(false, false, false, false), plumbing.NetMsgWhoIsRouterToNetwork, nil).MarshalBinary()
	reg, _ := plumbing.NewRegisterForeignDevice(60).MarshalBinary()
	return [][]byte{
		frame(plumbing.BVLCFuncUnicast, plain, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil)),
		frame(plumbing.BVLCFuncBroadcast, plain, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoHas, services.WhoHasObjects(0, 0, "DEV-canned"))),
		frame(plumbing.BVLCFuncUnicast, routed, read),
		frame(plumbing.BVLCFuncUnicast, viaRouter, sub),
		frame(plumbing.BVLCFuncUnicast, routed, segmented),
		frame(plumbing.BVLCFuncUnicast, routed, &plumbing.APDU{Type: plumbing.SegmentAck, InvokeID: 3, SequenceNumber: 0, ActualWindowSize: 2}),
		frame(plumbing.BVLCFuncUnicast, routed, &plumbing.APDU{Type: plumbing.Abort, InvokeID: 3}),
		frame(plumbing.BVLCFuncUnicast, routed, &plumbing.APDU{Type: plumbing.SimpleAck, InvokeID: 1, Service: services.ServiceConfirmedCOVNotification}),
		net, reg,
		{0x81, 0x0A, 0x00, 0x04},
		{0x81, 0x0A, 0x00, 0x08, 0x01, 0x04},
	}
}

// FuzzHandle feeds the server raw datagrams: whatever they hold, nothing
// panics on the read loop, and the handler goroutines stay under the cap.
// Run it for a while with
//
//	go test ./internal/server -run=^$ -fuzz=FuzzHandle -fuzztime=60s
func FuzzHandle(f *testing.F) {
	h := &canned{listSize: 50}
	srv, err := Open(Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: 50 * time.Millisecond, MaxRPSPerSource: -1, MaxInFlight: 16}, h)
	if err != nil {
		f.Fatal(err)
	}
	h.srv = srv
	f.Cleanup(func() { srv.Close() })
	src := netip.MustParseAddrPort("127.0.0.1:9")
	for _, s := range seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		srv.handle(src, data)
		if srv.Dropped().Panics != 0 {
			t.Fatalf("a handler panicked on %x", data)
		}
	})
}

// FuzzConfirmed targets the confirmed-request parser alone: the APDU
// bytes after the NPDU, with the tag loop and the max-APDU and segment
// fields decoded by hand.
func FuzzConfirmed(f *testing.F) {
	h := &canned{listSize: 50}
	srv, err := Open(Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: 50 * time.Millisecond, MaxRPSPerSource: -1, MaxInFlight: 16}, h)
	if err != nil {
		f.Fatal(err)
	}
	h.srv = srv
	f.Cleanup(func() { srv.Close() })
	env := Envelope{Peer: Peer{IP: netip.MustParseAddrPort("127.0.0.1:9")}, HasDest: true, DNET: 9000, DADR: []byte{0, 1}}
	read := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, 4242, objects.PropertyIdObjectName))
	read.InvokeID, read.MaxSize = 3, 5
	read.SetAPDUFlags(true, false, false)
	b := make([]byte, read.MarshalLen())
	read.MarshalTo(b)
	f.Add(b)
	f.Add([]byte{0x00, 0x05, 0x01, 0x0C})
	f.Add([]byte{0x02, 0x75, 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x10, 0x92, 0x19, 0x4D})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0]>>4 != plumbing.ConfirmedReq {
			data = append([]byte{byte(plumbing.ConfirmedReq) << 4}, data...)
		}
		srv.confirmed(env, data)
	})
}

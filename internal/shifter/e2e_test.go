package shifter_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/client/sim"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
	"github.com/jonalfarlinga/bacnet-shifter/internal/translate"
)

// The default sim: seven devices.
const simDevices = 7

func deviceObject(instance uint32) client.ObjectID {
	return client.ObjectID{Type: objects.ObjectTypeDevice, Instance: instance}
}

// realOf maps a device the consumer heard to its table record.
func realOf(t *testing.T, b *harness.Bench, dev client.Device) table.Device {
	t.Helper()
	d, ok := b.Shifter.Table().ByVirtual(dev.Instance)
	if !ok {
		t.Fatalf("virtual device %d is not in the table", dev.Instance)
	}
	return d
}

// ---- test 2 and test 1: fidelity, then the leak check ----------------------

// The properties the sim's objects have, read from every object.
var allProps = []uint16{
	objects.PropertyIdObjectIdentifier, objects.PropertyIdObjectName, objects.PropertyIdObjectType, objects.PropertyIdDescription,
	objects.PropertyIdPresentValue, objects.PropertyIdStatusFlags, objects.PropertyIdEventState, objects.PropertyIdReliability,
	objects.PropertyIdOutOfService, objects.PropertyIdUnits, objects.PropertyIdPriorityArray, objects.PropertyIdRelinquishDefault,
	objects.PropertyIdPolarity, objects.PropertyIdInactiveText, objects.PropertyIdActiveText, objects.PropertyIdNumberOfStates,
	objects.PropertyIdStateText, objects.PropertyIdRecordCount, objects.PropertyIdTotalRecordCount, objects.PropertyIdBufferSize,
	objects.PropertyIdLogInterval, objects.PropertyIdSystemStatus, objects.PropertyIdVendorName, objects.PropertyIdVendorIdentifier,
	objects.PropertyIdModelName, objects.PropertyIdFirmwareRevision, objects.PropertyIdApplicationSoftwareVersion,
	objects.PropertyIdLocation, objects.PropertyIdProtocolVersion, objects.PropertyIdProtocolRevision,
	objects.PropertyIdProtocolServicesSupported, objects.PropertyIdProtocolObjectTypesSupported,
	objects.PropertyIdMaxApduLengthAccepted, objects.PropertyIdSegmentationSupported, objects.PropertyIdObjectList,
}

// A few properties for the devices with hundreds of objects.
var fewProps = []uint16{objects.PropertyIdObjectName, objects.PropertyIdPresentValue, objects.PropertyIdUnits, objects.PropertyIdDescription}

// passes reports whether a property's strings cross as they are: outside
// the strict profile, the three version strings and nothing else.
func passes(prop uint16) bool { return control.Passes(uint32(prop), nil, false) }

// secrets collects what must never appear on the consumer socket: every
// character string the site returned, as the BACnet encoding of it (tag,
// length, character set, bytes), so that a short string such as "On" is
// not found by chance in a number; and the byte sequences of the site's
// identifiers and addresses.
type secrets struct {
	strings map[string][]byte
	bytes   [][]byte
}

func (s *secrets) addString(str string) {
	if str == "" {
		return
	}
	if s.strings == nil {
		s.strings = map[string][]byte{}
	}
	if _, ok := s.strings[str]; ok {
		return
	}
	b, err := objects.EncString(str).MarshalBinary()
	if err != nil {
		panic(err)
	}
	s.strings[str] = b
}

func TestFidelityAndLeak(t *testing.T) {
	stations := sim.Default()
	stations[3][0].NoWildcard = true // the legacy panel is read by its own instance only
	b := harness.Start(t, harness.Options{Stations: stations})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	direct, realDevices := b.Direct()
	if len(realDevices) != simDevices {
		t.Fatalf("the direct client heard %d devices, want %d", len(realDevices), simDevices)
	}
	ctx := b.Ctx()
	tb := b.Shifter.Table()
	var leak secrets

	// Every sim device is on a virtual network, at a two-byte MAC, with a
	// virtual instance that maps back to its real one.
	for virtual, dev := range heard {
		rec := realOf(t, b, dev)
		if dev.Addr.Net == 0 || len(dev.Addr.MAC) != 2 || dev.Addr.IP != b.Shifter.ConsumerAddr() {
			t.Errorf("virtual device %d is at %v, want a routed address through the shifter", virtual, dev.Addr)
		}
		real, ok := realDevices[rec.Instance]
		if !ok {
			t.Fatalf("virtual device %d maps to %d, which the direct client did not hear", virtual, rec.Instance)
		}
		if dev.VendorID != real.VendorID || dev.MaxAPDU != real.MaxAPDU {
			t.Errorf("device %d announces vendor %d APDU %d, real %d %d", virtual, dev.VendorID, dev.MaxAPDU, real.VendorID, real.MaxAPDU)
		}
		leak.bytes = append(leak.bytes, encodedDeviceID(rec.Instance))
		if real.Addr.Net != 0 {
			// The real network and MAC as an NPDU carries them.
			leak.bytes = append(leak.bytes, append([]byte{byte(real.Addr.Net >> 8), byte(real.Addr.Net), byte(len(real.Addr.MAC))}, real.Addr.MAC...))
		}
	}
	for _, addr := range b.Sim.Addrs() {
		ip := addr.Addr().As4()
		leak.bytes = append(leak.bytes, append(ip[:], byte(addr.Port()>>8), byte(addr.Port())))
	}

	rules := translate.Rules{
		Device: func(real uint32) (uint32, bool) { d, ok := tb.Device(real); return d.Virtual, ok },
		Known:  tb.Known,
	}

	for virtual, dev := range heard {
		rec := realOf(t, b, dev)
		real := realDevices[rec.Instance]

		// The object list, read as the client reads it: whole, or element
		// by element where the device cannot segment.
		directList, err := direct.ReadObjectList(ctx, real, nil)
		if err != nil {
			t.Fatalf("device %d: direct object list: %v", rec.Instance, err)
		}
		viaList, err := b.Consumer.ReadObjectList(ctx, dev, nil)
		if err != nil {
			t.Fatalf("device %d: object list through the shifter: %v", rec.Instance, err)
		}
		if len(viaList) != len(directList) {
			t.Fatalf("device %d: %d objects through the shifter, %d direct", rec.Instance, len(viaList), len(directList))
		}
		for i := range directList {
			want := directList[i]
			if want.Type == objects.ObjectTypeDevice {
				want.Instance = virtual
			}
			if viaList[i] != want {
				t.Errorf("device %d: object %d is %v through the shifter, want %v", rec.Instance, i, viaList[i], want)
			}
		}

		props := allProps
		if len(directList) > 100 {
			props = fewProps
		}
		var directSpecs, viaSpecs []client.ReadSpec
		for i, obj := range directList {
			directSpecs = append(directSpecs, client.ReadSpec{Object: obj, Props: props})
			viaSpecs = append(viaSpecs, client.ReadSpec{Object: viaList[i], Props: props})
		}
		directResults, err := direct.ReadMany(ctx, real, directSpecs)
		if err != nil {
			t.Fatalf("device %d: direct ReadMany: %v", rec.Instance, err)
		}
		viaResults, err := b.Consumer.ReadMany(ctx, dev, viaSpecs)
		if err != nil {
			t.Fatalf("device %d: ReadMany through the shifter: %v", rec.Instance, err)
		}
		for i := range directResults {
			compareObject(t, rec, rules, directResults[i], viaResults[i], &leak)
		}
	}

	// The sim's errors come through with the same class, code or reason.
	for virtual, dev := range heard {
		rec := realOf(t, b, dev)
		real := realDevices[rec.Instance]
		cases := []struct {
			name string
			obj  client.ObjectID
			prop uint16
		}{
			{"unknown object", client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 9999}, objects.PropertyIdPresentValue},
			{"unknown property", client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 0}, 9999},
			{"wildcard", deviceObject(client.WildcardInstance), objects.PropertyIdObjectIdentifier},
		}
		for _, tc := range cases {
			dObj, vObj := tc.obj, tc.obj
			if tc.obj.Type == objects.ObjectTypeDevice && tc.obj.Instance == 0 {
				dObj.Instance, vObj.Instance = rec.Instance, virtual
			}
			_, dErr := direct.ReadProperty(ctx, real.Addr, dObj, tc.prop)
			vValues, vErr := b.Consumer.ReadProperty(ctx, dev.Addr, vObj, tc.prop)
			if !sameOutcome(dErr, vErr) {
				t.Errorf("device %d, %s: direct %v, through the shifter %v", rec.Instance, tc.name, dErr, vErr)
			}
			if tc.name == "wildcard" && vErr == nil {
				if len(vValues) != 1 || vValues[0].Kind != client.KindObjectID || vValues[0].Object.Instance != virtual {
					t.Errorf("device %d: the wildcard read gave %+v, want device %d", rec.Instance, vValues, virtual)
				}
			}
		}
		_, dErr := direct.ReadPropertyMultiple(ctx, real.Addr, []client.ReadSpec{{Object: deviceObject(rec.Instance), Props: []uint16{objects.PropertyIdObjectName}}})
		_, vErr := b.Consumer.ReadPropertyMultiple(ctx, dev.Addr, []client.ReadSpec{{Object: deviceObject(virtual), Props: []uint16{objects.PropertyIdObjectName}}})
		if !sameOutcome(dErr, vErr) {
			t.Errorf("device %d: ReadPropertyMultiple direct %v, through the shifter %v", rec.Instance, dErr, vErr)
		}
		if rec.Instance == 4000 && dErr == nil {
			t.Error("the NoRPM device answered a ReadPropertyMultiple")
		}
	}

	// Trend logs read with ReadRange equal the direct read.
	ahu := realDevices[1001]
	vAHU := heard[realOf(t, b, heard[mustVirtual(t, tb, 1001)]).Virtual]
	for _, rng := range []client.Range{{}, client.ByPosition(1, 10), client.ByPosition(48, -5), client.BySequence(20, 3)} {
		req := client.ReadRangeRequest{Object: client.ObjectID{Type: objects.ObjectTypeTrendLog, Instance: 0}, Property: objects.PropertyIdLogBuffer, Range: rng}
		dRes, dErr := direct.ReadRange(ctx, ahu.Addr, req)
		vRes, vErr := b.Consumer.ReadRange(ctx, vAHU.Addr, req)
		if !sameOutcome(dErr, vErr) {
			t.Fatalf("ReadRange %+v: direct %v, through the shifter %v", rng, dErr, vErr)
		}
		if dErr != nil {
			continue
		}
		if dRes.ItemCount != vRes.ItemCount || dRes.FirstItem != vRes.FirstItem || dRes.LastItem != vRes.LastItem || len(dRes.Items) != len(vRes.Items) {
			t.Errorf("ReadRange %+v: direct %+v, through the shifter %+v", rng, dRes, vRes)
		}
		if (dRes.FirstSequence == nil) != (vRes.FirstSequence == nil) || (dRes.FirstSequence != nil && *dRes.FirstSequence != *vRes.FirstSequence) {
			t.Errorf("ReadRange %+v: first sequence differs", rng)
		}
		dRecs, vRecs := dRes.LogRecords(), vRes.LogRecords()
		for i := range dRecs {
			if i < len(vRecs) && (!dRecs[i].At.Equal(vRecs[i].At) || dRecs[i].Datum.Float != vRecs[i].Datum.Float) {
				t.Errorf("ReadRange %+v: record %d is %+v, want %+v", rng, i, vRecs[i], dRecs[i])
			}
		}
	}

	// Test 1: nothing identifying crossed the consumer socket.
	for _, s := range []string{"AHU-1", "AHU1.SAT", "CHW-PLANT", "VAV-2-01", "METER-GW", "BOILER-1", "Loopback", "SIM-AHU", "Air handler"} {
		leak.addString(s)
	}
	checkLeak(t, b.ServerRec.Events(), leak)
}

func mustVirtual(t *testing.T, tb *table.Table, real uint32) uint32 {
	t.Helper()
	d, ok := tb.Device(real)
	if !ok {
		t.Fatalf("device %d is not in the table", real)
	}
	return d.Virtual
}

func encodedDeviceID(instance uint32) []byte {
	v := uint32(objects.ObjectTypeDevice)<<22 | instance
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// sameOutcome reports whether two reads failed the same way, or both
// succeeded.
func sameOutcome(a, b error) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	var ba, bb *client.BACnetError
	if errors.As(a, &ba) && errors.As(b, &bb) {
		return ba.Class == bb.Class && ba.Code == bb.Code
	}
	var ra, rb *client.RejectError
	if errors.As(a, &ra) && errors.As(b, &rb) {
		return ra.Reason == rb.Reason
	}
	var aa, ab *client.AbortError
	if errors.As(a, &aa) && errors.As(b, &ab) {
		return aa.Reason == ab.Reason
	}
	return errors.Is(a, client.ErrTimeout) && errors.Is(b, client.ErrTimeout)
}

// compareObject checks one object's properties through the shifter against
// the direct read after translation, and collects the real strings for the
// leak check.
func compareObject(t *testing.T, rec table.Device, rules translate.Rules, direct, via client.ObjectResult, leak *secrets) {
	t.Helper()
	wantObj := direct.Object
	if wantObj.Type == objects.ObjectTypeDevice {
		wantObj.Instance = rec.Virtual
	}
	if via.Object != wantObj {
		t.Errorf("device %d: object %v came back as %v", rec.Instance, direct.Object, via.Object)
		return
	}
	if len(via.Props) != len(direct.Props) {
		t.Errorf("device %d, object %v: %d properties through the shifter, %d direct", rec.Instance, direct.Object, len(via.Props), len(direct.Props))
		return
	}
	for i, dp := range direct.Props {
		vp := via.Props[i]
		where := fmt.Sprintf("device %d, object %v, %s", rec.Instance, direct.Object, control.PropertyName(dp.ID))
		if dp.ID != vp.ID || !sameOutcome(dp.Err, vp.Err) {
			t.Errorf("%s: direct %d %v, through the shifter %d %v", where, dp.ID, dp.Err, vp.ID, vp.Err)
			continue
		}
		if dp.Err != nil {
			continue
		}
		prop := uint16(dp.ID)
		if prop == objects.PropertyIdLocalTime || prop == objects.PropertyIdLocalDate {
			continue // the clock moves between the two reads
		}
		want := rules.Values(dp.Values)
		if !passes(prop) {
			// Every string is a secret, and must have come back as a
			// pseudonym; the rest of the value is compared as it is.
			collectStrings(dp.Values, leak)
			want = expectReplaced(t, where, want, vp.Values)
		}
		if !equalValues(want, vp.Values) {
			t.Errorf("%s: through the shifter %+v, want %+v", where, vp.Values, want)
		}
	}
}

// collectStrings adds every string among the values, at any depth, to the
// secrets.
func collectStrings(values []client.Value, leak *secrets) {
	for _, v := range values {
		switch v.Kind {
		case client.KindString:
			leak.addString(v.Str)
		case client.KindConstructed:
			collectStrings(v.Items, leak)
		}
	}
}

// expectReplaced checks that every string among want came back in got as
// a pseudonym, neither the real string nor empty, and returns want with
// the pseudonyms in place, so that the rest of the value compares as it
// is.
func expectReplaced(t *testing.T, where string, want, got []client.Value) []client.Value {
	t.Helper()
	out := make([]client.Value, len(want))
	copy(out, want)
	for j, v := range out {
		switch v.Kind {
		case client.KindString:
			if v.Str == "" {
				continue
			}
			if j >= len(got) || got[j].Kind != client.KindString || got[j].Str == v.Str || got[j].Str == "" {
				t.Errorf("%s: %q was not replaced: %+v", where, v.Str, got)
				continue
			}
			out[j].Str = got[j].Str
		case client.KindConstructed:
			if j < len(got) && got[j].Kind == client.KindConstructed {
				out[j].Items = expectReplaced(t, where, v.Items, got[j].Items)
			}
		}
	}
	return out
}

// equalValues compares values, with a tolerance for the reals the sim
// drifts between two reads.
func equalValues(a, b []client.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Kind != y.Kind || x.Tag != y.Tag || x.Bool != y.Bool || x.Uint != y.Uint || x.Int != y.Int ||
			x.Str != y.Str || !bytes.Equal(x.Bytes, y.Bytes) || x.Object != y.Object || len(x.Bits) != len(y.Bits) {
			return false
		}
		for j := range x.Bits {
			if x.Bits[j] != y.Bits[j] {
				return false
			}
		}
		if math.Abs(x.Float-y.Float) > math.Max(1, 1e-3*math.Abs(x.Float)) {
			return false
		}
		if !equalValues(x.Items, y.Items) {
			return false
		}
	}
	return true
}

// checkLeak asserts that none of the secrets is in any datagram.
func checkLeak(t *testing.T, events []client.PacketEvent, leak secrets) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("nothing was recorded on the consumer socket")
	}
	found := map[string]bool{}
	for _, e := range events {
		for str, enc := range leak.strings {
			if bytes.Contains(e.Data, enc) {
				found[fmt.Sprintf("string %q", str)] = true
			}
		}
		for _, s := range leak.bytes {
			if bytes.Contains(e.Data, s) {
				found[fmt.Sprintf("bytes %x", s)] = true
			}
		}
	}
	var list []string
	for k := range found {
		list = append(list, k)
	}
	sort.Strings(list)
	for _, k := range list {
		t.Errorf("leaked on the consumer socket: %s", k)
	}
	t.Logf("leak check: %d datagrams, %d strings, %d byte sequences", len(events), len(leak.strings), len(leak.bytes))
}

// ---- test 3: the guard at no-write -----------------------------------------

// Every confirmed service code gets its documented answer, every
// unconfirmed one but Who-Is gets nothing, and the site sees only the
// level's list.
func TestGuardNoWrite(t *testing.T) { guardAt(t, control.NoWrite) }

func TestGuardLimited(t *testing.T) { guardAt(t, control.Limited) }

func TestGuardFullService(t *testing.T) { guardAt(t, control.FullService) }

// What each level sends to the site, in the names sentSet gives.
var levelList = map[control.Level][]string{
	control.NoWrite: {
		"unconfirmed who-is", "confirmed read-property", "confirmed read-property-multiple",
		"confirmed read-range", "segment-ack", "abort", "network who-is-router-to-network",
		"bvlc register-foreign-device", "bvlc read-foreign-device-table", "bvlc read-broadcast-distribution-table",
	},
	control.Limited:     {"confirmed subscribe-cov", "simple-ack confirmed-cov-notification"},
	control.FullService: {"confirmed write-property"},
}

func guardAt(t *testing.T, level control.Level) {
	guardBody(t, harness.Start(t, harness.Options{Control: level}), level)
}

// The guard test again, per peer level: the global level is full-service
// and the test's consumers, all on loopback, get the level from a
// consumer.peers entry. The dispatch holds them to it, and the site sees
// only that level's list.
func TestGuardPerPeer(t *testing.T) {
	for _, level := range []control.Level{control.NoWrite, control.Limited} {
		t.Run(level.String(), func(t *testing.T) {
			b := harness.Start(t, harness.Options{Control: control.FullService, Configure: func(cfg *shifter.Config) {
				cfg.Peers = []shifter.Peer{{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Control: level}}
			}})
			guardBody(t, b, level)
		})
	}
}

func guardBody(t *testing.T, b *harness.Bench, level control.Level) {
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	var dev client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 1001 {
			dev = d
		}
	}
	raw := harness.NewRaw(t)
	to := b.Shifter.ConsumerAddr()
	npdu := func() *plumbing.NPDU { return harness.NPDUTo(dev.Addr.Net, dev.Addr.MAC, 0, nil, true) }

	for service := 0; service < 256; service++ {
		req := plumbing.NewAPDU(plumbing.ConfirmedReq, uint8(service), nil)
		req.InvokeID, req.MaxSize = uint8(service), 5
		req.SetAPDUFlags(true, false, false)
		got := raw.Exchange(t, to, npdu(), req, time.Second)
		if got == nil || got.APDU == nil {
			t.Errorf("confirmed service %d: no answer", service)
			continue
		}
		a := got.APDU
		switch {
		case level.Forwards(uint8(service)):
			// A forwarded service with no parameters is rejected before
			// anything is sent.
			if a.Type != plumbing.Reject || a.Reason != objects.RejectReasonMissingRequiredParameter {
				t.Errorf("service %d with no parameters: %+v, want Reject missing-required-parameter", service, a)
			}
		case !control.Known(uint8(service)):
			if a.Type != plumbing.Reject || a.Reason != objects.RejectReasonUnrecognizedService {
				t.Errorf("unknown service %d: %+v, want Reject unrecognized-service", service, a)
			}
		default:
			if a.Type != plumbing.Error || len(a.Objects) != 2 {
				t.Errorf("service %d: %+v, want an Error", service, a)
				continue
			}
			class, _ := objects.DecEnumerated(a.Objects[0])
			code, _ := objects.DecEnumerated(a.Objects[1])
			if class != uint32(objects.ErrorClassServices) || code != uint32(objects.ErrorCodeServiceRequestDenied) {
				t.Errorf("service %d: Error %d %d, want services, service-request-denied", service, class, code)
			}
		}
		if a.InvokeID != uint8(service) || got.NPDU.Control&0x08 == 0 || got.NPDU.SNET != dev.Addr.Net {
			t.Errorf("service %d: the answer has invoke %d from network %d", service, a.InvokeID, got.NPDU.SNET)
		}
	}
	// Every unconfirmed service but Who-Is gets nothing: all of them at
	// once, then a wait for anything at all.
	raw.Drain(t)
	for service := 0; service < 256; service++ {
		if service == int(services.ServiceUnconfirmedWhoIs) {
			continue
		}
		raw.Send(t, to, npdu(), plumbing.NewAPDU(plumbing.UnConfirmedReq, uint8(service), nil))
	}
	if got := raw.Receive(t, 300*time.Millisecond); got != nil {
		t.Errorf("an unconfirmed service got an answer: %+v", got.APDU)
	}
	if got := raw.Exchange(t, to, npdu(), plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil), time.Second); got == nil || got.APDU == nil || got.APDU.Service != services.ServiceUnconfirmedIAm {
		t.Errorf("Who-Is got %+v, want an I-Am", got)
	}

	// The consumer's reads still succeed, with each of the three services.
	if _, err := b.Consumer.ReadProperty(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectName); err != nil {
		t.Errorf("ReadProperty after the flood: %v", err)
	}
	if _, err := b.Consumer.ReadPropertyMultiple(ctx, dev.Addr, []client.ReadSpec{{Object: deviceObject(dev.Instance), Props: []uint16{objects.PropertyIdObjectName}}}); err != nil {
		t.Errorf("ReadPropertyMultiple after the flood: %v", err)
	}
	if _, err := b.Consumer.ReadRange(ctx, dev.Addr, client.ReadRangeRequest{Object: client.ObjectID{Type: objects.ObjectTypeTrendLog}, Property: objects.PropertyIdLogBuffer, Range: client.ByPosition(1, 2)}); err != nil {
		t.Errorf("ReadRange after the flood: %v", err)
	}

	must := []string{"unconfirmed who-is", "confirmed read-property", "confirmed read-property-multiple", "confirmed read-range"}
	if level >= control.Limited {
		// A confirmed subscription, and a notification the shifter
		// acknowledges upstream.
		sub, err := b.Consumer.SubscribeCOV(ctx, dev.Addr, client.ObjectID{Type: objects.ObjectTypeAnalogInput}, client.COVOptions{Confirmed: true}, func(client.COVNotification) {})
		if err != nil {
			t.Fatalf("SubscribeCOV at %s: %v", level, err)
		}
		b.Sim.NotifyCOV(1001, objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogInput})
		time.Sleep(200 * time.Millisecond)
		if err := sub.Cancel(ctx); err != nil {
			t.Errorf("Cancel at %s: %v", level, err)
		}
		must = append(must, "confirmed subscribe-cov", "simple-ack confirmed-cov-notification")
	}
	if level >= control.FullService {
		// A write the rules let through reaches the sim once, at 13, and
		// the consumer gets the SimpleACK.
		raw.Drain(t)
		setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
		got := raw.Exchange(t, to, npdu(), writeAPDU(200, setpoint, objects.PropertyIdPresentValue, nil, []objects.APDUPayload{objects.EncReal(56)}, nil), 2*time.Second)
		if got == nil || got.APDU == nil || got.APDU.Type != plumbing.SimpleAck {
			t.Errorf("a write at %s got %s, want SimpleACK", level, answer(got))
		}
		if writes := b.Sim.Writes(); len(writes) != 1 || writes[0].Priority != 13 || writes[0].Device != 1001 {
			t.Errorf("the sim took %+v, want one write at 13 to device 1001", writes)
		}
		must = append(must, "confirmed write-property")
	}

	// What reached the site is exactly the level's list, and the services
	// the consumer used.
	sent := sentSet(t, b.SiteRec.Sent())
	allowed := map[string]bool{}
	for l := control.NoWrite; l <= level; l++ {
		for _, name := range levelList[l] {
			allowed[name] = true
		}
	}
	for s := range sent {
		if !allowed[s] {
			t.Errorf("the site received %s, which %s does not send", s, level)
		}
	}
	for _, m := range must {
		if !sent[m] {
			t.Errorf("the site never received %s", m)
		}
	}
}

// sentSet names the kinds of message in a list of datagrams.
func sentSet(t *testing.T, datagrams [][]byte) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, d := range datagrams {
		var bvlc plumbing.BVLC
		if err := bvlc.UnmarshalBinary(d); err != nil {
			t.Fatal(err)
		}
		switch bvlc.Function {
		case plumbing.BVLCFuncUnicast, plumbing.BVLCFuncBroadcast, plumbing.BVLCFuncDistributeBroadcastToNetwork:
		case 0x05:
			set["bvlc register-foreign-device"] = true
			continue
		case 0x02:
			set["bvlc read-broadcast-distribution-table"] = true
			continue
		case 0x06:
			set["bvlc read-foreign-device-table"] = true
			continue
		default:
			set[fmt.Sprintf("bvlc %#x", bvlc.Function)] = true
			continue
		}
		var npdu plumbing.NPDU
		if err := npdu.UnmarshalBinary(d[bvlc.MarshalLen():]); err != nil {
			t.Fatal(err)
		}
		if npdu.Control&plumbing.NetworkLayerMessage != 0 {
			var m plumbing.NetworkMessage
			if err := m.UnmarshalBinary(d); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("network %#x", m.Type)
			if m.Type == plumbing.NetMsgWhoIsRouterToNetwork {
				name = "network who-is-router-to-network"
			}
			set[name] = true
			continue
		}
		var a plumbing.APDU
		if err := a.UnmarshalBinary(d[bvlc.MarshalLen()+npdu.MarshalLen():]); err != nil {
			t.Fatal(err)
		}
		switch a.Type {
		case plumbing.ConfirmedReq:
			set["confirmed "+control.ServiceName(a.Service)] = true
		case plumbing.UnConfirmedReq:
			set["unconfirmed "+control.UnconfirmedServiceName(a.Service)] = true
		case plumbing.SegmentAck:
			set["segment-ack"] = true
		case plumbing.Abort:
			if a.Flags&0x1 == 0 {
				set["abort"] = true
			} else {
				set["server abort"] = true
			}
		case plumbing.SimpleAck:
			set["simple-ack "+control.ServiceName(a.Service)] = true
		default:
			set[fmt.Sprintf("pdu type %d service %d", a.Type, a.Service)] = true
		}
	}
	return set
}

// ---- test 5: stability -----------------------------------------------------

type snapshot struct {
	virtual map[uint32]uint32 // real instance to virtual
	mac     map[uint32]uint16
	net     map[uint32]uint16
	name    map[uint32]string // the device's name pseudonym
}

func snap(t *testing.T, b *harness.Bench) snapshot {
	t.Helper()
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	s := snapshot{virtual: map[uint32]uint32{}, mac: map[uint32]uint16{}, net: map[uint32]uint16{}, name: map[uint32]string{}}
	for _, dev := range heard {
		rec := realOf(t, b, dev)
		s.virtual[rec.Instance] = rec.Virtual
		s.mac[rec.Instance] = rec.MAC
		s.net[rec.Instance] = dev.Addr.Net
		values, err := b.Consumer.ReadProperty(b.Ctx(), dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectName)
		if err != nil || len(values) != 1 {
			t.Fatalf("device %d: name: %+v, %v", rec.Instance, values, err)
		}
		s.name[rec.Instance] = values[0].Str
	}
	return s
}

func TestStability(t *testing.T) {
	dir := t.TempDir()
	first := snap(t, harness.Start(t, harness.Options{DataDir: dir}))
	if len(first.virtual) != simDevices {
		t.Fatalf("%d devices in the first run", len(first.virtual))
	}

	// The same data directory, the site seen in another order.
	stations := sim.Default()
	for i, j := 0, len(stations)-1; i < j; i, j = i+1, j-1 {
		stations[i], stations[j] = stations[j], stations[i]
	}
	again := snap(t, harness.Start(t, harness.Options{DataDir: dir, Stations: stations}))
	for real := range first.virtual {
		if again.virtual[real] != first.virtual[real] || again.mac[real] != first.mac[real] || again.net[real] != first.net[real] || again.name[real] != first.name[real] {
			t.Errorf("device %d changed on restart: %d %04x %d %s, was %d %04x %d %s", real,
				again.virtual[real], again.mac[real], again.net[real], again.name[real],
				first.virtual[real], first.mac[real], first.net[real], first.name[real])
		}
	}

	// A different key changes everything.
	other := snap(t, harness.Start(t, harness.Options{}))
	for real := range first.virtual {
		if other.virtual[real] == first.virtual[real] || other.mac[real] == first.mac[real] || other.name[real] == first.name[real] {
			t.Errorf("device %d kept a pseudonym under another key: %d %04x %s", real, other.virtual[real], other.mac[real], other.name[real])
		}
		if first.net[real] != 9000 && other.net[real] == first.net[real] {
			t.Errorf("device %d kept its virtual network %d under another key", real, first.net[real])
		}
	}
}

// ---- test 7: routed and BBMD-reached site devices -------------------------

func TestRemoteSite(t *testing.T) {
	b := harness.Start(t, harness.Options{Stations: sim.RemoteSite(false), ForeignDevice: true})
	heard := b.AwaitDevices(5, 15*time.Second)
	ctx := b.Ctx()
	onV, routed := map[uint32]bool{}, map[uint32]uint16{}
	for _, dev := range heard {
		rec := realOf(t, b, dev)
		if dev.Addr.Net == 9000 {
			onV[rec.Instance] = true
		} else {
			routed[rec.Instance] = dev.Addr.Net
		}
		if _, err := b.Consumer.ReadProperty(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectName); err != nil {
			t.Errorf("device %d: read through the shifter: %v", rec.Instance, err)
		}
	}
	for _, want := range []uint32{5000, 1001, 2000} {
		if !onV[want] {
			t.Errorf("device %d is not on V: on V %v, routed %v", want, onV, routed)
		}
	}
	if routed[2101] == 0 || routed[2101] != routed[2102] {
		t.Errorf("the terminal units are on networks %v, want one virtual network of their own", routed)
	}
	routers, err := b.Consumer.WhoIsRouterToNetwork(ctx, nil)
	if err != nil || len(routers) != 1 || routers[0].Router != b.Shifter.ConsumerAddr() {
		t.Fatalf("routers %+v, %v; want the shifter alone", routers, err)
	}
	if nets := routers[0].Networks; len(nets) != 2 || nets[0] != min(9000, routed[2101]) || nets[1] != max(9000, routed[2101]) {
		t.Errorf("the shifter routes to %v, want 9000 and %d", nets, routed[2101])
	}
	dnet := routed[2101]
	if routers, err := b.Consumer.WhoIsRouterToNetwork(ctx, &dnet); err != nil || len(routers) != 1 {
		t.Errorf("asking for %d gave %+v, %v", dnet, routers, err)
	}
	dnet = 2001
	if routers, err := b.Consumer.WhoIsRouterToNetwork(ctx, &dnet); err != nil || len(routers) != 0 {
		t.Errorf("asking for the real network 2001 gave %+v, %v; want nobody", routers, err)
	}

	// The real network number appears in no NPDU on the consumer socket.
	for _, e := range b.ServerRec.Events() {
		var bvlc plumbing.BVLC
		if bvlc.UnmarshalBinary(e.Data) != nil {
			continue
		}
		var npdu plumbing.NPDU
		if npdu.UnmarshalBinary(e.Data[bvlc.MarshalLen():]) != nil {
			continue
		}
		if (npdu.Control&0x20 != 0 && npdu.DNET == 2001) || (npdu.Control&0x08 != 0 && npdu.SNET == 2001) {
			t.Errorf("network 2001 in an NPDU on the consumer socket: %x", e.Data)
		}
	}
	leak := secrets{bytes: [][]byte{{0x07, 0xD1, 0x01, 0x05}, {0x07, 0xD1, 0x01, 0x06}}}
	leak.addString("BBMD-1")
	leak.addString("VAV-2-01")
	checkLeak(t, b.ServerRec.Events(), leak)
}

// ---- Who-Has and the refusals ----------------------------------------------

func TestWhoHasAndRefusals(t *testing.T) {
	b := harness.Start(t, harness.Options{})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	var ahu client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 1001 {
			ahu = d
		}
	}
	// Reading the names puts them in the table.
	name, err := b.Consumer.ReadProperty(ctx, ahu.Addr, deviceObject(ahu.Instance), objects.PropertyIdObjectName)
	if err != nil {
		t.Fatal(err)
	}
	sat := client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 0}
	satName, err := b.Consumer.ReadProperty(ctx, ahu.Addr, sat, objects.PropertyIdObjectName)
	if err != nil {
		t.Fatal(err)
	}
	raw := harness.NewRaw(t)
	to := b.Shifter.ConsumerAddr()
	global := plumbing.NewNPDU(false, true, false, false)
	global.DNET, global.Hop = 0xFFFF, 255

	for _, tc := range []struct {
		name    string
		payload []objects.APDUPayload
		object  client.ObjectID
	}{
		{"by name", services.WhoHasObjects(0, 0, satName[0].Str), sat},
		{"by identifier", services.WhoHasObjects(sat.Type, sat.Instance, ""), sat},
		{"the device by name", services.WhoHasObjects(0, 0, name[0].Str), deviceObject(ahu.Instance)},
		{"the device by identifier", services.WhoHasObjects(objects.ObjectTypeDevice, ahu.Instance, ""), deviceObject(ahu.Instance)},
	} {
		raw.Drain(t)
		got := raw.Exchange(t, to, global, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoHas, tc.payload), time.Second)
		if got == nil || got.APDU == nil || got.APDU.Service != services.ServiceUnconfirmedIHave || len(got.APDU.Objects) != 3 {
			t.Errorf("Who-Has %s: got %+v, want an I-Have", tc.name, got)
			continue
		}
		dev, _ := objects.DecObjectIdentifier(got.APDU.Objects[0])
		obj, _ := objects.DecObjectIdentifier(got.APDU.Objects[1])
		str, _ := objects.DecString(got.APDU.Objects[2])
		if dev.InstanceNumber != ahu.Instance || obj.ObjectType != tc.object.Type || obj.InstanceNumber != tc.object.Instance {
			t.Errorf("Who-Has %s: I-Have names device %d object %v, want %d %v", tc.name, dev.InstanceNumber, obj, ahu.Instance, tc.object)
		}
		if str == "AHU1.SAT" || str == "AHU-1" || str == "" {
			t.Errorf("Who-Has %s: I-Have carries %q", tc.name, str)
		}
		if got.NPDU.SNET != ahu.Addr.Net || !bytes.Equal(got.NPDU.SADR, ahu.Addr.MAC) {
			t.Errorf("Who-Has %s: the I-Have is from %d/%x", tc.name, got.NPDU.SNET, got.NPDU.SADR)
		}
	}
	raw.Drain(t)
	if got := raw.Exchange(t, to, global, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoHas, services.WhoHasObjects(0, 0, "AHU1.SAT")), 200*time.Millisecond); got != nil {
		t.Errorf("Who-Has by the real name was answered: %+v", got.APDU)
	}

	// A device identifier the shifter never issued does not exist.
	_, err = b.Consumer.ReadProperty(ctx, ahu.Addr, deviceObject(1001), objects.PropertyIdObjectName)
	var be *client.BACnetError
	if !errors.As(err, &be) || be.Class != uint32(objects.ErrorClassObject) || be.Code != client.ErrorCodeUnknownObject {
		t.Errorf("reading the real instance gave %v, want object: unknown object", err)
	}
	results, err := b.Consumer.ReadPropertyMultiple(ctx, ahu.Addr, []client.ReadSpec{
		{Object: deviceObject(1001), Props: []uint16{objects.PropertyIdObjectName}},
		{Object: sat, Props: []uint16{objects.PropertyIdObjectName}},
	})
	if err != nil || len(results) != 2 {
		t.Fatalf("ReadPropertyMultiple with a real instance: %+v, %v", results, err)
	}
	for _, r := range results {
		switch {
		case r.Object == sat:
			if len(r.Props) != 1 || r.Props[0].Err != nil {
				t.Errorf("the known object failed: %+v", r)
			}
		case r.Object == deviceObject(1001):
			if len(r.Props) != 1 || !errors.As(r.Props[0].Err, &be) || be.Code != client.ErrorCodeUnknownObject {
				t.Errorf("the real instance was answered: %+v", r)
			}
		default:
			t.Errorf("unexpected object %v", r.Object)
		}
	}

	// A ReadPropertyMultiple with an array index is rejected, reason other.
	rpm := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadPropMultiple, []objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeDevice, ahu.Instance),
		objects.EncOpeningTag(1),
		objects.ContextTag(0, objects.EncUnsignedInteger(uint(objects.PropertyIdObjectList))),
		objects.ContextTag(1, objects.EncUnsignedInteger(1)),
		objects.EncClosingTag(1),
	})
	rpm.InvokeID, rpm.MaxSize = 1, 5
	rpm.SetAPDUFlags(true, false, false)
	raw.Drain(t)
	if got := raw.Exchange(t, to, harness.NPDUTo(ahu.Addr.Net, ahu.Addr.MAC, 0, nil, true), rpm, time.Second); got == nil || got.APDU == nil || got.APDU.Type != plumbing.Reject || got.APDU.Reason != objects.RejectReasonOther {
		t.Errorf("an indexed ReadPropertyMultiple got %+v, want Reject other", got)
	}

	// A request for a network the shifter does not route to is rejected at
	// the network layer, and one for nobody gets nothing.
	_, err = b.Consumer.ReadProperty(ctx, client.Address{IP: to, Net: 1234, MAC: []byte{1}}, deviceObject(1), objects.PropertyIdObjectName)
	if !errors.Is(err, client.ErrNetworkUnreachable) {
		t.Errorf("a read to network 1234 gave %v, want the network rejected", err)
	}
	_, err = b.Consumer.ReadProperty(ctx, client.Address{IP: to, Net: ahu.Addr.Net, MAC: []byte{0xFF, 0xFF}}, deviceObject(1), objects.PropertyIdObjectName)
	if !errors.Is(err, client.ErrTimeout) {
		t.Errorf("a read to nobody gave %v, want a timeout", err)
	}
	_, err = b.Consumer.ReadProperty(ctx, client.Address{IP: to}, deviceObject(1), objects.PropertyIdObjectName)
	if !errors.Is(err, client.ErrTimeout) {
		t.Errorf("a read to the shifter itself gave %v, want a timeout", err)
	}
	// A Who-Is on one virtual network draws only its devices.
	raw.Drain(t)
	vnet := uint16(0)
	for _, d := range heard {
		if d.Addr.Net != 9000 {
			vnet = d.Addr.Net
		}
	}
	onNet := plumbing.NewNPDU(false, true, false, false)
	onNet.DNET, onNet.Hop = vnet, 255
	raw.Send(t, to, onNet, plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil))
	var iAms int
	for got := raw.Receive(t, 300*time.Millisecond); got != nil; got = raw.Receive(t, 100*time.Millisecond) {
		if got.APDU != nil && got.APDU.Service == services.ServiceUnconfirmedIAm {
			iAms++
			if got.NPDU.SNET != vnet {
				t.Errorf("an I-Am from network %d answered a Who-Is on %d", got.NPDU.SNET, vnet)
			}
		}
	}
	if iAms != 3 {
		t.Errorf("%d I-Ams on network %d, want the 3 terminal units", iAms, vnet)
	}
	_ = context.Background
}

package shifter_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
)

// ---- test 8 ---------------------------------------------------------------
//
// The priority rule and the reserved set under full-service, twice: with a
// fake in the place of the library client, where what passes reaches the
// fake at the right priority with the right value, what is refused never
// does, the consumer gets the documented answer, and the site's answers are
// injected one by one; then against the simulated site through the real
// client.

func u8(v uint8) *uint8    { return &v }
func u32(v uint32) *uint32 { return &v }

// writeAPDU builds a WriteProperty: object [0], property [1], an optional
// index [2], the value between tags 3, an optional priority [4].
func writeAPDU(invoke uint8, obj client.ObjectID, prop uint16, index *uint32, value []objects.APDUPayload, priority *uint8) *plumbing.APDU {
	payload := []objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, obj.Type, obj.Instance),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(prop))),
	}
	if index != nil {
		payload = append(payload, objects.ContextTag(2, objects.EncUnsignedInteger(uint(*index))))
	}
	payload = append(payload, objects.EncOpeningTag(3))
	payload = append(payload, value...)
	payload = append(payload, objects.EncClosingTag(3))
	if priority != nil {
		payload = append(payload, objects.ContextTag(4, objects.EncUnsignedInteger(uint(*priority))))
	}
	a := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedWriteProperty, payload)
	a.InvokeID, a.MaxSize = invoke, 5
	a.SetAPDUFlags(true, false, false)
	return a
}

// answer names a reply for a failure message.
func answer(got *harness.Received) string {
	if got == nil || got.APDU == nil {
		return "nothing"
	}
	a := got.APDU
	switch a.Type {
	case plumbing.SimpleAck:
		return "SimpleACK"
	case plumbing.Reject:
		return "Reject " + objects.RejectReasonMap[a.Reason]
	case plumbing.Error:
		class, code := errorOf(a)
		return "Error " + client.ErrorClassName(class) + " " + client.ErrorCodeName(code)
	}
	return "PDU type " + string(rune('0'+a.Type))
}

func errorOf(a *plumbing.APDU) (class, code uint32) {
	if a.Type != plumbing.Error || len(a.Objects) != 2 {
		return 0xFFFF, 0xFFFF
	}
	class, _ = objects.DecEnumerated(a.Objects[0])
	code, _ = objects.DecEnumerated(a.Objects[1])
	return class, code
}

// tagBytes marshals tags, to compare values.
func tagBytes(t *testing.T, tags []*objects.Object) []byte {
	t.Helper()
	var out []byte
	for _, tag := range tags {
		b, err := tag.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

func payloadBytes(t *testing.T, payload []objects.APDUPayload) []byte {
	t.Helper()
	tags := make([]*objects.Object, 0, len(payload))
	for _, p := range payload {
		tags = append(tags, p.(*objects.Object))
	}
	return tagBytes(t, tags)
}

func TestWriteFullService(t *testing.T) {
	fake := &harness.FakeWriter{}
	b := harness.Start(t, harness.Options{Control: control.FullService, Writer: fake})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	var ahu client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 1001 {
			ahu = d
		}
	}
	raw := harness.NewRaw(t)
	to := b.Shifter.ConsumerAddr()
	npdu := func() *plumbing.NPDU { return harness.NPDUTo(ahu.Addr.Net, ahu.Addr.MAC, 0, nil, true) }

	setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
	fanStatus := client.ObjectID{Type: objects.ObjectTypeBinaryInput, Instance: 0}
	alarms := client.ObjectID{Type: objects.ObjectTypeNotificationClass, Instance: 0}
	real := func(v float32) []objects.APDUPayload { return []objects.APDUPayload{objects.EncReal(v)} }
	null := []objects.APDUPayload{objects.EncNull()}

	type want struct {
		forwarded bool
		priority  uint8
		pdu       uint8
		class     uint32
		code      uint32
		reason    uint8
	}
	simpleACK := func(priority uint8) want { return want{forwarded: true, priority: priority, pdu: plumbing.SimpleAck} }
	writeDenied := want{pdu: plumbing.Error, class: uint32(objects.ErrorClassProperty), code: uint32(control.ErrorCodeWriteAccessDenied)}
	reject := func(reason uint8) want { return want{pdu: plumbing.Reject, reason: reason} }

	cases := []struct {
		name     string
		obj      client.ObjectID
		prop     uint16
		index    *uint32
		value    []objects.APDUPayload
		priority *uint8
		want     want
	}{
		{"no priority goes at 13", setpoint, objects.PropertyIdPresentValue, nil, real(56), nil, simpleACK(13)},
		{"16 keeps 16", setpoint, objects.PropertyIdPresentValue, nil, real(57), u8(16), simpleACK(16)},
		{"13 keeps 13", setpoint, objects.PropertyIdPresentValue, nil, real(58), u8(13), simpleACK(13)},
		{"8 is refused", setpoint, objects.PropertyIdPresentValue, nil, real(59), u8(8), writeDenied},
		{"a relinquish at 8 is refused", setpoint, objects.PropertyIdPresentValue, nil, null, u8(8), writeDenied},
		{"a relinquish with no priority goes at 13", setpoint, objects.PropertyIdPresentValue, nil, null, nil, simpleACK(13)},
		{"out-of-service is reserved", fanStatus, objects.PropertyIdOutOfService, nil, []objects.APDUPayload{objects.EncBoolean(true)}, nil, writeDenied},
		{"a notification class is reserved", alarms, objects.PropertyIdPriority, nil, []objects.APDUPayload{objects.EncUnsignedInteger(1)}, u8(16), writeDenied},
		{"object-name is replaced", setpoint, objects.PropertyIdObjectName, nil, []objects.APDUPayload{objects.EncString("AHU1.SAT.SP")}, nil, writeDenied},
		{"an array index is rejected", setpoint, objects.PropertyIdPriorityArray, u32(16), real(1), nil, reject(objects.RejectReasonOther)},
		{"priority 0 is out of range", setpoint, objects.PropertyIdPresentValue, nil, real(1), u8(0), reject(objects.RejectReasonParameterOutOfRange)},
		{"priority 17 is out of range", setpoint, objects.PropertyIdPresentValue, nil, real(1), u8(17), reject(objects.RejectReasonParameterOutOfRange)},
		{"an empty value is missing", setpoint, objects.PropertyIdPresentValue, nil, nil, nil, reject(objects.RejectReasonMissingRequiredParameter)},
	}
	for i, tc := range cases {
		raw.Drain(t)
		before := len(fake.Calls())
		got := raw.Exchange(t, to, npdu(), writeAPDU(uint8(i+1), tc.obj, tc.prop, tc.index, tc.value, tc.priority), time.Second)
		if got == nil || got.APDU == nil {
			t.Errorf("%s: no answer", tc.name)
			continue
		}
		a := got.APDU
		class, code := errorOf(a)
		if a.Type != tc.want.pdu || (a.Type == plumbing.Reject && a.Reason != tc.want.reason) ||
			(a.Type == plumbing.Error && (class != tc.want.class || code != tc.want.code)) {
			t.Errorf("%s: got %s, want pdu %d class %d code %d reason %d", tc.name, answer(got), tc.want.pdu, tc.want.class, tc.want.code, tc.want.reason)
		}
		if a.InvokeID != uint8(i+1) || got.NPDU.SNET != ahu.Addr.Net || !bytes.Equal(got.NPDU.SADR, ahu.Addr.MAC) {
			t.Errorf("%s: the answer has invoke %d from %d/%x", tc.name, a.InvokeID, got.NPDU.SNET, got.NPDU.SADR)
		}
		calls := fake.Calls()
		if !tc.want.forwarded {
			if len(calls) != before {
				t.Errorf("%s: the writer was called: %+v", tc.name, calls[before:])
			}
			continue
		}
		if len(calls) != before+1 {
			t.Errorf("%s: the writer was called %d times, want once", tc.name, len(calls)-before)
			continue
		}
		c := calls[before]
		if c.Priority != tc.want.priority || c.Object != tc.obj || c.Property != tc.prop || c.To.IP != b.Sim.Addr() {
			t.Errorf("%s: the writer got %+v, want priority %d to %v %v", tc.name, c, tc.want.priority, b.Sim.Addr(), tc.obj)
		}
		if !bytes.Equal(tagBytes(t, c.Value), payloadBytes(t, tc.value)) {
			t.Errorf("%s: the writer got the value %x, want %x", tc.name, tagBytes(t, c.Value), payloadBytes(t, tc.value))
		}
	}

	// The reserved service: refused, and the writer untouched.
	raw.Drain(t)
	before := len(fake.Calls())
	lso := plumbing.NewAPDU(plumbing.ConfirmedReq, control.ServiceConfirmedLifeSafetyOperation, []objects.APDUPayload{
		objects.ContextTag(0, objects.EncUnsignedInteger(1)), objects.ContextTag(1, objects.EncString("operator")), objects.ContextTag(2, objects.EncEnumerated(0)),
	})
	lso.InvokeID, lso.MaxSize = 100, 5
	lso.SetAPDUFlags(true, false, false)
	if got := raw.Exchange(t, to, npdu(), lso, time.Second); got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
		t.Errorf("LifeSafetyOperation: got %s, want Error service-request-denied", answer(got))
	} else if class, code := errorOf(got.APDU); class != uint32(objects.ErrorClassServices) || code != uint32(objects.ErrorCodeServiceRequestDenied) {
		t.Errorf("LifeSafetyOperation: got %s, want Error services service-request-denied", answer(got))
	}
	if len(fake.Calls()) != before {
		t.Error("LifeSafetyOperation reached the writer")
	}

	// The object and the value are translated: the device object by its
	// virtual instance, a device identifier inside the value at any depth,
	// context-tagged in the [3] of a device-object-property reference and
	// application-tagged on its own.
	raw.Drain(t)
	before = len(fake.Calls())
	reference := []objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogValue, 0),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(objects.PropertyIdPresentValue))),
		objects.EncObjectIdentifier(true, 3, objects.ObjectTypeDevice, ahu.Instance),
	}
	if got := raw.Exchange(t, to, npdu(), writeAPDU(101, deviceObject(ahu.Instance), objects.PropertyIdListOfObjectPropertyReferences, nil, reference, nil), time.Second); got == nil || got.APDU == nil || got.APDU.Type != plumbing.SimpleAck {
		t.Errorf("a write with a reference: got %s, want SimpleACK", answer(got))
	}
	calls := fake.Calls()
	if len(calls) != before+1 {
		t.Fatalf("a write with a reference: the writer was called %d times", len(calls)-before)
	}
	wantRef := []objects.APDUPayload{reference[0], reference[1], objects.EncObjectIdentifier(true, 3, objects.ObjectTypeDevice, 1001)}
	if c := calls[before]; c.Object != deviceObject(1001) || !bytes.Equal(tagBytes(t, c.Value), payloadBytes(t, wantRef)) {
		t.Errorf("a write with a reference: the writer got %v %x, want device 1001 and %x", c.Object, tagBytes(t, c.Value), payloadBytes(t, wantRef))
	}
	raw.Drain(t)
	before = len(fake.Calls())
	plain := []objects.APDUPayload{objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, ahu.Instance)}
	if got := raw.Exchange(t, to, npdu(), writeAPDU(102, setpoint, objects.PropertyIdProfileName, nil, plain, nil), time.Second); got == nil || got.APDU == nil || got.APDU.Type != plumbing.SimpleAck {
		t.Errorf("a write of a device identifier: got %s, want SimpleACK", answer(got))
	}
	calls = fake.Calls()
	wantPlain := []objects.APDUPayload{objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, 1001)}
	if len(calls) != before+1 || !bytes.Equal(tagBytes(t, calls[before].Value), payloadBytes(t, wantPlain)) {
		t.Errorf("a write of a device identifier: the writer got %+v, want %x", calls[before:], payloadBytes(t, wantPlain))
	}

	// A device the shifter never issued, as the object or inside the value.
	raw.Drain(t)
	before = len(fake.Calls())
	if got := raw.Exchange(t, to, npdu(), writeAPDU(103, deviceObject(1001), objects.PropertyIdUtcOffset, nil, []objects.APDUPayload{objects.EncSignedInteger(-300)}, nil), time.Second); got == nil || got.APDU == nil {
		t.Error("a write to the real instance: no answer")
	} else if class, code := errorOf(got.APDU); class != uint32(objects.ErrorClassObject) || code != uint32(control.ErrorCodeUnknownObject) {
		t.Errorf("a write to the real instance: got %s, want Error object unknown-object", answer(got))
	}
	stranger := []objects.APDUPayload{objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, 1001)}
	if got := raw.Exchange(t, to, npdu(), writeAPDU(104, setpoint, objects.PropertyIdProfileName, nil, stranger, nil), time.Second); got == nil || got.APDU == nil {
		t.Error("a write naming the real instance: no answer")
	} else if class, code := errorOf(got.APDU); class != uint32(objects.ErrorClassServices) || code != uint32(control.ErrorCodeOther) {
		t.Errorf("a write naming the real instance: got %s, want Error services other", answer(got))
	}
	if len(fake.Calls()) != before {
		t.Error("a write naming a device the shifter never issued reached the writer")
	}

	// What the site answers comes back as it is: an Error, and silence
	// for a timeout, with no resend. A refusal by the guard is the
	// shifter's bug and is answered service-request-denied.
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"an Error", &client.BACnetError{Class: uint32(objects.ErrorClassProperty), Code: 37}, "Error property value out of range"},
		{"a Reject", &client.RejectError{Reason: objects.RejectReasonInvalidParameterDataType}, "Reject Invalid parameter data type"},
		{"a timeout", client.ErrTimeout, "nothing"},
		{"the guard", client.ErrServiceNotAllowed, "Error services service request denied"},
	} {
		fake.SetErr(tc.err)
		raw.Drain(t)
		got := raw.Exchange(t, to, npdu(), writeAPDU(110, setpoint, objects.PropertyIdPresentValue, nil, real(60), nil), time.Second)
		if answer(got) != tc.want {
			t.Errorf("%s from the site: the consumer got %s, want %s", tc.name, answer(got), tc.want)
		}
	}
	fake.SetErr(nil)

	// Nothing reached the site socket as a write: the refusals never do,
	// and the forwarded ones went to the fake.
	if sent := sentSet(t, b.SiteRec.Sent()); sent["confirmed write-property"] {
		t.Error("a write reached the site socket")
	}
}

// countService counts the confirmed requests of one service among the
// datagrams a socket sent.
func countService(t *testing.T, datagrams [][]byte, service uint8) int {
	t.Helper()
	n := 0
	for _, d := range datagrams {
		var bvlc plumbing.BVLC
		if err := bvlc.UnmarshalBinary(d); err != nil {
			t.Fatal(err)
		}
		if bvlc.Function != plumbing.BVLCFuncUnicast && bvlc.Function != plumbing.BVLCFuncBroadcast {
			continue
		}
		var npdu plumbing.NPDU
		if err := npdu.UnmarshalBinary(d[bvlc.MarshalLen():]); err != nil {
			t.Fatal(err)
		}
		if npdu.Control&plumbing.NetworkLayerMessage != 0 {
			continue
		}
		var a plumbing.APDU
		if err := a.UnmarshalBinary(d[bvlc.MarshalLen()+npdu.MarshalLen():]); err != nil {
			t.Fatal(err)
		}
		if a.Type == plumbing.ConfirmedReq && a.Service == service {
			n++
		}
	}
	return n
}

// Through the real site client: a write with no priority reaches the sim
// at 13 and one at 16 at 16, the consumer gets the sim's SimpleACK and
// reads the value back; the refused ones never reach the sim; a device
// behind the site's router takes a write too; the sim's own refusal comes
// back as it is; and a silent site gets exactly one datagram.
func TestWriteReachesSite(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.FullService})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	var ahu, vav client.Device
	for _, d := range heard {
		switch realOf(t, b, d).Instance {
		case 1001:
			ahu = d
		case 2101:
			vav = d
		}
	}
	raw := harness.NewRaw(t)
	to := b.Shifter.ConsumerAddr()
	setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
	real := func(v float32) []objects.APDUPayload { return []objects.APDUPayload{objects.EncReal(v)} }
	exchange := func(invoke uint8, d client.Device, obj client.ObjectID, prop uint16, value []objects.APDUPayload, priority *uint8) *harness.Received {
		t.Helper()
		raw.Drain(t)
		return raw.Exchange(t, to, harness.NPDUTo(d.Addr.Net, d.Addr.MAC, 0, nil, true), writeAPDU(invoke, obj, prop, nil, value, priority), 3*time.Second)
	}

	if got := exchange(1, ahu, setpoint, objects.PropertyIdPresentValue, real(58), nil); answer(got) != "SimpleACK" {
		t.Fatalf("a write with no priority got %s", answer(got))
	}
	if got := exchange(2, ahu, setpoint, objects.PropertyIdPresentValue, real(59), u8(16)); answer(got) != "SimpleACK" {
		t.Fatalf("a write at 16 got %s", answer(got))
	}
	writes := b.Sim.Writes()
	if len(writes) != 2 || writes[0].Priority != 13 || writes[1].Priority != 16 || writes[0].Device != 1001 ||
		writes[0].Object.ObjectType != setpoint.Type || writes[0].Object.InstanceNumber != setpoint.Instance ||
		writes[0].Class != 0 || writes[1].Code != 0 {
		t.Errorf("the sim took %+v, want a write at 13 and one at 16 to AV 0 of device 1001", writes)
	}
	if values, err := b.Consumer.ReadProperty(ctx, ahu.Addr, setpoint, objects.PropertyIdPresentValue); err != nil || len(values) != 1 || values[0].Float != 58 {
		t.Errorf("the present value reads back as %+v, %v; want 58, the write at 13", values, err)
	}

	// The refused ones never reach the sim.
	for _, tc := range []struct {
		name     string
		obj      client.ObjectID
		prop     uint16
		value    []objects.APDUPayload
		priority *uint8
	}{
		{"priority 8", setpoint, objects.PropertyIdPresentValue, real(1), u8(8)},
		{"out-of-service", client.ObjectID{Type: objects.ObjectTypeBinaryInput}, objects.PropertyIdOutOfService, []objects.APDUPayload{objects.EncBoolean(true)}, nil},
		{"a notification class", client.ObjectID{Type: objects.ObjectTypeNotificationClass}, objects.PropertyIdPriority, []objects.APDUPayload{objects.EncUnsignedInteger(1)}, nil},
		{"object-name", setpoint, objects.PropertyIdObjectName, []objects.APDUPayload{objects.EncString("x")}, nil},
	} {
		if got := exchange(3, ahu, tc.obj, tc.prop, tc.value, tc.priority); got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
			t.Errorf("%s: got %s, want Error write-access-denied", tc.name, answer(got))
		}
	}
	raw.Drain(t)
	lso := plumbing.NewAPDU(plumbing.ConfirmedReq, control.ServiceConfirmedLifeSafetyOperation, []objects.APDUPayload{
		objects.ContextTag(0, objects.EncUnsignedInteger(1)), objects.ContextTag(1, objects.EncString("operator")), objects.ContextTag(2, objects.EncEnumerated(0)),
	})
	lso.InvokeID, lso.MaxSize = 4, 5
	lso.SetAPDUFlags(true, false, false)
	if got := raw.Exchange(t, to, harness.NPDUTo(ahu.Addr.Net, ahu.Addr.MAC, 0, nil, true), lso, time.Second); got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
		t.Errorf("LifeSafetyOperation: got %s, want Error service-request-denied", answer(got))
	}
	if len(b.Sim.Writes()) != 2 || len(b.Sim.Services()) != 0 {
		t.Errorf("a refused write or service reached the sim: %+v, %+v", b.Sim.Writes(), b.Sim.Services())
	}

	// A device behind the site's router takes a write as well.
	coolingSetpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
	if got := exchange(5, vav, coolingSetpoint, objects.PropertyIdPresentValue, real(75), nil); answer(got) != "SimpleACK" {
		t.Errorf("a write to the routed device got %s", answer(got))
	}
	writes = b.Sim.Writes()
	if last := writes[len(writes)-1]; len(writes) != 3 || last.Device != 2101 || last.Priority != 13 {
		t.Errorf("the sim took %+v, want a third write, to device 2101 at 13", writes)
	}

	// The sim's own refusal comes back as it is: a value of the wrong kind
	// is Error property, invalid-data-type.
	got := exchange(6, ahu, setpoint, objects.PropertyIdPresentValue, []objects.APDUPayload{objects.EncEnumerated(1)}, nil)
	if class, code := errorOf(got.APDU); got == nil || got.APDU == nil || class != uint32(objects.ErrorClassProperty) || code != 9 {
		t.Errorf("a write of the wrong kind got %s, want Error property code 9", answer(got))
	}

	// A silent site: the consumer gets nothing, and the site socket
	// carried the write once, although reads are retried.
	before := countService(t, b.SiteRec.Sent(), services.ServiceConfirmedWriteProperty)
	b.Sim.Silence(0, true)
	if got := exchange(7, ahu, setpoint, objects.PropertyIdPresentValue, real(60), nil); got != nil {
		t.Errorf("a write to a silent site was answered with %s", answer(got))
	}
	b.Sim.Silence(0, false)
	if n := countService(t, b.SiteRec.Sent(), services.ServiceConfirmedWriteProperty); n != before+1 {
		t.Errorf("the site socket carried %d writes during the silence, want 1", n-before)
	}
	// The sim recorded the wrong-kind write with its refusal, so four in
	// all, and nothing from the silence.
	if len(b.Sim.Writes()) != 4 {
		t.Errorf("the silent site took a write: %+v", b.Sim.Writes())
	}
}

package translate

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
)

func marshal(t *testing.T, tags []*objects.Object) []byte {
	t.Helper()
	var b []byte
	for _, tag := range tags {
		tb, err := tag.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, tb...)
	}
	return b
}

// Every kind of value, nested constructed values included, survives tags to
// values to tags byte for byte, and values to tags to values.
func TestRoundTrip(t *testing.T) {
	tags := []*objects.Object{
		objects.EncNull(), objects.EncBoolean(true), objects.EncBoolean(false),
		objects.EncUnsignedInteger(7), objects.EncUnsignedInteger(70000), objects.EncSignedInteger(-300),
		objects.EncReal(21.5), objects.EncDouble(1e-9), objects.EncOctetString([]byte{1, 2, 3}), objects.EncOctetString(nil),
		objects.EncString("AHU1.OAT"), objects.EncString(""), objects.EncBitString([]bool{true, false, false, true, true}),
		objects.EncEnumerated(2), objects.EncEnumerated(70000),
		{TagNumber: objects.TagDate, Data: []byte{126, 10, 14, 3}, Length: 4},
		{TagNumber: objects.TagTime, Data: []byte{2, 15, 0, 0}, Length: 4},
		objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, 1001),
		objects.ContextTag(0, objects.EncUnsignedInteger(5)),
		objects.ContextTag(1, objects.EncReal(3)),
		objects.EncContextBool(2, true),
		objects.EncOpeningTag(3),
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogInput, 3),
		objects.EncOpeningTag(4), objects.EncString("inner"), objects.EncClosingTag(4),
		objects.EncClosingTag(3),
		objects.EncOpeningTag(0), objects.EncClosingTag(0),
	}
	values, err := Decode(tags)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshal(t, Encode(values)), marshal(t, tags)) {
		t.Errorf("tags changed through values:\n%x\n%x", marshal(t, Encode(values)), marshal(t, tags))
	}
	again, err := Decode(Encode(values))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, values) {
		t.Errorf("values changed through tags:\n%+v\n%+v", again, values)
	}
	kinds := map[client.Kind]bool{}
	for _, v := range values {
		kinds[v.Kind] = true
	}
	for k := client.KindNull; k <= client.KindConstructed; k++ {
		if !kinds[k] {
			t.Errorf("kind %d is not covered", k)
		}
	}
	for _, bad := range [][]*objects.Object{
		{objects.EncOpeningTag(1)},
		{objects.EncClosingTag(1)},
		{objects.EncOpeningTag(1), objects.EncClosingTag(2)},
	} {
		if _, err := Decode(bad); err == nil {
			t.Error("unbalanced tags were decoded")
		}
	}
}

// A UCS-2 string comes back as the same text in UTF-8: the accepted loss.
func TestStringCharset(t *testing.T) {
	values, err := Decode([]*objects.Object{{TagNumber: objects.TagCharacterString, Data: []byte{4, 0, 'O', 0, 'K'}, Length: 5}})
	if err != nil || len(values) != 1 || values[0].Str != "OK" {
		t.Fatalf("%+v, %v", values, err)
	}
	if got := Encode(values)[0].Data; !bytes.Equal(got, []byte{0, 'O', 'K'}) {
		t.Errorf("re-encoded as %x", got)
	}
}

func testRules(known map[uint32]uint32) Rules {
	return Rules{
		Device: func(i uint32) (uint32, bool) {
			if v, ok := known[i]; ok {
				return v, true
			}
			return i + 1000000, true // a referenced device gets a pseudonym too
		},
		Known:   func(i uint32) bool { _, ok := known[i]; return ok },
		Network: func(n uint16) uint16 { return n + 7000 },
		DeviceMAC: func(i uint32) ([]byte, bool) {
			return []byte{0xAA, byte(i)}, true
		},
		MACAt: func(net uint16, mac []byte) ([]byte, bool) {
			if net == 2001 && bytes.Equal(mac, []byte{5}) {
				return []byte{0xBB, 0x05}, true
			}
			return nil, false
		},
	}
}

func ctx4(tag uint8, b ...byte) client.Value {
	return client.Value{Kind: client.KindContext, Tag: tag, Bytes: b}
}
func devID(i uint32) []byte {
	return []byte{0x02, byte(i >> 16), byte(i >> 8), byte(i)}
}

// Device identifiers are rewritten at every depth, by the rules for context
// tags; everything else is untouched.
func TestDeviceIdentifiers(t *testing.T) {
	r := testRules(map[uint32]uint32{1001: 4242, 2000: 17})
	in := []client.Value{
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 1001}},
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 3000}},
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: Wildcard}},
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 1001}},
		{Kind: client.KindConstructed, Tag: 2, Items: []client.Value{
			{Kind: client.KindConstructed, Tag: 4, Items: []client.Value{
				{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 2000}},
			}},
		}},
		// A device-object-property reference: [0] object, [1] property, [3] device.
		ctx4(0, devID(1001)...), ctx4(1, 85), ctx4(3, devID(5555)...),
		// One with an index.
		ctx4(0, 0, 0, 0, 3), ctx4(1, 85), ctx4(2, 1), ctx4(3, devID(5555)...),
		// A known device in a context tag of its own.
		ctx4(0, devID(2000)...),
		// A timestamp at 02:15:00.00 is not a device.
		ctx4(0, 2, 15, 0, 0),
		// A [3] that is not preceded by a reference is not one either.
		ctx4(3, devID(5555)...),
		{Kind: client.KindReal, Float: 21.5},
	}
	out := r.Values(in)
	want := func(i int, b []byte) {
		t.Helper()
		if !bytes.Equal(out[i].Bytes, b) {
			t.Errorf("value %d is %x, want %x", i, out[i].Bytes, b)
		}
	}
	if out[0].Object.Instance != 4242 {
		t.Errorf("known device: %+v", out[0])
	}
	if out[1].Object.Instance != 1003000 {
		t.Errorf("referenced device: %+v", out[1])
	}
	if out[2].Object.Instance != Wildcard || out[3].Object.Instance != 1001 {
		t.Errorf("wildcard or non-device changed: %+v %+v", out[2], out[3])
	}
	if out[4].Items[0].Items[0].Object.Instance != 17 {
		t.Errorf("nested device: %+v", out[4])
	}
	want(5, devID(4242))
	want(7, devID(1005555))
	want(11, devID(1005555))
	want(12, devID(17))
	want(13, []byte{2, 15, 0, 0})
	want(14, devID(5555))
	if out[15].Float != 21.5 || in[0].Object.Instance != 1001 {
		t.Error("the input or an unrelated value was changed")
	}
}

func TestAddresses(t *testing.T) {
	r := testRules(map[uint32]uint32{1001: 4242})
	bindings := []client.Value{
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 1001}},
		{Kind: client.KindUnsigned, Uint: 0},
		{Kind: client.KindOctets, Bytes: []byte{10, 0, 0, 3, 0xBA, 0xC0}},
		{Kind: client.KindObjectID, Object: client.ObjectID{Type: objects.ObjectTypeDevice, Instance: 2101}},
		{Kind: client.KindUnsigned, Uint: 2001},
		{Kind: client.KindOctets, Bytes: []byte{5}},
	}
	out := r.AddressBindings(bindings)
	if out[0].Object.Instance != 4242 || out[1].Uint != 7000 || !bytes.Equal(out[2].Bytes, []byte{0xAA, 0xE9}) {
		t.Errorf("first binding: %+v", out[:3])
	}
	if out[3].Object.Instance != 1002101 || out[4].Uint != 9001 || !bytes.Equal(out[5].Bytes, []byte{0xAA, 0x35}) {
		t.Errorf("second binding: %+v", out[3:])
	}
	if bindings[1].Uint != 0 {
		t.Error("the input was changed")
	}

	var unmapped int
	r.OnUnmapped = func(uint16, []byte) { unmapped++ }
	recipients := []client.Value{
		{Kind: client.KindConstructed, Tag: 1, Items: []client.Value{{Kind: client.KindUnsigned, Uint: 2001}, {Kind: client.KindOctets, Bytes: []byte{5}}}},
		{Kind: client.KindConstructed, Tag: 1, Items: []client.Value{{Kind: client.KindUnsigned, Uint: 0}, {Kind: client.KindOctets, Bytes: []byte{10, 0, 0, 9, 0xBA, 0xC0}}}},
		{Kind: client.KindConstructed, Tag: 0, Items: []client.Value{{Kind: client.KindObjectID, Object: client.ObjectID{Type: 8, Instance: 1001}}}},
	}
	out = r.Values(recipients)
	if out[0].Items[0].Uint != 9001 || !bytes.Equal(out[0].Items[1].Bytes, []byte{0xBB, 5}) {
		t.Errorf("known address: %+v", out[0])
	}
	if out[1].Items[0].Uint != 7000 || len(out[1].Items[1].Bytes) != 0 || unmapped != 1 {
		t.Errorf("unknown address: %+v, %d unmapped", out[1], unmapped)
	}
	if out[2].Items[0].Object.Instance != 4242 {
		t.Errorf("recipient by device: %+v", out[2])
	}
}

func TestReplaceStrings(t *testing.T) {
	in := []client.Value{{Kind: client.KindString, Str: "a"}, {Kind: client.KindUnsigned, Uint: 1}, {Kind: client.KindString, Str: "b"}}
	out := ReplaceStrings(in, func(s string) string { return "X" + s })
	if out[0].Str != "Xa" || out[2].Str != "Xb" || out[1].Uint != 1 || in[0].Str != "a" {
		t.Errorf("%+v", out)
	}
}

func TestObjectID(t *testing.T) {
	if id, ok := ObjectID(objects.EncObjectIdentifier(true, 0, objects.ObjectTypeDevice, 9)); !ok || !IsDevice(id) || id.InstanceNumber != 9 {
		t.Errorf("%+v %t", id, ok)
	}
	if _, ok := ObjectID(objects.EncUnsignedInteger(5)); ok {
		t.Error("an unsigned read as an identifier")
	}
	if id, _ := ObjectID(objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, Wildcard)); IsDevice(id) {
		t.Error("the wildcard counts as a device")
	}
}

// Hidden objects are left out of a list of objects in each of its shapes:
// an object-list, a subordinate-list of device-object references, and a
// list-of-group-members of read-access specifications; strings are
// replaced at any depth.
func TestDropObjectsAndReplaceDeep(t *testing.T) {
	hidden := map[uint16]bool{56: true}
	oid := func(typ uint16, inst uint32) client.Value {
		return client.Value{Kind: client.KindObjectID, Object: client.ObjectID{Type: typ, Instance: inst}}
	}
	ctxID := func(tag uint8, typ uint16, inst uint32) client.Value {
		v := uint32(typ)<<22 | inst
		return client.Value{Kind: client.KindContext, Tag: tag, Bytes: []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}}
	}
	list := DropObjects([]client.Value{oid(8, 1), oid(0, 0), oid(56, 1), oid(0, 1)}, hidden)
	if len(list) != 3 || list[2].Object.Type != 0 || list[2].Object.Instance != 1 {
		t.Errorf("object-list: %+v", list)
	}
	sub := DropObjects([]client.Value{ctxID(0, 8, 1), ctxID(1, 0, 0), ctxID(0, 8, 1), ctxID(1, 56, 1), ctxID(1, 0, 2)}, hidden)
	if len(sub) != 3 || sub[2].Tag != 1 {
		t.Errorf("subordinate-list: %+v", sub)
	}
	refs := client.Value{Kind: client.KindConstructed, Tag: 1, Items: []client.Value{{Kind: client.KindContext, Tag: 0, Bytes: []byte{85}}}}
	members := DropObjects([]client.Value{ctxID(0, 56, 1), refs, ctxID(0, 0, 0), refs}, hidden)
	if len(members) != 2 || members[0].Tag != 0 || members[1].Kind != client.KindConstructed {
		t.Errorf("list-of-group-members: %+v", members)
	}
	if out := DropObjects([]client.Value{oid(56, 1)}, hidden); out == nil || len(out) != 0 {
		t.Errorf("a list of hidden objects only: %+v, want an empty list", out)
	}
	deep := ReplaceStrings([]client.Value{{Kind: client.KindString, Str: "a"}, {Kind: client.KindConstructed, Tag: 2, Items: []client.Value{{Kind: client.KindString, Str: "b"}}}},
		func(s string) string { return "x" + s })
	if deep[0].Str != "xa" || deep[1].Items[0].Str != "xb" {
		t.Errorf("deep replacement: %+v", deep)
	}
	if v := ReplaceUnsigned([]client.Value{{Kind: client.KindUnsigned, Uint: 999}}, 0); v[0].Uint != 0 {
		t.Errorf("vendor identifier not blanked: %+v", v)
	}
}

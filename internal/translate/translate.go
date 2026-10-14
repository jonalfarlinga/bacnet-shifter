// Package translate turns the library's decoded values back into tags, and
// rewrites what identifies the site in values on their way to the consumer:
// device object identifiers wherever they appear, addresses, and the
// replaced string properties (spec §6.5, §6.6 and §9.4).
//
// Device identifiers are rewritten by rule, not by property: every
// application-tagged object identifier of type device is mapped, at any
// depth. A context-tagged value of four bytes may be a device identifier or
// may be something else of four bytes, a Time at two in the morning among
// them, so it is mapped only when its instance is a device the table knows,
// or when it sits where a device identifier sits by schema: the [3] of a
// BACnetDeviceObjectPropertyReference, after an object [0] and a property
// [1]. That is the one deviation from the spec's blanket rule, and the
// reason is that a timestamp [0] 02:15:00.00 encodes as 02 0F 00 00, which
// reads as device object 983040.
package translate

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
)

// Wildcard is the device instance that means "this device"; it passes
// through untranslated in both directions.
const Wildcard = client.WildcardInstance

// ---- values to tags and back -----------------------------------------------

// Encode turns values back into the tags they came from. What it loses, and
// v1 accepts: the character set a string was sent in, and the tag number of
// a reserved application tag, which the client decoded as octets.
func Encode(values []client.Value) []*objects.Object {
	var tags []*objects.Object
	for _, v := range values {
		tags = appendTags(tags, v)
	}
	return tags
}

func appendTags(tags []*objects.Object, v client.Value) []*objects.Object {
	switch v.Kind {
	case client.KindNull:
		return append(tags, objects.EncNull())
	case client.KindBoolean:
		return append(tags, objects.EncBoolean(v.Bool))
	case client.KindUnsigned:
		return append(tags, objects.EncUnsignedInteger(uint(v.Uint)))
	case client.KindSigned:
		return append(tags, objects.EncSignedInteger(int(v.Int)))
	case client.KindReal:
		return append(tags, objects.EncReal(float32(v.Float)))
	case client.KindDouble:
		return append(tags, objects.EncDouble(v.Float))
	case client.KindOctets:
		return append(tags, objects.EncOctetString(v.Bytes))
	case client.KindString:
		return append(tags, objects.EncString(v.Str))
	case client.KindBits:
		return append(tags, objects.EncBitString(v.Bits))
	case client.KindEnumerated:
		return append(tags, objects.EncEnumerated(uint32(v.Uint)))
	case client.KindDate:
		return append(tags, &objects.Object{TagNumber: objects.TagDate, Data: v.Bytes, Length: uint32(len(v.Bytes))})
	case client.KindTime:
		return append(tags, &objects.Object{TagNumber: objects.TagTime, Data: v.Bytes, Length: uint32(len(v.Bytes))})
	case client.KindObjectID:
		return append(tags, objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, v.Object.Type, v.Object.Instance))
	case client.KindContext:
		return append(tags, &objects.Object{TagClass: true, TagNumber: v.Tag, Data: v.Bytes, Length: uint32(len(v.Bytes))})
	case client.KindConstructed:
		tags = append(tags, objects.EncOpeningTag(v.Tag))
		for _, item := range v.Items {
			tags = appendTags(tags, item)
		}
		return append(tags, objects.EncClosingTag(v.Tag))
	}
	return tags
}

// Decode turns a run of tags into values, as the client does for a reply:
// opening and closing tags become constructed values.
func Decode(tags []*objects.Object) ([]client.Value, error) {
	values, rest, err := decodeUntilClose(tags)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("closing tag %d without an opening tag", rest[0].TagNumber)
	}
	return values, nil
}

func decodeUntilClose(tags []*objects.Object) ([]client.Value, []*objects.Object, error) {
	var values []client.Value
	for len(tags) > 0 {
		t := tags[0]
		switch t.Kind {
		case objects.TagClosing:
			return values, tags, nil
		case objects.TagOpening:
			items, rest, err := decodeUntilClose(tags[1:])
			if err != nil {
				return nil, nil, err
			}
			if len(rest) == 0 || rest[0].TagNumber != t.TagNumber {
				return nil, nil, fmt.Errorf("opening tag %d is not closed", t.TagNumber)
			}
			values = append(values, client.Value{Kind: client.KindConstructed, Tag: t.TagNumber, Items: items})
			tags = rest[1:]
		default:
			values = append(values, DecodePrimitive(t))
			tags = tags[1:]
		}
	}
	return values, nil, nil
}

// DecodePrimitive decodes one primitive tag as the client does.
func DecodePrimitive(t *objects.Object) client.Value {
	if t.TagClass {
		return client.Value{Kind: client.KindContext, Tag: t.TagNumber, Bytes: t.Data}
	}
	d := t.Data
	switch t.TagNumber {
	case objects.TagNull:
		return client.Value{Kind: client.KindNull}
	case objects.TagBoolean:
		return client.Value{Kind: client.KindBoolean, Bool: t.Length == 1}
	case objects.TagUnsignedInteger:
		if len(d) >= 1 && len(d) <= 8 {
			return client.Value{Kind: client.KindUnsigned, Uint: beUint(d)}
		}
	case objects.TagSignedInteger:
		if len(d) >= 1 && len(d) <= 8 {
			shift := uint(64 - 8*len(d))
			return client.Value{Kind: client.KindSigned, Int: int64(beUint(d)<<shift) >> shift}
		}
	case objects.TagReal:
		if len(d) == 4 {
			return client.Value{Kind: client.KindReal, Float: float64(math.Float32frombits(binary.BigEndian.Uint32(d)))}
		}
	case objects.TagDouble:
		if len(d) == 8 {
			return client.Value{Kind: client.KindDouble, Float: math.Float64frombits(binary.BigEndian.Uint64(d))}
		}
	case objects.TagOctetString:
		return client.Value{Kind: client.KindOctets, Bytes: d}
	case objects.TagCharacterString:
		if len(d) >= 1 {
			return client.Value{Kind: client.KindString, Str: decodeString(d[0], d[1:])}
		}
	case objects.TagBitString:
		if bits, err := objects.DecBitString(t); err == nil {
			return client.Value{Kind: client.KindBits, Bits: bits}
		}
	case objects.TagEnumerated:
		if len(d) >= 1 && len(d) <= 4 {
			return client.Value{Kind: client.KindEnumerated, Uint: beUint(d)}
		}
	case objects.TagDate:
		if len(d) == 4 {
			return client.Value{Kind: client.KindDate, Bytes: d}
		}
	case objects.TagTime:
		if len(d) == 4 {
			return client.Value{Kind: client.KindTime, Bytes: d}
		}
	case objects.TagBACnetObjectIdentifier:
		if len(d) == 4 {
			return client.Value{Kind: client.KindObjectID, Object: objectIDOf(d)}
		}
	}
	return client.Value{Kind: client.KindOctets, Bytes: d}
}

func beUint(d []byte) uint64 {
	var v uint64
	for _, b := range d {
		v = v<<8 | uint64(b)
	}
	return v
}

func objectIDOf(d []byte) client.ObjectID {
	v := binary.BigEndian.Uint32(d)
	return client.ObjectID{Type: uint16(v >> 22), Instance: v & 0x3FFFFF}
}

func decodeString(charset uint8, d []byte) string {
	switch charset {
	case 4:
		units := make([]uint16, len(d)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(d[2*i:])
		}
		return string(utf16.Decode(units))
	case 5:
		runes := make([]rune, len(d))
		for i, b := range d {
			runes[i] = rune(b)
		}
		return string(runes)
	}
	return string(d)
}

// ObjectID reads an object identifier out of a tag: an application-tagged
// one, or a context-tagged one of four bytes.
func ObjectID(t *objects.Object) (objects.ObjectIdentifier, bool) {
	if t == nil || t.Kind != objects.TagPrimitive || len(t.Data) != 4 {
		return objects.ObjectIdentifier{}, false
	}
	if !t.TagClass && t.TagNumber != objects.TagBACnetObjectIdentifier {
		return objects.ObjectIdentifier{}, false
	}
	id, err := objects.DecObjectIdentifier(t)
	return id, err == nil
}

// IsDevice reports whether an identifier names a device object other than
// the wildcard.
func IsDevice(id objects.ObjectIdentifier) bool {
	return id.ObjectType == objects.ObjectTypeDevice && id.InstanceNumber != Wildcard
}

// ---- the rewriting ---------------------------------------------------------

// Rules is what the rewriting asks of the table. Downstream the functions
// map real to virtual; upstream the other way round.
type Rules struct {
	// Device maps a device instance. ok is false when it cannot be mapped:
	// upstream, a virtual instance the shifter never issued.
	Device func(instance uint32) (virtual uint32, ok bool)
	// Known reports whether a device instance is one the table knows, for
	// the context-tag rule.
	Known func(instance uint32) bool
	// Network maps a network number; 0 is the local network.
	Network func(number uint16) uint16
	// DeviceMAC gives the MAC of a device on the other side, by the
	// instance given to Device.
	DeviceMAC func(instance uint32) ([]byte, bool)
	// MACAt gives the MAC on the other side of the device at an address;
	// false when the table does not know which device that is.
	MACAt func(net uint16, mac []byte) ([]byte, bool)
	// OnUnmapped is told of an address whose device the table does not
	// know, which is rewritten to the broadcast MAC. May be nil.
	OnUnmapped func(net uint16, mac []byte)
}

// Values rewrites the device identifiers and the addresses in values, at
// any depth, and returns the rewritten copy.
func (r Rules) Values(values []client.Value) []client.Value {
	out := make([]client.Value, len(values))
	copy(out, values)
	for i := range out {
		v := &out[i]
		switch v.Kind {
		case client.KindObjectID:
			if v.Object.Type == objects.ObjectTypeDevice && v.Object.Instance != Wildcard {
				if m, ok := r.Device(v.Object.Instance); ok {
					v.Object.Instance = m
				}
			}
		case client.KindContext:
			if len(v.Bytes) != 4 {
				continue
			}
			id := objectIDOf(v.Bytes)
			if id.Type != objects.ObjectTypeDevice || id.Instance == Wildcard || !r.contextIsDevice(out, i, id.Instance) {
				continue
			}
			if m, ok := r.Device(id.Instance); ok {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, uint32(objects.ObjectTypeDevice)<<22|m)
				v.Bytes = b
			}
		case client.KindConstructed:
			if addr, ok := r.address(*v); ok {
				*v = addr
				continue
			}
			v.Items = r.Values(v.Items)
		}
	}
	return out
}

// contextIsDevice decides whether the context-tagged four bytes at i, which
// read as a device identifier, are one: when the table knows the instance,
// or when the tag is the [3] of a device-object-property reference, after
// an object [0], a property [1] and perhaps an index [2].
func (r Rules) contextIsDevice(items []client.Value, i int, instance uint32) bool {
	if r.Known != nil && r.Known(instance) {
		return true
	}
	v := items[i]
	if v.Tag != 3 {
		return false
	}
	j := i - 1
	if j >= 0 && items[j].Kind == client.KindContext && items[j].Tag == 2 {
		j--
	}
	if j < 1 || items[j].Kind != client.KindContext || items[j].Tag != 1 || len(items[j].Bytes) == 0 || len(items[j].Bytes) > 4 {
		return false
	}
	j--
	return items[j].Kind == client.KindContext && items[j].Tag == 0 && len(items[j].Bytes) == 4
}

// address rewrites a BACnetAddress in the form it takes inside a choice:
// [1] { network-number Unsigned, mac-address OctetString }, as a recipient
// gives it. The network number is mapped; the MAC becomes that of the device
// the table knows at the address, or the broadcast MAC, empty, when it knows
// none.
func (r Rules) address(v client.Value) (client.Value, bool) {
	if v.Tag != 1 || len(v.Items) != 2 || v.Items[0].Kind != client.KindUnsigned || v.Items[1].Kind != client.KindOctets {
		return v, false
	}
	if r.Network == nil || r.MACAt == nil {
		return v, false
	}
	net := uint16(v.Items[0].Uint)
	mac, ok := r.MACAt(net, v.Items[1].Bytes)
	if !ok {
		if r.OnUnmapped != nil {
			r.OnUnmapped(net, v.Items[1].Bytes)
		}
		mac = nil
	}
	items := []client.Value{
		{Kind: client.KindUnsigned, Uint: uint64(r.Network(net))},
		{Kind: client.KindOctets, Bytes: mac},
	}
	return client.Value{Kind: client.KindConstructed, Tag: 1, Items: items}, true
}

// AddressBindings rewrites a device-address-binding value: a list of device
// identifier, network number and MAC. Each device identifier is mapped, the
// network number too, and the MAC becomes the device's MAC on the other
// side, so that an entry for a device not yet heard from is rewritten as
// well.
func (r Rules) AddressBindings(values []client.Value) []client.Value {
	out := make([]client.Value, len(values))
	copy(out, values)
	for i := 0; i+2 < len(out); i += 3 {
		dev, net, mac := &out[i], &out[i+1], &out[i+2]
		if dev.Kind != client.KindObjectID || net.Kind != client.KindUnsigned || mac.Kind != client.KindOctets {
			break
		}
		if dev.Object.Type != objects.ObjectTypeDevice {
			continue
		}
		real := dev.Object.Instance
		m, ok := r.Device(real)
		if !ok {
			continue
		}
		dev.Object.Instance = m
		if r.Network != nil {
			net.Uint = uint64(r.Network(uint16(net.Uint)))
		}
		if r.DeviceMAC != nil {
			if vmac, ok := r.DeviceMAC(real); ok {
				mac.Bytes = vmac
			} else {
				mac.Bytes = nil
			}
		}
	}
	return out
}

// ReplaceStrings maps every character string among the values, for a
// replaced property: one string, or an array of them.
func ReplaceStrings(values []client.Value, f func(string) string) []client.Value {
	out := make([]client.Value, len(values))
	copy(out, values)
	for i := range out {
		if out[i].Kind == client.KindString {
			out[i].Str = f(out[i].Str)
		}
	}
	return out
}

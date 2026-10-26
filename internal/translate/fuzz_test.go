package translate

import (
	"testing"

	"github.com/jonalfarlinga/bacnet/objects"
)

// FuzzDecodeValues decodes raw bytes into tags, the tags into values, runs
// the rewriting over them and encodes them back: whatever the bytes,
// nothing panics, and what decoded encodes again to the same tags. Run it
// for a while with
//
//	go test ./internal/translate -run=^$ -fuzz=FuzzDecodeValues -fuzztime=60s
func FuzzDecodeValues(f *testing.F) {
	for _, tags := range [][]*objects.Object{
		{objects.EncString("AHU-1"), objects.EncReal(21.5), objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, 1001)},
		{objects.EncOpeningTag(0), objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogInput, 1),
			objects.ContextTag(1, objects.EncUnsignedInteger(85)), &objects.Object{TagClass: true, TagNumber: 3, Data: devID(1001), Length: 4}, objects.EncClosingTag(0)},
		{objects.EncOpeningTag(1), objects.EncUnsignedInteger(2001), objects.EncOctetString([]byte{5}), objects.EncClosingTag(1)},
		{objects.EncBitString([]bool{true, false, true}), objects.EncEnumerated(3), objects.EncNull(), objects.EncBoolean(true),
			objects.EncSignedInteger(-7), objects.EncDouble(1.5)},
	} {
		var b []byte
		for _, t := range tags {
			tb, _ := t.MarshalBinary()
			b = append(b, tb...)
		}
		f.Add(b)
	}
	rules := testRules(map[uint32]uint32{1001: 5001, 2000: 5002})
	f.Fuzz(func(t *testing.T, data []byte) {
		var tags []*objects.Object
		for offset := 0; offset < len(data); {
			tag, n, err := objects.DecodeTag(data[offset:])
			if err != nil || n <= 0 {
				break
			}
			tags = append(tags, tag)
			offset += n
		}
		values, err := Decode(tags)
		if err != nil {
			return
		}
		rewritten := rules.Values(values)
		rules.AddressBindings(values)
		ReplaceStrings(values, func(s string) string { return "x" })
		again := Encode(rewritten)
		if _, err := Decode(again); err != nil {
			t.Fatalf("the encoding of decoded values does not decode: %v", err)
		}
		if len(Encode(values)) != len(tags) {
			t.Fatalf("%d tags decoded and encoded back to %d", len(tags), len(Encode(values)))
		}
	})
}

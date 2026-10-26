package shifter

import (
	"testing"

	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"
)

// The fuzzers of the shifter's own request parsers. Each takes raw bytes,
// decodes them into tags as the server does for a confirmed request, and
// hands the tags to the parser: whatever the bytes, the parser answers or
// refuses and never panics. Run one for a while with
//
//	go test ./internal/shifter -run=^$ -fuzz=FuzzParseWrite -fuzztime=60s

// tagsFrom decodes bytes into tags, stopping at the first bad one, as the
// server's confirmed-request parser does.
func tagsFrom(b []byte) []*objects.Object {
	var tags []*objects.Object
	for offset := 0; offset < len(b); {
		tag, n, err := objects.DecodeTag(b[offset:])
		if err != nil || n <= 0 {
			return tags
		}
		tags = append(tags, tag)
		offset += n
	}
	return tags
}

func payloadBytes(payload []objects.APDUPayload) []byte {
	var out []byte
	for _, p := range payload {
		b, err := p.MarshalBinary()
		if err != nil {
			panic(err)
		}
		out = append(out, b...)
	}
	return out
}

func FuzzParseWrite(f *testing.F) {
	f.Add(payloadBytes(services.ConfirmedWritePropertyObjects(objects.ObjectTypeAnalogValue, 0, objects.PropertyIdPresentValue, float32(21.5))))
	f.Add(payloadBytes([]objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogValue, 0),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(objects.PropertyIdPresentValue))),
		objects.ContextTag(2, objects.EncUnsignedInteger(3)),
		objects.EncOpeningTag(3), objects.EncNull(), objects.EncClosingTag(3),
	}))
	f.Add(payloadBytes([]objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeDevice, 4194303),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(objects.PropertyIdObjectName))),
		objects.EncOpeningTag(3), objects.EncOpeningTag(0), objects.EncString("x"), objects.EncClosingTag(0), objects.EncClosingTag(3),
		objects.ContextTag(4, objects.EncUnsignedInteger(16)),
	}))
	f.Fuzz(func(t *testing.T, data []byte) {
		w, ans := parseWrite(tagsFrom(data))
		if ans == nil && len(w.value) == 0 {
			t.Fatal("a write with no value was accepted")
		}
	})
}

func FuzzParseRPM(f *testing.F) {
	f.Add(payloadBytes(services.ConfirmedReadPropertyMultipleObjects(objects.ObjectTypeDevice, 1001, []uint16{objects.PropertyIdObjectName, objects.PropertyIdObjectList})))
	f.Add(payloadBytes([]objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogInput, 0),
		objects.EncOpeningTag(1), objects.ContextTag(0, objects.EncUnsignedInteger(85)), objects.EncClosingTag(1),
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeAnalogInput, 1),
		objects.EncOpeningTag(1), objects.ContextTag(0, objects.EncUnsignedInteger(85)), objects.ContextTag(0, objects.EncUnsignedInteger(77)), objects.EncClosingTag(1),
	}))
	f.Fuzz(func(t *testing.T, data []byte) {
		specs, ans := parseRPM(tagsFrom(data))
		if ans == nil && len(specs) == 0 {
			t.Fatal("an empty request was accepted")
		}
		for _, s := range specs {
			if ans == nil && len(s.props) == 0 {
				t.Fatal("an object with no properties was accepted")
			}
		}
	})
}

func FuzzParseReadRange(f *testing.F) {
	f.Add(payloadBytes(services.ConfirmedReadRangeObjects(objects.ObjectTypeTrendLog, 0, objects.PropertyIdLogBuffer, 1, 10)))
	f.Add(payloadBytes([]objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeTrendLog, 0),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(objects.PropertyIdLogBuffer))),
	}))
	f.Add(payloadBytes([]objects.APDUPayload{
		objects.EncObjectIdentifier(true, 0, objects.ObjectTypeTrendLog, 0),
		objects.ContextTag(1, objects.EncUnsignedInteger(uint(objects.PropertyIdLogBuffer))),
		objects.EncOpeningTag(6), objects.EncUnsignedInteger(100), objects.EncSignedInteger(-5), objects.EncClosingTag(6),
	}))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseReadRange(tagsFrom(data))
	})
}

// FuzzWhoHas decodes an unconfirmed APDU and, when it is a Who-Has, the
// library's decoding of it, as the shifter's whoHas does.
func FuzzWhoHas(f *testing.F) {
	for _, payload := range [][]objects.APDUPayload{
		services.WhoHasObjects(0, 0, "AHU-1"),
		services.WhoHasObjects(objects.ObjectTypeAnalogInput, 3, ""),
		{objects.ContextTag(0, objects.EncUnsignedInteger(1)), objects.ContextTag(1, objects.EncUnsignedInteger(9999)), objects.ContextTag(3, objects.EncString("x"))},
	} {
		a := plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoHas, payload)
		b := make([]byte, a.MarshalLen())
		a.MarshalTo(b)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a plumbing.APDU
		if err := a.UnmarshalBinary(data); err != nil {
			return
		}
		tagsOf(&a)
		req := services.UnconfirmedWhoHas{APDU: &a}
		req.Decode()
	})
}

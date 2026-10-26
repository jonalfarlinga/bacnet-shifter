package control

import (
	"net/netip"
	"testing"

	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/services"
)

// Every confirmed service code has one answer per level: the level's list
// is forwarded, the four never-forwarded ones and the rest of the known ones
// are denied, and the unknown ones are rejected as unrecognized.
func TestRefusalTable(t *testing.T) {
	forwardedAt := map[Level][]uint8{
		NoWrite:     {12, 14, 26},
		Limited:     {12, 14, 26, 5},
		FullService: {12, 14, 26, 5, 15},
	}
	for level, list := range forwardedAt {
		want := map[uint8]bool{}
		for _, s := range list {
			want[s] = true
		}
		for service := 0; service < 256; service++ {
			s := uint8(service)
			a := level.Confirmed(s)
			switch {
			case want[s]:
				if !a.Forward {
					t.Errorf("%s: service %d is not forwarded", level, s)
				}
			case !Known(s):
				if a != Unrecognized {
					t.Errorf("%s: unknown service %d gets %+v, want Reject unrecognized-service", level, s, a)
				}
			default:
				if a != Denied {
					t.Errorf("%s: service %d gets %+v, want Error service-request-denied", level, s, a)
				}
			}
		}
	}
	for _, never := range []uint8{1, 2, 18, 28} {
		if FullService.Confirmed(never).Forward {
			t.Errorf("service %d is forwarded by full-service", never)
		}
	}
	for _, unknown := range []uint8{13, 21, 22, 23, 24, 25, 30, 31, 200, 255} {
		if Known(unknown) {
			t.Errorf("service %d is known", unknown)
		}
	}
}

func TestLevelNames(t *testing.T) {
	for _, name := range []string{"no-write", "limited", "full-service"} {
		l, err := Parse(name)
		if err != nil || l.String() != name {
			t.Errorf("%s: %v, %v", name, l, err)
		}
	}
	for _, name := range []string{"root", "god"} {
		if _, err := Parse(name); err == nil {
			t.Errorf("%q was accepted as a level", name)
		}
	}
}

func TestNames(t *testing.T) {
	if got, err := ServiceByName("life-safety-operation"); err != nil || got != 27 {
		t.Errorf("life-safety-operation: %d, %v", got, err)
	}
	if got, err := ServiceByName("read-property"); err != nil || got != services.ServiceConfirmedReadProperty {
		t.Errorf("read-property: %d, %v", got, err)
	}
	if _, err := ServiceByName("who-is"); err == nil {
		t.Error("an unconfirmed service was accepted as a confirmed one")
	}
	for name, id := range map[string]uint32{
		"object-name": uint32(objects.PropertyIdObjectName), "max-apdu-length-accepted": uint32(objects.PropertyIdMaxApduLengthAccepted),
		"serial-number": uint32(objects.PropertyIdSerialNumber), "time-delay-normal": uint32(objects.PropertyIdTimeDelayNormal),
		"event-detection-enable": uint32(objects.PropertyIdEventDetectionEnable), "9999": 9999,
	} {
		if got, err := PropertyByName(name); err != nil || got != id {
			t.Errorf("%s: %d, %v, want %d", name, got, err, id)
		}
	}
	if PropertyName(uint32(objects.PropertyIdObjectName)) != "object-name" || PropertyName(uint32(objects.PropertyIdCovIncrement)) != "cov-increment" {
		t.Errorf("property names: %s, %s", PropertyName(uint32(objects.PropertyIdObjectName)), PropertyName(uint32(objects.PropertyIdCovIncrement)))
	}
	if typ, err := ObjectTypeByName("alert-enrollment"); err != nil || typ != 52 {
		t.Errorf("alert-enrollment: %d, %v", typ, err)
	}
	if typ, err := ObjectTypeByName("300"); err != nil || typ != 300 {
		t.Errorf("proprietary type: %d, %v", typ, err)
	}
	if _, err := ObjectTypeByName("nothing"); err == nil {
		t.Error("an unknown object type was accepted")
	}
}

func u8(v uint8) *uint8 { return &v }

// The write rules at each level: the priority rule, the array index, the
// reserved objects and properties, and the string rule.
func TestWriteRules(t *testing.T) {
	reserved := DefaultReserved()
	passThrough := map[uint32]bool{uint32(objects.PropertyIdDescription): true}
	setpoint := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogValue, InstanceNumber: 0}
	alarms := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeNotificationClass, InstanceNumber: 0}
	pv, oos, name := uint32(objects.PropertyIdPresentValue), uint32(objects.PropertyIdOutOfService), uint32(objects.PropertyIdObjectName)

	for _, tc := range []struct {
		name     string
		level    Level
		w        Write
		priority uint8
		ans      Answer
	}{
		{"no-write refuses", NoWrite, Write{Object: setpoint, Property: pv}, 0, Denied},
		{"limited refuses", Limited, Write{Object: setpoint, Property: pv}, 0, Denied},
		{"none becomes 13", FullService, Write{Object: setpoint, Property: pv}, 13, Answer{Forward: true}},
		{"13 is kept", FullService, Write{Object: setpoint, Property: pv, Priority: u8(13)}, 13, Answer{Forward: true}},
		{"16 is kept", FullService, Write{Object: setpoint, Property: pv, Priority: u8(16)}, 16, Answer{Forward: true}},
		{"12 is refused", FullService, Write{Object: setpoint, Property: pv, Priority: u8(12)}, 0, WriteDenied},
		{"1 is refused", FullService, Write{Object: setpoint, Property: pv, Priority: u8(1)}, 0, WriteDenied},
		{"0 is out of range", FullService, Write{Object: setpoint, Property: pv, Priority: u8(0)}, 0, RejectOutOfRange},
		{"17 is out of range", FullService, Write{Object: setpoint, Property: pv, Priority: u8(17)}, 0, RejectOutOfRange},
		{"an index is rejected", FullService, Write{Object: setpoint, Property: uint32(objects.PropertyIdPriorityArray), Indexed: true, Priority: u8(16)}, 0, RejectOther},
		{"a reserved property", FullService, Write{Object: setpoint, Property: oos, Priority: u8(16)}, 0, WriteDenied},
		{"a reserved object", FullService, Write{Object: alarms, Property: uint32(objects.PropertyIdPriority)}, 0, WriteDenied},
		{"a string to a replaced property", FullService, Write{Object: setpoint, Property: name, StringValue: true}, 0, WriteDenied},
		{"a string to a pass-through property", FullService, Write{Object: setpoint, Property: uint32(objects.PropertyIdDescription), StringValue: true}, 13, Answer{Forward: true}},
		{"a string to a version property", FullService, Write{Object: setpoint, Property: uint32(objects.PropertyIdVendorName), StringValue: true}, 13, Answer{Forward: true}},
		{"a number to a replaced property", FullService, Write{Object: setpoint, Property: name}, 13, Answer{Forward: true}},
		{"a reserved object at 16", FullService, Write{Object: alarms, Property: oos, Priority: u8(16)}, 0, WriteDenied},
	} {
		priority, ans, rule := tc.level.Write(tc.w, WritePolicy{Reserved: reserved, PassThrough: passThrough, Allow: WriteAllowAll()})
		if priority != tc.priority || ans != tc.ans || (rule == "") != ans.Forward {
			t.Errorf("%s: priority %d, %+v, %q; want %d, %+v", tc.name, priority, ans, rule, tc.priority, tc.ans)
		}
	}

	// The write allow list, last of the rules: empty covers nothing; an
	// entry matches on type, property, and the device and consumer it
	// names.
	src := netip.MustParseAddr("10.8.0.7")
	w := Write{Object: setpoint, Property: pv, Device: 777, Source: src}
	if _, ans, rule := FullService.Write(w, WritePolicy{Reserved: reserved}); ans != WriteDenied || rule != RuleAllow {
		t.Errorf("an empty allow list: %+v, %q", ans, rule)
	}
	dev := uint32(777)
	for _, tc := range []struct {
		name  string
		entry WriteEntry
		w     Write
		ok    bool
	}{
		{"type and property", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: pv}, w, true},
		{"other property", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: oos}, w, false},
		{"any property", WriteEntry{Object: objects.ObjectTypeAnalogValue, AnyProperty: true}, w, true},
		{"any object", WriteEntry{AnyObject: true, Property: pv}, w, true},
		{"the device", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: pv, Device: &dev}, w, true},
		{"another device", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: pv, Device: &dev}, Write{Object: setpoint, Property: pv, Device: 778, Source: src}, false},
		{"the consumer", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: pv, Consumer: netip.MustParsePrefix("10.8.0.0/24")}, w, true},
		{"another consumer", WriteEntry{Object: objects.ObjectTypeAnalogValue, Property: pv, Consumer: netip.MustParsePrefix("10.9.0.0/24")}, w, false},
	} {
		_, ans, _ := FullService.Write(tc.w, WritePolicy{Reserved: reserved, Allow: WriteAllow{tc.entry}})
		if ans.Forward != tc.ok {
			t.Errorf("%s: forwarded %t, want %t", tc.name, ans.Forward, tc.ok)
		}
	}
	// The floor stays under the list.
	if _, ans, rule := FullService.Write(Write{Object: setpoint, Property: oos, Priority: u8(16)}, WritePolicy{Reserved: reserved, Allow: WriteAllowAll()}); ans != WriteDenied || rule != RuleReserved {
		t.Errorf("an allow-all list let a reserved property through: %+v, %q", ans, rule)
	}
	allow, err := ParseWriteAllow([]WriteEntryNames{{Object: "analog-value", Property: "present-value"}, {Object: "*", Property: "*", Device: "777", Consumer: "10.8.0.7"}})
	if err != nil || len(allow) != 2 || !allow[1].AnyObject || allow[1].Device == nil || *allow[1].Device != 777 || allow[1].Consumer.Bits() != 32 {
		t.Errorf("parsed %+v, %v", allow, err)
	}
	for _, bad := range [][]WriteEntryNames{
		{{Object: "no-such-type", Property: "present-value"}},
		{{Object: "analog-value", Property: "no-such-property"}},
		{{Object: "analog-value", Property: "present-value", Device: "x"}},
		{{Object: "analog-value", Property: "present-value", Consumer: "everyone"}},
		{{Property: "present-value"}},
	} {
		if _, err := ParseWriteAllow(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}

	if !FullService.ReservedService(27, reserved) || !NoWrite.ReservedService(27, reserved) || FullService.ReservedService(15, reserved) {
		t.Error("the reserved services apply at every level")
	}
}

func TestDefaults(t *testing.T) {
	r := DefaultReserved()
	if len(r.Services) != 10 || len(r.Objects) != 5 || len(r.Properties) != 10 {
		t.Errorf("default reserved set has %d, %d, %d entries", len(r.Services), len(r.Objects), len(r.Properties))
	}
	if !r.Services[27] || !r.Objects[objects.ObjectTypeNotificationClass] || !r.Properties[uint32(objects.PropertyIdOutOfService)] {
		t.Error("a default entry is missing")
	}
	hidden := DefaultHidden()
	if len(hidden) != 1 || !hidden[56] {
		t.Errorf("default hidden set: %v", hidden)
	}
	if pt, err := ParsePassThrough([]string{"state-text", "active-text"}); err != nil || len(pt) != 2 || !pt[uint32(objects.PropertyIdStateText)] {
		t.Errorf("pass-through set: %v, %v", pt, err)
	}
	if _, err := ParsePassThrough([]string{"no-such-property"}); err == nil {
		t.Error("an unknown property name was accepted")
	}
	if _, err := ParseHidden([]string{"no-such-type"}); err == nil {
		t.Error("an unknown object type name was accepted")
	}
	vendor := uint32(objects.PropertyIdVendorName)
	if !Passes(vendor, nil, false) || Passes(vendor, nil, true) || Passes(uint32(objects.PropertyIdDescription), nil, false) {
		t.Error("the version strings pass unless strict, and nothing else passes on its own")
	}
	// The strict profile does not override the operator's own list.
	if !Passes(vendor, map[uint32]bool{vendor: true}, true) {
		t.Error("a listed property passes under the strict profile too")
	}
}

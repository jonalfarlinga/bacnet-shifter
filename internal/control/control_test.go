package control

import (
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
// reserved objects and properties, and the replaced properties.
func TestWriteRules(t *testing.T) {
	reserved := DefaultReserved()
	replaced, _ := ParseReplaced(DefaultReplacedNames)
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
		{"a replaced property", FullService, Write{Object: setpoint, Property: name}, 0, WriteDenied},
		{"a reserved object at 16", FullService, Write{Object: alarms, Property: oos, Priority: u8(16)}, 0, WriteDenied},
	} {
		priority, ans := tc.level.Write(tc.w, reserved, replaced)
		if priority != tc.priority || ans != tc.ans {
			t.Errorf("%s: priority %d, %+v; want %d, %+v", tc.name, priority, ans, tc.priority, tc.ans)
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
	replaced, err := ParseReplaced(DefaultReplacedNames)
	if err != nil || len(replaced) != 5 || !replaced[uint32(objects.PropertyIdSerialNumber)] {
		t.Errorf("default replaced set: %v, %v", replaced, err)
	}
	if _, err := ParseReplaced([]string{"no-such-property"}); err == nil {
		t.Error("an unknown property name was accepted")
	}
}

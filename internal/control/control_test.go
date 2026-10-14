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
		God:         {12, 14, 26, 5, 15, 0, 3, 4, 6, 7, 8, 9, 10, 11, 16, 17, 19, 20, 27, 29},
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
		if God.Confirmed(never).Forward {
			t.Errorf("service %d is forwarded by god", never)
		}
	}
	for _, unknown := range []uint8{13, 21, 22, 23, 24, 25, 30, 31, 200, 255} {
		if Known(unknown) {
			t.Errorf("service %d is known", unknown)
		}
	}
}

func TestLevelNames(t *testing.T) {
	for _, name := range []string{"no-write", "limited", "full-service", "god"} {
		l, err := Parse(name)
		if err != nil || l.String() != name {
			t.Errorf("%s: %v, %v", name, l, err)
		}
	}
	if _, err := Parse("root"); err == nil {
		t.Error("an unknown level was accepted")
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

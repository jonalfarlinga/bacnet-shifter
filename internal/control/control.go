// Package control is the shifter's control level: the three levels, what
// each forwards to the site, the answer every other request gets, and the
// names of the services, object types and properties that the configuration
// speaks of.
package control

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/services"
)

// Level bounds what the shifter sends to the site. Each level includes the
// ones before it.
type Level uint8

const (
	// NoWrite forwards exactly the library's read-only list: Who-Is and the
	// three reads.
	NoWrite Level = iota
	// Limited adds SubscribeCOV and CancelCOV.
	Limited
	// FullService adds WriteProperty at priority 13 to ordinary properties
	// of ordinary objects. It is the highest level: no level forwards the
	// reserved set, a write at priority 1 to 12, or any other confirmed
	// service.
	FullService
)

var levelNames = []string{"no-write", "limited", "full-service"}

// Parse reads a level as the configuration names it.
func Parse(s string) (Level, error) {
	for i, name := range levelNames {
		if strings.EqualFold(strings.TrimSpace(s), name) {
			return Level(i), nil
		}
	}
	return NoWrite, fmt.Errorf("control %q is not one of %s", s, strings.Join(levelNames, ", "))
}

func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return fmt.Sprintf("level %d", uint8(l))
}

// Service codes and error codes the library has no constant for.
const (
	ServiceConfirmedLifeSafetyOperation  uint8 = 27
	ServiceConfirmedSubscribeCOVProperty uint8 = 28
	ServiceConfirmedGetEventInformation  uint8 = 29

	ErrorCodeOther                   uint8 = 0
	ErrorCodeInconsistentParameters  uint8 = 9
	ErrorCodeNoSpaceToAddListElement uint8 = 19
	ErrorCodeUnknownObject           uint8 = 31
	ErrorCodeUnknownProperty         uint8 = 32
	ErrorCodeWriteAccessDenied       uint8 = 40
)

// Answer is what a confirmed request gets from the dispatch: it is
// forwarded, or refused with a Reject or an Error.
type Answer struct {
	Forward bool
	// Reject says the refusal is a Reject with Reason; otherwise it is an
	// Error with Class and Code.
	Reject bool
	Reason uint8
	Class  uint8
	Code   uint8
}

// Refusals the dispatch gives.
var (
	// Unrecognized is the Reject for a service the shifter cannot name.
	Unrecognized = Answer{Reject: true, Reason: objects.RejectReasonUnrecognizedService}
	// Denied is the Error for a known service the level does not forward.
	Denied = Answer{Class: objects.ErrorClassServices, Code: objects.ErrorCodeServiceRequestDenied}
	// WriteDenied is the Error for a write the level or the reserved set
	// refuses.
	WriteDenied = Answer{Class: objects.ErrorClassProperty, Code: ErrorCodeWriteAccessDenied}
	// Untranslatable is the Error for a write whose value names a device
	// or an address the shifter never issued.
	Untranslatable = Answer{Class: objects.ErrorClassServices, Code: ErrorCodeOther}
	// RejectOther is the Reject for a well-formed request the shifter does
	// not split or forward: an indexed ReadPropertyMultiple, a range by
	// time.
	RejectOther = Answer{Reject: true, Reason: objects.RejectReasonOther}
	// NoSpace is the Error for a subscription past one of the caps: the
	// consumer's own, the site device's, or the site's.
	NoSpace = Answer{Class: objects.ErrorClassResources, Code: ErrorCodeNoSpaceToAddListElement}
)

// forwarded is the confirmed services each level adds to the ones before it.
var forwarded = map[Level][]uint8{
	NoWrite:     {services.ServiceConfirmedReadProperty, services.ServiceConfirmedReadPropMultiple, services.ServiceConfirmedReadRange},
	Limited:     {services.ServiceConfirmedSubscribeCOV},
	FullService: {services.ServiceConfirmedWriteProperty},
}

// Forwards reports whether the level forwards a confirmed service, before
// the rules that apply to its payload.
func (l Level) Forwards(service uint8) bool {
	for lvl := NoWrite; lvl <= l; lvl++ {
		for _, s := range forwarded[lvl] {
			if s == service {
				return true
			}
		}
	}
	return false
}

// Known reports whether the shifter can parse and name a confirmed service:
// 0 to 12, 14 to 20 and 26 to 29. The rest are removed from the standard,
// virtual terminal, or newer than the library.
func Known(service uint8) bool {
	return service <= 12 || (service >= 14 && service <= 20) || (service >= 26 && service <= 29)
}

// Confirmed is the answer a confirmed service gets at the level, by its
// code alone: forwarded, Reject unrecognized-service for an unknown one, or
// Error service-request-denied for a known one the level does not forward.
// The rules that look into the payload (the priority rule, the reserved
// set, the translatable-value check) come after it.
func (l Level) Confirmed(service uint8) Answer {
	switch {
	case !Known(service):
		return Unrecognized
	case l.Forwards(service):
		return Answer{Forward: true}
	}
	return Denied
}

// ---- names -----------------------------------------------------------------

// confirmedNames names the confirmed services, hyphenated as the standard
// writes them.
var confirmedNames = map[uint8]string{
	0: "acknowledge-alarm", 1: "confirmed-cov-notification", 2: "confirmed-event-notification",
	3: "get-alarm-summary", 4: "get-enrollment-summary", 5: "subscribe-cov", 6: "atomic-read-file",
	7: "atomic-write-file", 8: "add-list-element", 9: "remove-list-element", 10: "create-object",
	11: "delete-object", 12: "read-property", 13: "read-property-conditional", 14: "read-property-multiple",
	15: "write-property", 16: "write-property-multiple", 17: "device-communication-control",
	18: "confirmed-private-transfer", 19: "confirmed-text-message", 20: "reinitialize-device",
	21: "vt-open", 22: "vt-close", 23: "vt-data", 24: "authenticate", 25: "request-key",
	26: "read-range", 27: "life-safety-operation", 28: "subscribe-cov-property", 29: "get-event-information",
	30: "subscribe-cov-property-multiple", 31: "confirmed-cov-notification-multiple",
	32: "confirmed-audit-notification", 33: "audit-log-query",
}

var unconfirmedNames = map[uint8]string{
	0: "i-am", 1: "i-have", 2: "unconfirmed-cov-notification", 3: "unconfirmed-event-notification",
	4: "unconfirmed-private-transfer", 5: "unconfirmed-text-message", 6: "time-synchronization",
	7: "who-has", 8: "who-is", 9: "utc-time-synchronization", 10: "write-group",
	11: "unconfirmed-cov-notification-multiple", 12: "unconfirmed-audit-notification", 13: "who-am-i", 14: "you-are",
}

// ServiceName names a confirmed service for a log line.
func ServiceName(service uint8) string {
	if name, ok := confirmedNames[service]; ok {
		return name
	}
	return "confirmed service " + strconv.Itoa(int(service))
}

// UnconfirmedServiceName names an unconfirmed service for a log line.
func UnconfirmedServiceName(service uint8) string {
	if name, ok := unconfirmedNames[service]; ok {
		return name
	}
	return "unconfirmed service " + strconv.Itoa(int(service))
}

// ServiceByName finds a confirmed service by its hyphenated name, or its
// number.
func ServiceByName(name string) (uint8, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for code, n := range confirmedNames {
		if n == name {
			return code, nil
		}
	}
	if v, err := strconv.ParseUint(name, 10, 8); err == nil {
		return uint8(v), nil
	}
	return 0, fmt.Errorf("%q is not a confirmed service", name)
}

// hyphenate turns the library's CamelCase names into the standard's
// hyphenated ones: MaxApduLengthAccepted becomes max-apdu-length-accepted.
func hyphenate(camel string) string {
	var b strings.Builder
	for i, r := range camel {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r + 'a' - 'A')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PropertyName names a property as the standard does, for logs and the
// configuration.
func PropertyName(id uint32) string {
	if id <= 0xFFFF {
		if name, ok := objects.PropertyMap[uint16(id)]; ok {
			return hyphenate(name)
		}
	}
	return objects.PropertyName(id)
}

// PropertyByName finds a property by its hyphenated name, or its number for
// a proprietary one.
func PropertyByName(name string) (uint32, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for id, n := range objects.PropertyMap {
		if hyphenate(n) == name {
			return uint32(id), nil
		}
	}
	if v, err := strconv.ParseUint(name, 10, 32); err == nil && v <= 4194303 {
		return uint32(v), nil
	}
	return 0, fmt.Errorf("%q is not a property", name)
}

// ObjectTypeByName finds an object type by its hyphenated name, or its
// number for a proprietary one.
func ObjectTypeByName(name string) (uint16, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for id, n := range objects.ObjectTypeMap {
		if n == name {
			return id, nil
		}
	}
	if v, err := strconv.ParseUint(name, 10, 16); err == nil && v <= 1023 {
		return uint16(v), nil
	}
	return 0, fmt.Errorf("%q is not an object type", name)
}

// ---- the reserved set ------------------------------------------------------

// Reserved is the life-safety and alarm set: refused at every level,
// full-service included.
type Reserved struct {
	Services   map[uint8]bool
	Objects    map[uint16]bool
	Properties map[uint32]bool
}

// DefaultReservedNames is the documented default, by name.
var DefaultReservedNames = struct{ Services, Objects, Properties []string }{
	Services: []string{
		"life-safety-operation", "acknowledge-alarm", "device-communication-control", "reinitialize-device",
		"add-list-element", "remove-list-element", "create-object", "delete-object", "atomic-read-file", "atomic-write-file",
	},
	Objects:    []string{"life-safety-point", "life-safety-zone", "notification-class", "event-enrollment", "alert-enrollment"},
	Properties: []string{"out-of-service", "event-detection-enable", "event-enable", "limit-enable", "time-delay", "time-delay-normal", "notification-class", "notify-type", "recipient-list", "ack-required"},
}

// ParseReserved resolves the names of a reserved set.
func ParseReserved(services, objectTypes, properties []string) (Reserved, error) {
	r := Reserved{Services: map[uint8]bool{}, Objects: map[uint16]bool{}, Properties: map[uint32]bool{}}
	for _, s := range services {
		code, err := ServiceByName(s)
		if err != nil {
			return r, fmt.Errorf("reserved.services: %w", err)
		}
		r.Services[code] = true
	}
	for _, o := range objectTypes {
		typ, err := ObjectTypeByName(o)
		if err != nil {
			return r, fmt.Errorf("reserved.objects: %w", err)
		}
		r.Objects[typ] = true
	}
	for _, p := range properties {
		id, err := PropertyByName(p)
		if err != nil {
			return r, fmt.Errorf("reserved.properties: %w", err)
		}
		r.Properties[id] = true
	}
	return r, nil
}

// DefaultReserved is the documented default set.
func DefaultReserved() Reserved {
	r, err := ParseReserved(DefaultReservedNames.Services, DefaultReservedNames.Objects, DefaultReservedNames.Properties)
	if err != nil {
		panic(err)
	}
	return r
}

// DefaultReplacedNames is the documented default list of replaced string
// properties.
var DefaultReplacedNames = []string{"object-name", "description", "location", "model-name", "serial-number"}

// ParseReplaced resolves the names of the replaced string properties.
func ParseReplaced(names []string) (map[uint32]bool, error) {
	set := map[uint32]bool{}
	for _, n := range names {
		id, err := PropertyByName(n)
		if err != nil {
			return nil, fmt.Errorf("pseudonym.replaced: %w", err)
		}
		set[id] = true
	}
	return set, nil
}

// ReservedService reports whether a confirmed service is refused for being
// in the reserved set, which every level applies.
func (l Level) ReservedService(service uint8, r Reserved) bool {
	return r.Services[service]
}

// ---- the write rules ------------------------------------------------------

// DefaultWritePriority is the priority a full-service write goes out at
// when the consumer names none.
const DefaultWritePriority uint8 = 13

// RejectOutOfRange is the Reject for a priority that is not 1 to 16.
var RejectOutOfRange = Answer{Reject: true, Reason: objects.RejectReasonParameterOutOfRange}

// Write is a consumer's WriteProperty as the rules see it: the object and
// property named, whether an array index was given, and the priority if
// one was.
type Write struct {
	Object   objects.ObjectIdentifier
	Property uint32
	Indexed  bool
	// Priority is nil when the request names none.
	Priority *uint8
}

// Write applies the level's rules to a WriteProperty, in this order:
// the level, the array-index rule, the reserved objects and properties and
// the replaced properties, then the priority rule. It gives the priority
// to send the write at, 0 for none, or the refusal.
//
// At full-service a write with no priority goes out at 13, one at 13 to 16
// keeps its priority, and one at 1 to 12 is refused with
// write-access-denied, a relinquish the same; an indexed write is refused
// with Reject other, since the library's write method takes no index; a
// write to a reserved object or property, or to a replaced property, with
// write-access-denied. A priority that is not 1 to 16 is refused with
// Reject parameter-out-of-range at every level, before anything is sent.
func (l Level) Write(w Write, reserved Reserved, replaced map[uint32]bool) (priority uint8, ans Answer) {
	if !l.Forwards(services.ServiceConfirmedWriteProperty) {
		return 0, Denied
	}
	if w.Priority != nil && (*w.Priority == 0 || *w.Priority > 16) {
		return 0, RejectOutOfRange
	}
	if w.Indexed {
		return 0, RejectOther
	}
	if replaced[w.Property] {
		return 0, WriteDenied
	}
	if reserved.Objects[w.Object.ObjectType] || reserved.Properties[w.Property] {
		return 0, WriteDenied
	}
	switch {
	case w.Priority == nil:
		return DefaultWritePriority, Answer{Forward: true}
	case *w.Priority < DefaultWritePriority:
		return 0, WriteDenied
	}
	return *w.Priority, Answer{Forward: true}
}

// Sorted lists a set in order, for logs.
func Sorted[T uint8 | uint16 | uint32](set map[T]bool) []T {
	list := make([]T, 0, len(set))
	for v := range set {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

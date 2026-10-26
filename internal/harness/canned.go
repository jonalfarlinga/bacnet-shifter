package harness

import (
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"
)

// CannedDevice is a site device the raw socket stands in for, with the
// objects the sim does not have: a Network Port object, say. It answers
// ReadProperty from its map, the device's object-list from the map's keys
// (whole, or element by element, with element 0 the count), and every
// other request with Reject unrecognized-service. It records every object
// a request named, so that a test can assert what the site never saw.
type CannedDevice struct {
	Instance uint32
	// Objects maps each object to its properties and their values.
	Objects map[objects.ObjectIdentifier]map[uint32][]*objects.Object

	mu       sync.Mutex
	requests []objects.ObjectIdentifier
}

// Requests is every object a request named, in order.
func (d *CannedDevice) Requests() []objects.ObjectIdentifier {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]objects.ObjectIdentifier(nil), d.requests...)
}

// objectList is the identifiers of the objects, the device first, the
// rest sorted.
func (d *CannedDevice) objectList() []objects.ObjectIdentifier {
	device := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeDevice, InstanceNumber: d.Instance}
	var rest []objects.ObjectIdentifier
	for id := range d.Objects {
		if id != device {
			rest = append(rest, id)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		if rest[i].ObjectType != rest[j].ObjectType {
			return rest[i].ObjectType < rest[j].ObjectType
		}
		return rest[i].InstanceNumber < rest[j].InstanceNumber
	})
	return append([]objects.ObjectIdentifier{device}, rest...)
}

// read answers one ReadProperty: the values, or an error class and code.
func (d *CannedDevice) read(obj objects.ObjectIdentifier, prop uint32, index *uint32) ([]*objects.Object, *[2]uint32) {
	if obj.ObjectType == objects.ObjectTypeDevice && (obj.InstanceNumber == d.Instance || obj.InstanceNumber == 4194303) {
		obj.InstanceNumber = d.Instance
	}
	props, ok := d.Objects[obj]
	if !ok {
		return nil, &[2]uint32{uint32(objects.ErrorClassObject), 31}
	}
	if obj.ObjectType == objects.ObjectTypeDevice && prop == uint32(objects.PropertyIdObjectList) {
		list := d.objectList()
		var out []*objects.Object
		switch {
		case index == nil:
			for _, id := range list {
				out = append(out, objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, id.ObjectType, id.InstanceNumber))
			}
		case *index == 0:
			out = append(out, objects.EncUnsignedInteger(uint(len(list))))
		case int(*index) <= len(list):
			id := list[*index-1]
			out = append(out, objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, id.ObjectType, id.InstanceNumber))
		default:
			return nil, &[2]uint32{uint32(objects.ErrorClassProperty), 42}
		}
		return out, nil
	}
	if obj.ObjectType == objects.ObjectTypeDevice && prop == uint32(objects.PropertyIdObjectIdentifier) {
		return []*objects.Object{objects.EncObjectIdentifier(false, objects.TagBACnetObjectIdentifier, objects.ObjectTypeDevice, d.Instance)}, nil
	}
	values, ok := props[prop]
	if !ok {
		return nil, &[2]uint32{uint32(objects.ErrorClassProperty), 32}
	}
	return values, nil
}

// ServeDevice makes the raw socket answer as the canned device until the
// socket is closed. The socket cannot be read by the test while it runs.
func (r *Raw) ServeDevice(t *testing.T, d *CannedDevice) {
	t.Helper()
	go func() {
		buf := make([]byte, 2048)
		for {
			r.Conn.SetReadDeadline(time.Time{})
			n, from, err := r.Conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var bvlc plumbing.BVLC
			var npdu plumbing.NPDU
			if bvlc.UnmarshalBinary(buf[:n]) != nil || npdu.UnmarshalBinary(buf[bvlc.MarshalLen():n]) != nil || npdu.Control&plumbing.NetworkLayerMessage != 0 {
				continue
			}
			var a plumbing.APDU
			if a.UnmarshalBinary(buf[bvlc.MarshalLen()+npdu.MarshalLen():n]) != nil || a.Type != plumbing.ConfirmedReq {
				continue
			}
			r.sendReply(from, d.answer(&a))
		}
	}()
}

// answer builds the reply to one confirmed request.
func (d *CannedDevice) answer(a *plumbing.APDU) *plumbing.APDU {
	reject := func(reason uint8) *plumbing.APDU {
		return &plumbing.APDU{Type: plumbing.Reject, InvokeID: a.InvokeID, Reason: reason}
	}
	errorOf := func(class, code uint32) *plumbing.APDU {
		e := plumbing.NewAPDU(plumbing.Error, a.Service, []objects.APDUPayload{objects.EncEnumerated(class), objects.EncEnumerated(code)})
		e.InvokeID = a.InvokeID
		return e
	}
	if a.Service != services.ServiceConfirmedReadProperty {
		return reject(objects.RejectReasonUnrecognizedService)
	}
	var tags []*objects.Object
	for _, p := range a.Objects {
		if t, ok := p.(*objects.Object); ok {
			tags = append(tags, t)
		}
	}
	if len(tags) < 2 {
		return reject(objects.RejectReasonMissingRequiredParameter)
	}
	obj, err := objects.DecObjectIdentifier(tags[0])
	if err != nil {
		return reject(objects.RejectReasonInvalidParameterDataType)
	}
	var prop uint32
	for _, b := range tags[1].Data {
		prop = prop<<8 | uint32(b)
	}
	var index *uint32
	if len(tags) > 2 && tags[2].TagClass && tags[2].TagNumber == 2 {
		var i uint32
		for _, b := range tags[2].Data {
			i = i<<8 | uint32(b)
		}
		index = &i
	}
	d.mu.Lock()
	d.requests = append(d.requests, obj)
	d.mu.Unlock()
	values, fail := d.read(obj, prop, index)
	if fail != nil {
		return errorOf(fail[0], fail[1])
	}
	payload := []objects.APDUPayload{objects.EncObjectIdentifier(true, 0, obj.ObjectType, obj.InstanceNumber), objects.ContextTag(1, objects.EncUnsignedInteger(uint(prop)))}
	if index != nil {
		payload = append(payload, objects.ContextTag(2, objects.EncUnsignedInteger(uint(*index))))
	}
	payload = append(payload, objects.EncOpeningTag(3))
	for _, v := range values {
		payload = append(payload, v)
	}
	payload = append(payload, objects.EncClosingTag(3))
	ack := plumbing.NewAPDU(plumbing.ComplexAck, a.Service, payload)
	ack.InvokeID = a.InvokeID
	return ack
}

// sendReply writes one APDU to a peer in a plain envelope.
func (r *Raw) sendReply(to netip.AddrPort, a *plumbing.APDU) {
	bvlc := plumbing.NewBVLC(plumbing.BVLCFuncUnicast)
	npdu := plumbing.NewNPDU(false, false, false, false)
	b := make([]byte, bvlc.MarshalLen()+npdu.MarshalLen()+a.MarshalLen())
	bvlc.Length = uint16(len(b))
	bvlc.MarshalTo(b)
	npdu.MarshalTo(b[bvlc.MarshalLen():])
	if a.MarshalTo(b[bvlc.MarshalLen()+npdu.MarshalLen():]) != nil {
		return
	}
	r.Conn.WriteToUDPAddrPort(b, to)
}

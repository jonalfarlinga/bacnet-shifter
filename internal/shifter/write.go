package shifter

import (
	"context"
	"errors"
	"fmt"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"

	"github.com/jonalfarlinga/bacnet-shifter/internal/audit"
	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
	"github.com/jonalfarlinga/bacnet-shifter/internal/translate"
)

// SiteWriter sends one WriteProperty to a site device: the tags of the
// value, a single Null to relinquish, and the priority, 0 for none. It is
// the one method of the library client the write path needs, and the
// client fills it; the tests put a fake in its place to inject the site's
// answers. A write is sent once, never resent.
type SiteWriter interface {
	WriteProperty(ctx context.Context, to client.Address, obj client.ObjectID, prop uint16, value []*objects.Object, priority uint8) error
}

// writeRequest is a consumer's WriteProperty, parsed.
type writeRequest struct {
	obj      objects.ObjectIdentifier
	prop     uint32
	index    *uint32
	value    []*objects.Object
	priority *uint8
	// hasString says a character string is among the value's tags, at
	// any depth.
	hasString bool
}

// parseWrite reads a WriteProperty: object [0], property [1], an optional
// array index [2], the value between tags 3, and an optional priority [4].
// ans says how to refuse a request that has them wrong.
func parseWrite(tags []*objects.Object) (writeRequest, *control.Answer) {
	var w writeRequest
	obj, prop, index, ans := readHeader(tags)
	if ans != nil {
		return w, ans
	}
	w.obj, w.prop, w.index = obj, prop, index
	rest := tags[2:]
	if index != nil {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return w, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
	}
	invalidTag := &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidTag}
	if rest[0].Kind != objects.TagOpening || rest[0].TagNumber != 3 {
		return w, invalidTag
	}
	// The value runs to the closing tag 3 at its own depth; a constructed
	// value has opening and closing tags of its own inside it.
	end, depth := 0, 0
scan:
	for i := 1; i < len(rest); i++ {
		switch rest[i].Kind {
		case objects.TagOpening:
			depth++
		case objects.TagClosing:
			if depth > 0 {
				depth--
				continue
			}
			if rest[i].TagNumber != 3 {
				return w, invalidTag
			}
			end = i
			break scan
		}
	}
	if end == 0 {
		return w, invalidTag
	}
	if end == 1 {
		return w, &control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter}
	}
	w.value = rest[1:end]
	for _, t := range w.value {
		if !t.TagClass && t.Kind == objects.TagPrimitive && t.TagNumber == objects.TagCharacterString {
			w.hasString = true
		}
	}
	rest = rest[end+1:]
	if len(rest) > 0 && isContext(rest[0], 4) {
		if len(rest[0].Data) == 0 || len(rest[0].Data) > 4 {
			return w, &control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType}
		}
		p := uintOf(rest[0])
		if p > 255 {
			return w, &control.RejectOutOfRange
		}
		pr := uint8(p)
		w.priority = &pr
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return w, &control.Answer{Reject: true, Reason: objects.RejectReasonTooManyArguments}
	}
	return w, nil
}

// upstreamRules is the rewriting of a consumer's values on their way to
// the site: virtual device identifiers and addresses back to the real
// ones. missing counts what could not be mapped, a virtual device the
// shifter never issued or an address nobody is at, so that nothing is
// forwarded broken.
func (s *Shifter) upstreamRules(missing *int) translate.Rules {
	return translate.Rules{
		Device: func(virtual uint32) (uint32, bool) {
			d, ok := s.table.ByVirtual(virtual)
			if !ok {
				*missing++
				return 0, false
			}
			return d.Instance, true
		},
		Known: func(virtual uint32) bool {
			_, ok := s.table.ByVirtual(virtual)
			return ok
		},
		Network: func(vnet uint16) uint16 {
			if vnet == s.table.V() {
				return 0
			}
			if real, ok := s.table.RealNetwork(vnet); ok {
				return real
			}
			return vnet
		},
		DeviceMAC: func(virtual uint32) ([]byte, bool) {
			d, ok := s.table.ByVirtual(virtual)
			if !ok {
				return nil, false
			}
			return realMAC(d), true
		},
		MACAt: func(vnet uint16, mac []byte) ([]byte, bool) {
			d, ok := s.table.At(vnet, mac)
			if !ok {
				return nil, false
			}
			return realMAC(d), true
		},
		OnUnmapped: func(uint16, []byte) { *missing++ },
	}
}

// realMAC is a device's MAC on the site: its MAC on its routed network, or
// its six-byte BACnet/IP address.
func realMAC(d table.Device) []byte {
	a := d.Address.Client()
	if a.Routed() {
		return a.MAC
	}
	if !a.IP.IsValid() {
		return nil
	}
	ip := a.IP.Addr().As4()
	return []byte{ip[0], ip[1], ip[2], ip[3], byte(a.IP.Port() >> 8), byte(a.IP.Port())}
}

// writeOutcome names what a forwarded write came back with, for the audit
// record.
func writeOutcome(err error) string {
	var (
		be *client.BACnetError
		re *client.RejectError
		ae *client.AbortError
	)
	switch {
	case errors.As(err, &be):
		return "Error " + client.ErrorClassName(be.Class) + " " + client.ErrorCodeName(be.Code)
	case errors.As(err, &re):
		return "Reject " + objects.RejectReasonMap[re.Reason]
	case errors.As(err, &ae):
		return "Abort " + objects.AbortReasonMap[ae.Reason]
	case errors.Is(err, client.ErrTimeout):
		return "silence"
	case errors.Is(err, client.ErrNotSent):
		return "not sent: " + err.Error()
	}
	return err.Error()
}

func objectName(id objects.ObjectIdentifier) string {
	return fmt.Sprintf("%s %d", objects.ObjectTypeName(id.ObjectType), id.InstanceNumber)
}

// writeProperty applies the level's write rules to a consumer's
// WriteProperty, translates what passes and sends it through the site
// writer. The consumer gets the site's SimpleACK, Error, Reject, Abort or
// silence, as for a read; a write is never resent, so its retry after
// silence is a new request.
func (s *Shifter) writeProperty(req *server.Request, from server.Source, dev table.Device) {
	w, ans := parseWrite(req.Tags)
	if ans != nil {
		s.refuse(req, from, *ans)
		return
	}
	if s.hidden(w.obj) {
		s.refuseHidden(req, from, w.obj)
		return
	}
	real, ok := s.upstreamObject(w.obj)
	if !ok {
		s.log.Info("write to a device the shifter never issued", "from", req.Peer, "object", w.obj.InstanceNumber)
		s.unknownObject(req, from, dev, "unissued device")
		return
	}
	priority, ans2, rule := s.levelOf(req.Peer).Write(
		control.Write{Object: w.obj, Property: w.prop, Indexed: w.index != nil, Priority: w.priority, StringValue: w.hasString, Device: dev.Virtual, Source: req.Peer.IP.Addr()},
		control.WritePolicy{Reserved: s.cfg.Reserved, PassThrough: s.cfg.PassThrough, Strict: s.cfg.Strict, Allow: s.cfg.WriteAllow})
	if !ans2.Forward {
		s.refuseFor(req, from, ans2, dev, rule)
		return
	}
	values, err := translate.Decode(w.value)
	if err != nil {
		s.log.Info("refused a write whose value could not be decoded", "from", req.Peer, "object", objectName(w.obj), "property", control.PropertyName(w.prop), "error", err)
		req.Reject(from, objects.RejectReasonInvalidTag)
		return
	}
	missing := 0
	values = s.upstreamRules(&missing).Values(values)
	if missing > 0 {
		s.log.Info("the value of a write names a device or an address the shifter never issued", "from", req.Peer, "object", objectName(w.obj), "property", control.PropertyName(w.prop))
		s.refuseFor(req, from, control.Untranslatable, dev, "value names an unissued device or address")
		return
	}
	value := translate.Encode(values)

	attrs := []any{"from", req.Peer, "device", dev.Instance, "virtual", dev.Virtual, "object", objectName(real), "property", control.PropertyName(w.prop), "priority", priority}
	ctx, cancel := s.requestCtx()
	defer cancel()
	ae := s.auditEntry(req, dev, audit.EventWrite)
	ae.Priority = priority
	if err := s.writer.WriteProperty(ctx, dev.Address.Client(), toClientID(real), uint16(w.prop), value, priority); err != nil {
		if errors.Is(err, client.ErrNotSent) {
			s.log.Warn("a write never left the shifter", append(attrs, "error", err)...)
		}
		ae.Outcome = writeOutcome(err)
		s.cfg.Audit.Record(ae)
		s.fault(req, from, err)
		return
	}
	s.log.Info("write forwarded", attrs...)
	ae.Outcome = "acked"
	s.cfg.Audit.Record(ae)
	req.SimpleACK(from)
}

package shifter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/audit"
	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
)

// The COV fan-out: one upstream subscription per site object,
// shared by every consumer that subscribed to it, confirmed upstream when
// any of them asked for confirmed. Each consumer's process ID and lifetime
// are kept here, on the consumer side; every notification from the site is
// re-issued to each consumer with the virtual device identifier, that
// consumer's process ID and its own time remaining.

// Process IDs of the shifter's own subscriptions on the site: one for an
// unconfirmed subscription, another for a confirmed one, so that the
// upgrade of an object's subscription to confirmed can be made before the
// unconfirmed one is cancelled.
const (
	covProcessUnconfirmed uint32 = 1
	covProcessConfirmed   uint32 = 2
)

// covSweep is how often lapsed consumer subscriptions are dropped.
const covSweep = 10 * time.Second

// covKey names one site object: the real device and the real object.
type covKey struct {
	device uint32
	object client.ObjectID
}

// covConsumer is one consumer's subscription, as kept on the consumer side.
type covConsumer struct {
	peer      server.Peer
	process   uint32
	confirmed bool
	expires   time.Time
}

func covConsumerKey(p server.Peer, process uint32) string {
	return fmt.Sprintf("%s#%d", p.Key(), process)
}

// covEntry is the upstream subscription to one site object and the
// consumers it fans out to.
type covEntry struct {
	key    covKey
	dev    table.Device
	object client.ObjectID // real

	mu        sync.Mutex
	sub       *client.Subscription
	confirmed bool
	// gen counts the upstream subscriptions made for the entry; a
	// notification from an earlier one is dropped.
	gen       int
	consumers map[string]*covConsumer
	// last is the latest notification, replayed to a consumer that joins an
	// existing subscription, as the site would tell a new subscriber the
	// value as it is.
	last *client.COVNotification
	// dead marks an entry taken out of the map: a subscriber that holds it
	// starts over.
	dead bool
}

// covState is the fan-out table, and the counts the caps are enforced on:
// consumer subscriptions per source, upstream subscriptions per site device
// and in all. A count is reserved before the subscription is made and
// released when it goes, so that two subscriptions racing for the last
// place cannot both have it.
type covState struct {
	mu      sync.Mutex
	entries map[covKey]*covEntry

	perSource, perDevice, total, maxSources int
	bySource                                map[string]int
	byDevice                                map[uint32]int
	upstream                                int
}

func newCOVState(perSource, perDevice, total, maxSources int) *covState {
	return &covState{entries: map[covKey]*covEntry{}, perSource: perSource, perDevice: perDevice, total: total, maxSources: maxSources,
		bySource: map[string]int{}, byDevice: map[uint32]int{}}
}

// reserveConsumer counts a consumer subscription for the source, unless
// the source is at its cap, or it is a new source and as many sources
// already hold subscriptions as the shifter tracks.
func (c *covState) reserveConsumer(source string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.bySource[source]
	if n >= c.perSource || (n == 0 && len(c.bySource) >= c.maxSources) {
		return false
	}
	c.bySource[source] = n + 1
	return true
}

func (c *covState) releaseConsumer(source string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.bySource[source]; n <= 1 {
		delete(c.bySource, source)
	} else {
		c.bySource[source] = n - 1
	}
}

// reserveUpstream counts an upstream subscription to the device, unless
// the device or the site is at its cap.
func (c *covState) reserveUpstream(device uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byDevice[device] >= c.perDevice || c.upstream >= c.total {
		return false
	}
	c.byDevice[device]++
	c.upstream++
	return true
}

func (c *covState) releaseUpstream(device uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.byDevice[device]; n <= 1 {
		delete(c.byDevice, device)
	} else {
		c.byDevice[device] = n - 1
	}
	c.upstream--
}

// Counts is what the caps are enforced on: the consumer subscriptions of
// one source, the upstream subscriptions to one device, and in all.
func (c *covState) counts(source string, device uint32) (bySource, byDevice, upstream int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bySource[source], c.byDevice[device], c.upstream
}

// entry gets the fan-out of an object, making an empty one if there is
// none.
func (c *covState) entry(key covKey, dev table.Device) *covEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		e = &covEntry{key: key, dev: dev, object: key.object, consumers: map[string]*covConsumer{}}
		c.entries[key] = e
	}
	return e
}

func (c *covState) get(key covKey) *covEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[key]
}

// remove takes an entry out of the map, if it is still the one there. The
// caller holds e.mu and has marked it dead.
func (c *covState) remove(e *covEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[e.key] == e {
		delete(c.entries, e.key)
	}
}

func (c *covState) all() []*covEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := make([]*covEntry, 0, len(c.entries))
	for _, e := range c.entries {
		list = append(list, e)
	}
	return list
}

// subscribeCOV answers a consumer's SubscribeCOV: the process identifier
// [0], the object [1], and to subscribe, whether notifications are
// confirmed [2] and the lifetime [3]; without those two it is a
// cancellation.
func (s *Shifter) subscribeCOV(req *server.Request, from server.Source, dev table.Device) {
	tags := req.Tags
	if len(tags) < 2 {
		s.refuse(req, from, control.Answer{Reject: true, Reason: objects.RejectReasonMissingRequiredParameter})
		return
	}
	if !isContext(tags[0], 0) || len(tags[0].Data) == 0 || len(tags[0].Data) > 4 || !isContext(tags[1], 1) || len(tags[1].Data) != 4 {
		s.refuse(req, from, control.Answer{Reject: true, Reason: objects.RejectReasonInvalidParameterDataType})
		return
	}
	process := uintOf(tags[0])
	obj, _ := objects.DecObjectIdentifier(tags[1])
	var (
		confirmed *bool
		lifetime  *uint32
	)
	for _, t := range tags[2:] {
		switch {
		case isContext(t, 2):
			v := len(t.Data) == 1 && t.Data[0] != 0
			confirmed = &v
		case isContext(t, 3):
			l := uintOf(t)
			lifetime = &l
		}
	}
	if s.hidden(obj) {
		s.refuseHidden(req, from, obj)
		return
	}
	real, ok := s.upstreamObject(obj)
	if !ok {
		s.unknownObject(req, from, dev, "unissued device")
		return
	}
	key := covKey{device: dev.Instance, object: toClientID(real)}
	if confirmed == nil && lifetime == nil {
		s.covCancel(req, from, key, process)
		return
	}
	// A lifetime of 0 or absent, indefinite in the standard, is the ceiling;
	// a longer one is clamped to it.
	life := s.cfg.COVMaxLifetime
	if lifetime != nil && *lifetime > 0 {
		if l := time.Duration(*lifetime) * time.Second; l < life {
			life = l
		}
	}
	s.covSubscribe(req, from, dev, key, process, confirmed != nil && *confirmed, life)
}

// covSubscribe makes or renews a consumer's subscription, and the upstream
// one when it is the first, or the first to ask for confirmed.
func (s *Shifter) covSubscribe(req *server.Request, from server.Source, dev table.Device, key covKey, process uint32, confirmed bool, life time.Duration) {
	var e *covEntry
	for {
		e = s.cov.entry(key, dev)
		e.mu.Lock()
		if !e.dead {
			break
		}
		e.mu.Unlock()
	}
	defer e.mu.Unlock()

	ck := covConsumerKey(req.Peer, process)
	c, existed := e.consumers[ck]
	upstream := e.sub == nil || (confirmed && !e.confirmed)
	// The caps, before anything is made: a new consumer subscription counts
	// against its source; a first upstream subscription against the device
	// and the site. An upgrade to confirmed replaces one that is counted.
	if !existed && !s.cov.reserveConsumer(req.Peer.Key()) {
		s.covNoSpace(req, from, dev, key, "the consumer's subscriptions")
		s.covDropIfEmptyAndUnsubscribed(e)
		return
	}
	if e.sub == nil && !s.cov.reserveUpstream(dev.Instance) {
		if !existed {
			s.cov.releaseConsumer(req.Peer.Key())
		}
		s.covNoSpace(req, from, dev, key, "the site's subscriptions")
		s.covDropIfEmptyAndUnsubscribed(e)
		return
	}
	if !existed {
		c = &covConsumer{peer: req.Peer, process: process}
		e.consumers[ck] = c
	}
	c.confirmed, c.expires = confirmed, time.Now().Add(life)

	if upstream {
		if err := s.covUpstream(e, confirmed); err != nil {
			if e.sub == nil {
				s.cov.releaseUpstream(dev.Instance)
			}
			if !existed {
				s.dropConsumer(e, ck)
			}
			s.covDropIfEmptyAndUnsubscribed(e)
			s.fault(req, from, err)
			return
		}
	}
	s.log.Info("subscription", "from", req.Peer, "process", process, "device", dev.Instance, "virtual", dev.Virtual,
		"object", fmt.Sprintf("%s %d", objects.ObjectTypeName(key.object.Type), key.object.Instance),
		"confirmed", confirmed, "lifetime", life, "renewed", existed, "upstream_confirmed", e.confirmed)
	ae := s.auditEntry(req, dev, audit.EventSubscribe)
	ae.Outcome = "acked"
	ae.Detail = fmt.Sprintf("process %d, confirmed %t, lifetime %s, renewed %t", process, confirmed, life, existed)
	s.cfg.Audit.Record(ae)
	req.SimpleACK(from)
	if !upstream && e.last != nil {
		// The site tells a new subscriber the value as it is; so does the
		// shifter, from the latest notification.
		consumer, last := *c, *e.last
		s.spawn("notification", []any{"to", consumer.peer}, func() { s.covSend(e.dev, e.object, consumer, last) })
	}
}

// covNoSpace refuses a subscription past a cap and logs which.
func (s *Shifter) covNoSpace(req *server.Request, from server.Source, dev table.Device, key covKey, which string) {
	bySource, byDevice, upstream := s.cov.counts(req.Peer.Key(), dev.Instance)
	s.log.Warn("refused a subscription: a cap is reached", "from", req.Peer, "device", dev.Instance, "virtual", dev.Virtual,
		"object", fmt.Sprintf("%s %d", objects.ObjectTypeName(key.object.Type), key.object.Instance), "cap", which,
		"source_held", bySource, "device_held", byDevice, "site_held", upstream)
	s.refuseFor(req, from, control.NoSpace, dev, "subscription cap: "+which)
}

// dropConsumer takes one consumer out of an entry and releases its count.
// The caller holds e.mu.
func (s *Shifter) dropConsumer(e *covEntry, ck string) {
	c := e.consumers[ck]
	if c == nil {
		return
	}
	delete(e.consumers, ck)
	s.cov.releaseConsumer(c.peer.Key())
}

// covDropIfEmptyAndUnsubscribed takes an entry that was made for a
// subscription that did not happen out of the map. The caller holds e.mu.
func (s *Shifter) covDropIfEmptyAndUnsubscribed(e *covEntry) {
	if len(e.consumers) == 0 && e.sub == nil && !e.dead {
		e.dead = true
		s.cov.remove(e)
	}
}

// covUpstream subscribes to the object on the site, confirmed or not, and
// cancels the unconfirmed subscription a confirmed one replaces. The caller
// holds e.mu.
func (s *Shifter) covUpstream(e *covEntry, confirmed bool) error {
	process := covProcessUnconfirmed
	if confirmed {
		process = covProcessConfirmed
	}
	gen := e.gen + 1
	ctx, cancel := s.requestCtx()
	defer cancel()
	sub, err := s.site.SubscribeCOV(ctx, e.dev.Address.Client(), e.object,
		client.COVOptions{Confirmed: confirmed, Lifetime: s.cfg.COVLifetime, ProcessID: process},
		func(n client.COVNotification) {
			// On the client's read loop: it must not block.
			s.spawn("notification", []any{"device", e.dev.Instance, "object", e.object}, func() { s.covDeliver(e, gen, n) })
		})
	if err != nil {
		s.log.Info("upstream subscription refused", "device", e.dev.Instance, "object", e.object, "confirmed", confirmed, "error", err)
		return err
	}
	old := e.sub
	e.sub, e.confirmed, e.gen = sub, confirmed, gen
	s.log.Info("upstream subscription made", "device", e.dev.Instance, "object", e.object, "confirmed", confirmed, "process", process)
	if old != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.covCancelUpstream(e.dev, e.object, old)
		}()
	}
	return nil
}

// covCancelUpstream tells the site to drop one of the shifter's
// subscriptions.
func (s *Shifter) covCancelUpstream(dev table.Device, object client.ObjectID, sub *client.Subscription) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Site.Timeout*time.Duration(s.cfg.Site.Retries+1)+time.Second)
	defer cancel()
	if err := sub.Cancel(ctx); err != nil {
		s.log.Warn("upstream subscription not cancelled; it lapses on its own", "device", dev.Instance, "object", object, "error", err)
		return
	}
	s.log.Info("upstream subscription cancelled", "device", dev.Instance, "object", object)
}

// covCancel drops a consumer's subscription, and the upstream one when the
// consumer was the last.
func (s *Shifter) covCancel(req *server.Request, from server.Source, key covKey, process uint32) {
	e := s.cov.get(key)
	if e == nil {
		req.SimpleACK(from)
		return
	}
	e.mu.Lock()
	s.dropConsumer(e, covConsumerKey(req.Peer, process))
	sub := s.covDropIfEmpty(e)
	e.mu.Unlock()
	s.log.Info("subscription cancelled", "from", req.Peer, "process", process, "device", key.device, "object", key.object, "last", sub != nil)
	ae := s.auditEntry(req, e.dev, audit.EventCancel)
	ae.Outcome, ae.Detail = "acked", fmt.Sprintf("process %d, cancelled by the consumer, last %t", process, sub != nil)
	s.cfg.Audit.Record(ae)
	if sub != nil {
		s.covCancelUpstream(e.dev, e.object, sub)
	}
	req.SimpleACK(from)
}

// covDropIfEmpty takes an entry with no consumers left out of the table and
// returns its upstream subscription for the caller to cancel. The caller
// holds e.mu.
func (s *Shifter) covDropIfEmpty(e *covEntry) *client.Subscription {
	if len(e.consumers) != 0 || e.dead {
		return nil
	}
	e.dead = true
	e.gen++
	sub := e.sub
	e.sub = nil
	if sub != nil {
		s.cov.releaseUpstream(e.dev.Instance)
	}
	s.cov.remove(e)
	return sub
}

// covDeliver fans one notification from the site out to the consumers of
// its object.
func (s *Shifter) covDeliver(e *covEntry, gen int, n client.COVNotification) {
	e.mu.Lock()
	if gen != e.gen {
		e.mu.Unlock()
		return
	}
	e.last = &n
	now := time.Now()
	var targets []covConsumer
	for k, c := range e.consumers {
		if !c.expires.After(now) {
			s.dropConsumer(e, k)
			continue
		}
		targets = append(targets, *c)
	}
	dev, object := e.dev, e.object
	e.mu.Unlock()
	for _, c := range targets {
		s.spawn("notification", []any{"to", c.peer}, func() { s.covSend(dev, object, c, n) })
	}
}

// covSend re-issues one notification to one consumer, confirmed when it
// asked for confirmed.
func (s *Shifter) covSend(dev table.Device, object client.ObjectID, c covConsumer, n client.COVNotification) {
	payload := s.covPayload(dev, object, c, n)
	src := s.source(dev)
	if !c.confirmed {
		if err := s.srv.Unconfirmed(c.peer, src, services.ServiceUnconfirmedCOVNotification, payload); err != nil {
			s.log.Warn("notification not sent", "to", c.peer, "error", err)
		}
		return
	}
	reply, err := s.srv.Confirmed(s.ctx, c.peer, src, services.ServiceConfirmedCOVNotification, payload)
	switch {
	case err != nil:
		s.log.Info("confirmed notification not acknowledged", "to", c.peer, "process", c.process, "error", err)
	case reply.Type != plumbing.SimpleAck:
		s.log.Info("confirmed notification refused", "to", c.peer, "process", c.process, "type", reply.Type, "reason", reply.Reason)
	default:
		s.log.Debug("confirmed notification acknowledged", "to", c.peer, "process", c.process)
	}
}

// covPayload builds a notification for one consumer: its process ID, the
// virtual device, the object, the consumer's own time remaining, and the
// values translated.
func (s *Shifter) covPayload(dev table.Device, object client.ObjectID, c covConsumer, n client.COVNotification) []objects.APDUPayload {
	remaining := max(0, time.Until(c.expires)/time.Second)
	vobj := object
	if vobj.Type == objects.ObjectTypeDevice {
		vobj.Instance = dev.Virtual
	}
	payload := []objects.APDUPayload{
		objects.ContextTag(0, objects.EncUnsignedInteger(uint(c.process))),
		objects.EncObjectIdentifier(true, 1, objects.ObjectTypeDevice, dev.Virtual),
		objects.EncObjectIdentifier(true, 2, vobj.Type, vobj.Instance),
		objects.ContextTag(3, objects.EncUnsignedInteger(uint(remaining))),
		objects.EncOpeningTag(4),
	}
	for _, p := range n.Props {
		payload = append(payload, objects.ContextTag(0, objects.EncUnsignedInteger(uint(p.ID))))
		if p.Index != nil {
			payload = append(payload, objects.ContextTag(1, objects.EncUnsignedInteger(uint(*p.Index))))
		}
		payload = append(payload, objects.EncOpeningTag(2))
		for _, t := range encodeValues(s.downstream(dev, toObjectID(object), p.ID, p.Values)) {
			payload = append(payload, t)
		}
		payload = append(payload, objects.EncClosingTag(2))
	}
	return append(payload, objects.EncClosingTag(4))
}

// covSweeper drops lapsed consumer subscriptions, and the upstream
// subscription of an object no consumer holds any more, until the shifter
// closes.
func (s *Shifter) covSweeper() {
	ticker := time.NewTicker(covSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-s.ctx.Done():
			return
		}
		now := time.Now()
		for _, e := range s.cov.all() {
			e.mu.Lock()
			for k, c := range e.consumers {
				if !c.expires.After(now) {
					s.dropConsumer(e, k)
					s.log.Info("subscription lapsed", "from", c.peer, "process", c.process, "device", e.dev.Instance, "object", e.object)
					prefix, level := s.peerOf(c.peer)
					s.cfg.Audit.Record(audit.Entry{Event: audit.EventCancel, Peer: c.peer.String(), Prefix: prefix, Control: level.String(),
						Device: e.dev.Virtual, Real: e.dev.Instance, Object: objectName(toObjectID(e.object)), Detail: fmt.Sprintf("process %d, lapsed", c.process)})
				}
			}
			sub := s.covDropIfEmpty(e)
			e.mu.Unlock()
			if sub != nil {
				s.covCancelUpstream(e.dev, e.object, sub)
			}
		}
	}
}

// covCloseAll cancels every upstream subscription, at shutdown.
func (s *Shifter) covCloseAll() {
	var wg sync.WaitGroup
	for _, e := range s.cov.all() {
		e.mu.Lock()
		e.dead = true
		e.gen++
		sub := e.sub
		e.sub = nil
		if sub != nil {
			s.cov.releaseUpstream(e.dev.Instance)
		}
		for k := range e.consumers {
			s.dropConsumer(e, k)
		}
		s.cov.remove(e)
		e.mu.Unlock()
		if sub == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.covCancelUpstream(e.dev, e.object, sub)
		}()
	}
	wg.Wait()
}

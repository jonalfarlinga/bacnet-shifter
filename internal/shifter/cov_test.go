package shifter_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/client/sim"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
)

// notes collects the notifications of a subscription.
type notes struct {
	mu   sync.Mutex
	list []client.COVNotification
}

func (n *notes) add(note client.COVNotification) {
	n.mu.Lock()
	n.list = append(n.list, note)
	n.mu.Unlock()
}

func (n *notes) all() []client.COVNotification {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]client.COVNotification(nil), n.list...)
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var supplyAir = client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 0}

func simObject(id client.ObjectID) objects.ObjectIdentifier {
	return objects.ObjectIdentifier{ObjectType: id.Type, InstanceNumber: id.Instance}
}

// acks counts the SimpleACKs of confirmed COV notifications a peer sent the
// shifter's consumer socket.
func acks(t *testing.T, b *harness.Bench, from client.Address) int {
	t.Helper()
	n := 0
	for _, e := range b.ServerRec.Events() {
		if !e.Inbound || e.Peer != from.IP {
			continue
		}
		var bvlc plumbing.BVLC
		var npdu plumbing.NPDU
		if bvlc.UnmarshalBinary(e.Data) != nil || npdu.UnmarshalBinary(e.Data[bvlc.MarshalLen():]) != nil || npdu.Control&plumbing.NetworkLayerMessage != 0 {
			continue
		}
		var a plumbing.APDU
		if a.UnmarshalBinary(e.Data[bvlc.MarshalLen()+npdu.MarshalLen():]) != nil {
			continue
		}
		if a.Type == plumbing.SimpleAck && a.Service == services.ServiceConfirmedCOVNotification {
			n++
		}
	}
	return n
}

// Test 4: the consumer subscribes to a sim object and is notified with
// virtual identifiers and its own process ID; two consumers share one
// upstream subscription; a confirmed subscriber gets confirmed
// notifications and the shifter sees its acknowledgements; the last
// cancellation and the shifter's close empty the sim's subscriptions.
func TestCOVLimited(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.Limited})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	var ahu client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 1001 {
			ahu = d
		}
	}

	var got notes
	sub, err := b.Consumer.SubscribeCOV(ctx, ahu.Addr, supplyAir, client.COVOptions{}, got.add)
	if err != nil {
		t.Fatal(err)
	}
	// The device tells a new subscriber the value as it is; so does the
	// shifter.
	waitFor(t, "the first notification", func() bool { return len(got.all()) == 1 })
	n := got.all()[0]
	if n.Device != ahu.Instance || n.Object != supplyAir || n.ProcessID != client.DefaultCOVProcessID || n.Confirmed {
		t.Errorf("notification is %+v, want an unconfirmed one for the analog input of virtual device %d", n, ahu.Instance)
	}
	if n.From.Net != ahu.Addr.Net || string(n.From.MAC) != string(ahu.Addr.MAC) {
		t.Errorf("notification is from %v, want %v", n.From, ahu.Addr)
	}
	if n.Remaining <= 4*time.Minute || n.Remaining > client.DefaultCOVLifetime {
		t.Errorf("%s remaining, want about %s, the consumer's own lifetime", n.Remaining, client.DefaultCOVLifetime)
	}
	if len(n.Props) != 2 || n.Props[0].ID != uint32(objects.PropertyIdPresentValue) || n.Props[1].ID != uint32(objects.PropertyIdStatusFlags) {
		t.Fatalf("properties are %+v, want the present value and the status flags", n.Props)
	}
	if v := n.Props[0].Values; len(v) != 1 || v[0].Kind != client.KindReal || v[0].Float < 50 || v[0].Float > 60 {
		t.Errorf("present-value is %+v, want a real number near 55", v)
	}
	held := b.Sim.COVSubscriptions(1001)
	if len(held) != 1 || held[0].Subscriber != b.Shifter.SiteAddr() || held[0].Confirmed || held[0].Object != simObject(supplyAir) {
		t.Fatalf("the device holds %+v, want one unconfirmed subscription of the shifter's", held)
	}

	if sent := b.Sim.NotifyCOV(1001, simObject(supplyAir)); sent != 1 {
		t.Fatalf("the device notified %d subscribers, want 1", sent)
	}
	waitFor(t, "the second notification", func() bool { return len(got.all()) == 2 })

	// A second consumer, confirmed, with its own process ID: still one
	// upstream subscription, now confirmed.
	c2, _ := b.NewConsumer()
	var got2 notes
	sub2, err := c2.SubscribeCOV(ctx, ahu.Addr, supplyAir, client.COVOptions{Confirmed: true, ProcessID: 7}, got2.add)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the upstream subscription to become confirmed", func() bool {
		held := b.Sim.COVSubscriptions(1001)
		return len(held) == 1 && held[0].Confirmed
	})
	before, before2 := len(got.all()), len(got2.all())
	if sent := b.Sim.NotifyCOV(1001, simObject(supplyAir)); sent != 1 {
		t.Fatalf("the device notified %d subscribers, want 1", sent)
	}
	waitFor(t, "both consumers to be notified", func() bool { return len(got.all()) > before && len(got2.all()) > before2 })
	for _, n := range got2.all() {
		if !n.Confirmed || n.ProcessID != 7 || n.Device != ahu.Instance || n.Object != supplyAir {
			t.Errorf("the confirmed consumer got %+v", n)
		}
	}
	for _, n := range got.all() {
		if n.Confirmed || n.ProcessID != client.DefaultCOVProcessID {
			t.Errorf("the unconfirmed consumer got %+v", n)
		}
	}
	// The shifter acknowledged the confirmed notification upstream, and saw
	// the confirmed consumer's acknowledgement.
	waitFor(t, "the acknowledgements", func() bool {
		held := b.Sim.COVSubscriptions(1001)
		return len(held) == 1 && held[0].Acked >= 1 && acks(t, b, client.Address{IP: c2.Local()}) >= len(got2.all())
	})

	// The first consumer leaves: the upstream subscription stays for the
	// second.
	if err := sub.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 1 {
		t.Errorf("after one cancellation the device holds %+v, want one subscription", held)
	}
	if sent := b.Sim.NotifyCOV(1001, simObject(supplyAir)); sent != 1 {
		t.Fatalf("the device notified %d subscribers, want 1", sent)
	}
	count := len(got.all())
	time.Sleep(200 * time.Millisecond)
	if len(got.all()) != count {
		t.Error("the consumer that cancelled was notified")
	}
	// The last one out cancels upstream.
	if err := sub2.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 0 {
		t.Errorf("after the last cancellation the device holds %+v", held)
	}
	// Cancelling again is harmless.
	if err := b.Consumer.CancelCOV(ctx, ahu.Addr, supplyAir, 1); err != nil {
		t.Errorf("a cancellation of nothing gave %v", err)
	}

	// An object that takes no subscription answers as the site did.
	_, err = b.Consumer.SubscribeCOV(ctx, ahu.Addr, client.ObjectID{Type: objects.ObjectTypeSchedule}, client.COVOptions{}, got.add)
	var be *client.BACnetError
	if !errors.As(err, &be) || be.Class != uint32(objects.ErrorClassServices) || be.Code != 45 {
		t.Errorf("subscribing to the schedule gave %v, want services: optional functionality not supported", err)
	}
	_, err = b.Consumer.SubscribeCOV(ctx, ahu.Addr, client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: 99}, client.COVOptions{}, got.add)
	if !errors.As(err, &be) || be.Code != client.ErrorCodeUnknownObject {
		t.Errorf("subscribing to an unknown object gave %v, want unknown object", err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 0 {
		t.Errorf("a refused subscription left %+v on the device", held)
	}

	// Closing the shifter cancels what it holds.
	if _, err := b.Consumer.SubscribeCOV(ctx, ahu.Addr, supplyAir, client.COVOptions{}, got.add); err != nil {
		t.Fatal(err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 1 {
		t.Fatalf("the device holds %+v, want one subscription", held)
	}
	if err := b.Shifter.Close(); err != nil {
		t.Error(err)
	}
	b.Shifter = nil
	if held := b.Sim.COVSubscriptions(1001); len(held) != 0 {
		t.Errorf("after the shifter closed the device holds %+v", held)
	}
}

// A subscription on a device behind a site router works like one on the
// subnet, and a consumer that renews keeps its subscription.
func TestCOVRoutedAndRenewed(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.Limited})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	var vav client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 2101 {
			vav = d
		}
	}
	if vav.Addr.Net == 9000 {
		t.Fatalf("device 2101 is on V at %v", vav.Addr)
	}
	var got notes
	sub, err := b.Consumer.SubscribeCOV(ctx, vav.Addr, supplyAir, client.COVOptions{Lifetime: 2 * time.Second}, got.add)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first notification", func() bool { return len(got.all()) == 1 })
	if n := got.all()[0]; n.Device != vav.Instance || n.From.Net != vav.Addr.Net {
		t.Errorf("notification %+v, want one from virtual device %d on network %d", n, vav.Instance, vav.Addr.Net)
	}
	if held := b.Sim.COVSubscriptions(2101); len(held) != 1 {
		t.Fatalf("device 2101 holds %+v", held)
	}
	// The client renews at half the lifetime; the shifter keeps the
	// consumer and the upstream subscription.
	time.Sleep(2500 * time.Millisecond)
	if st := sub.Status(); st.Err != nil || st.Renewed.IsZero() {
		t.Errorf("status %+v", st)
	}
	if held := b.Sim.COVSubscriptions(2101); len(held) != 1 {
		t.Errorf("after renewals device 2101 holds %+v", held)
	}
	b.Sim.NotifyCOV(2101, simObject(supplyAir))
	waitFor(t, "a notification after the renewals", func() bool { return len(got.all()) >= 2 })
	if err := sub.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	if held := b.Sim.COVSubscriptions(2101); len(held) != 0 {
		t.Errorf("after the cancellation device 2101 holds %+v", held)
	}
}

// At no-write a SubscribeCOV is refused and nothing reaches the site.
func TestCOVRefusedAtNoWrite(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.NoWrite})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	var ahu client.Device
	for _, d := range heard {
		if realOf(t, b, d).Instance == 1001 {
			ahu = d
		}
	}
	_, err := b.Consumer.SubscribeCOV(b.Ctx(), ahu.Addr, supplyAir, client.COVOptions{}, func(client.COVNotification) {})
	var be *client.BACnetError
	if !errors.As(err, &be) || be.Class != uint32(objects.ErrorClassServices) || be.Code != uint32(objects.ErrorCodeServiceRequestDenied) {
		t.Errorf("SubscribeCOV at no-write gave %v, want services: service request denied", err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 0 {
		t.Errorf("the device holds %+v", held)
	}
	_ = sim.Default
}

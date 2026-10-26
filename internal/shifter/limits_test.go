package shifter_test

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
)

// The P1 tests: the shifter under a flood, a reflection attempt, the
// subscription caps, a flood of site devices, and a device that claims a
// known instance from a new address.

// deviceByReal finds the virtual device of a real instance among those the
// consumer heard.
func deviceByReal(t *testing.T, b *harness.Bench, heard map[uint32]client.Device, real uint32) client.Device {
	t.Helper()
	for _, d := range heard {
		if realOf(t, b, d).Instance == real {
			return d
		}
	}
	t.Fatalf("real device %d was not heard", real)
	return client.Device{}
}

// countIAms counts the I-Ams a raw socket receives within the wait.
func countIAms(t *testing.T, raw *harness.Raw, wait time.Duration) int {
	t.Helper()
	n := 0
	deadline := time.Now().Add(wait)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return n
		}
		rcv := raw.Receive(t, left)
		if rcv == nil {
			return n
		}
		if rcv.APDU != nil && rcv.APDU.Type == plumbing.UnConfirmedReq && rcv.APDU.Service == services.ServiceUnconfirmedIAm {
			n++
		}
	}
}

// A burst of thousands of Who-Is and ReadProperty datagrams from dozens of
// source ports: the goroutine count and the heap stay under a fixed bound,
// the rate limit and the in-flight cap are seen to drop, and an ordinary
// consumer read succeeds afterwards within the usual timeout.
func TestFloodBounded(t *testing.T) {
	const sources, each = 40, 100
	b := harness.Start(t, harness.Options{Configure: func(cfg *shifter.Config) {
		cfg.Consumer.MaxRPSPerSource = 20
		cfg.Consumer.MaxInFlight = 8
	}})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ahu := deviceByReal(t, b, heard, 1001)
	to := b.Shifter.ConsumerAddr()

	var senders []*harness.Raw
	for range sources {
		senders = append(senders, harness.NewRaw(t))
	}
	whoIs := plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil)
	plain := plumbing.NewNPDU(false, false, false, false)
	read := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedReadProperty,
		services.ConfirmedReadPropertyObjects(objects.ObjectTypeDevice, ahu.Instance, objects.PropertyIdObjectList))
	read.MaxSize = 5
	read.SetAPDUFlags(true, false, false)
	routed := harness.NPDUTo(ahu.Addr.Net, ahu.Addr.MAC, 0, nil, true)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	baseline := runtime.NumGoroutine()
	peakGoroutines, peakHeap := 0, uint64(0)
	sample := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		peakGoroutines = max(peakGoroutines, runtime.NumGoroutine())
		peakHeap = max(peakHeap, m.HeapAlloc)
	}
	for i := range each {
		for j, raw := range senders {
			read.InvokeID = uint8(i)
			if (i+j)%2 == 0 {
				raw.Send(t, to, plain, whoIs)
			} else {
				raw.Send(t, to, routed, read)
			}
		}
		if i%10 == 0 {
			sample()
		}
	}
	sample()
	time.Sleep(200 * time.Millisecond)
	sample()

	const goroutineBound, heapBound = 250, 64 << 20
	if peakGoroutines > baseline+goroutineBound {
		t.Errorf("%d goroutines at the peak, %d before the flood: more than %d over", peakGoroutines, baseline, goroutineBound)
	}
	if peakHeap > before.HeapAlloc+heapBound {
		t.Errorf("%d bytes of heap at the peak, %d before the flood: more than %d over", peakHeap, before.HeapAlloc, heapBound)
	}
	srv, _, _ := b.Shifter.Dropped()
	if srv.Rate == 0 || srv.InFlight == 0 {
		t.Errorf("the flood was not bounded: %d dropped by rate, %d at the in-flight cap", srv.Rate, srv.InFlight)
	}
	if srv.Panics != 0 {
		t.Errorf("%d handler panics during the flood", srv.Panics)
	}
	t.Logf("flood of %d datagrams: %d dropped by rate, %d at the in-flight cap; %d goroutines and %d bytes at the peak over %d and %d",
		sources*each, srv.Rate, srv.InFlight, peakGoroutines-baseline, peakHeap-before.HeapAlloc, baseline, before.HeapAlloc)

	// Then an ordinary read, from an address that was not in the flood.
	values, err := b.Consumer.ReadProperty(b.Ctx(), ahu.Addr, deviceObject(ahu.Instance), objects.PropertyIdObjectName)
	if err != nil || len(values) != 1 {
		t.Fatalf("a read after the flood: %+v, %v", values, err)
	}
}

// Whoever a Who-Is names as its source gets one I-Am per device per
// whois_interval, however many Who-Is arrive.
func TestReflectionBounded(t *testing.T) {
	const interval = 500 * time.Millisecond
	b := harness.Start(t, harness.Options{WhoIsInterval: interval})
	b.AwaitDevices(simDevices, 10*time.Second)
	raw := harness.NewRaw(t)
	whoIs := plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil)
	plain := plumbing.NewNPDU(false, false, false, false)
	for range 30 {
		raw.Send(t, b.Shifter.ConsumerAddr(), plain, whoIs)
	}
	if n := countIAms(t, raw, interval/2); n != simDevices {
		t.Errorf("%d I-Ams for 30 Who-Is in a burst, want %d: one per device", n, simDevices)
	}
	time.Sleep(interval)
	raw.Send(t, b.Shifter.ConsumerAddr(), plain, whoIs)
	if n := countIAms(t, raw, interval/2); n != simDevices {
		t.Errorf("%d I-Ams for a Who-Is after the interval, want %d", n, simDevices)
	}
}

// noSpace reports whether err is the Error the caps refuse with.
func noSpace(err error) bool {
	var be *client.BACnetError
	return errors.As(err, &be) && be.Class == uint32(control.NoSpace.Class) && be.Code == uint32(control.NoSpace.Code)
}

// The subscription caps: per site device, for the whole site, and per
// consumer source, each refused with Error resources, no-space-to-add-
// list-element; a cancellation gives the place back; and the site device
// never holds more than its cap.
func TestSubscriptionCaps(t *testing.T) {
	b := harness.Start(t, harness.Options{Control: control.Limited, Configure: func(cfg *shifter.Config) {
		cfg.MaxSubscriptionsPerSource = 3
		cfg.MaxSubscriptionsPerDevice = 2
		cfg.MaxSubscriptions = 4
	}})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ctx := b.Ctx()
	ahu, meter, boiler, plant := deviceByReal(t, b, heard, 1001), deviceByReal(t, b, heard, 3000), deviceByReal(t, b, heard, 4000), deviceByReal(t, b, heard, 2000)
	ai := func(i uint32) client.ObjectID {
		return client.ObjectID{Type: objects.ObjectTypeAnalogInput, Instance: i}
	}
	a := b.Consumer
	none := func(client.COVNotification) {}

	sub1, err := a.SubscribeCOV(ctx, ahu.Addr, ai(0), client.COVOptions{}, none)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SubscribeCOV(ctx, ahu.Addr, ai(1), client.COVOptions{}, none); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SubscribeCOV(ctx, ahu.Addr, ai(2), client.COVOptions{}, none); !noSpace(err) {
		t.Errorf("a third object of one device: %v, want the no-space Error", err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 2 {
		t.Errorf("the device holds %d subscriptions, want 2, the cap", len(held))
	}
	if _, err := a.SubscribeCOV(ctx, meter.Addr, ai(0), client.COVOptions{}, none); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SubscribeCOV(ctx, boiler.Addr, ai(0), client.COVOptions{}, none); !noSpace(err) {
		t.Errorf("a fourth subscription from one source: %v, want the no-space Error", err)
	}

	c, _ := b.NewConsumer()
	if _, err := c.SubscribeCOV(ctx, boiler.Addr, ai(0), client.COVOptions{}, none); err != nil {
		t.Fatalf("another source, the fourth upstream subscription: %v", err)
	}
	if _, err := c.SubscribeCOV(ctx, plant.Addr, ai(0), client.COVOptions{}, none); !noSpace(err) {
		t.Errorf("a fifth upstream subscription: %v, want the no-space Error", err)
	}
	if err := sub1.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubscribeCOV(ctx, ahu.Addr, ai(0), client.COVOptions{}, none); err != nil {
		t.Errorf("after a cancellation the place is not given back: %v", err)
	}
	// Joining an existing subscription costs the site nothing, but counts
	// for the source.
	if _, err := c.SubscribeCOV(ctx, ahu.Addr, ai(1), client.COVOptions{}, none); err != nil {
		t.Errorf("joining an existing subscription: %v", err)
	}
	if _, err := c.SubscribeCOV(ctx, meter.Addr, ai(0), client.COVOptions{}, none); !noSpace(err) {
		t.Errorf("a fourth subscription from the second source: %v, want the no-space Error", err)
	}
	if held := b.Sim.COVSubscriptions(1001); len(held) != 2 {
		t.Errorf("the device holds %d subscriptions at the end, want 2", len(held))
	}
}

// A thousand I-Ams for distinct instances in a burst: the table admits at
// most the configured rate, the file is written at most once a second, and
// the consumer side is told of at most that many devices.
func TestSiteFloodBounded(t *testing.T) {
	const perMinute, flood = 20, 1000
	b := harness.Start(t, harness.Options{Configure: func(cfg *shifter.Config) { cfg.MaxNewDevicesPerMinute = perMinute }})
	b.AwaitDevices(simDevices, 10*time.Second)
	tb := b.Shifter.Table()
	writesBefore := tb.Writes()

	site := harness.NewRaw(t)
	site.AnswerWithError(t, uint32(objects.ErrorClassObject), uint32(control.ErrorCodeUnknownObject))
	start := time.Now()
	for i := uint32(0); i < flood; i++ {
		site.SendIAm(t, b.Shifter.SiteAddr(), 500000+i)
	}
	// Each admitted device costs one name read, answered at once.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, dropped, _ := b.Shifter.Dropped(); dropped >= flood-perMinute {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	elapsed := int(time.Since(start)/time.Second) + 1
	_, dropped, _ := b.Shifter.Dropped()
	admitted := len(tb.Devices(0)) - simDevices
	if admitted > perMinute+elapsed || admitted < 1 {
		t.Errorf("%d of %d flooded devices admitted in %d seconds, want at most %d plus the refill", admitted, flood, elapsed, perMinute)
	}
	if dropped+admitted != flood {
		t.Errorf("%d dropped and %d admitted, want %d together", dropped, admitted, flood)
	}
	if writes := tb.Writes() - writesBefore; writes > elapsed+1 {
		t.Errorf("the table was written %d times in %d seconds, want at most one a second", writes, elapsed)
	}

	consumer := harness.NewRaw(t)
	consumer.Send(t, b.Shifter.ConsumerAddr(), plumbing.NewNPDU(false, false, false, false),
		plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil))
	if n := countIAms(t, consumer, 500*time.Millisecond); n != simDevices+admitted {
		t.Errorf("the consumer side sees %d devices, want %d: the sim's and the admitted", n, simDevices+admitted)
	}
	t.Logf("%d admitted, %d dropped, %d table writes in %d seconds", admitted, dropped, tb.Writes()-writesBefore, elapsed)
}

// An I-Am that claims a known instance from a new address, when the device
// was not heard this run, is believed only once the old address is silent.
func TestMoveConfirmed(t *testing.T) {
	const instance = 7001
	dir := t.TempDir()
	old := harness.NewRaw(t)
	old.AnswerWithError(t, uint32(objects.ErrorClassProperty), uint32(control.ErrorCodeUnknownProperty))
	key, _, err := pseudonym.LoadOrCreate(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	tb, err := table.Open(filepath.Join(dir, "table.json"), pseudonym.New(key), 9000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.EnsureDevice(client.Device{Instance: instance, Addr: client.Address{IP: old.Local()}, MaxAPDU: 1476, VendorID: 999}); err != nil {
		t.Fatal(err)
	}
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}

	b := harness.Start(t, harness.Options{DataDir: dir})
	b.AwaitDevices(simDevices, 10*time.Second)
	claimant := harness.NewRaw(t)
	claimant.AnswerWithError(t, uint32(objects.ErrorClassProperty), uint32(control.ErrorCodeUnknownProperty))
	claimant.SendIAm(t, b.Shifter.SiteAddr(), instance)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, moves := b.Shifter.Dropped(); moves == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, moves := b.Shifter.Dropped(); moves != 1 {
		t.Fatalf("%d moves refused, want 1: the old address answered", moves)
	}
	if d, _ := b.Shifter.Table().Device(instance); d.Address.IP != old.Local().String() {
		t.Errorf("the device is now at %s, want the old address %s kept", d.Address.IP, old.Local())
	}

	// The old address goes silent: the claim is believed.
	old.Conn.Close()
	claimant.SendIAm(t, b.Shifter.SiteAddr(), instance)
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if d, _ := b.Shifter.Table().Device(instance); d.Address.IP == claimant.Local().String() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if d, _ := b.Shifter.Table().Device(instance); d.Address.IP != claimant.Local().String() {
		t.Errorf("the device is at %s, want the new address %s once the old is silent", d.Address.IP, claimant.Local())
	}
}

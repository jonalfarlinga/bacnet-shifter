package shifter_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
	"github.com/jonalfarlinga/bacnet-shifter/internal/translate"
)

// siteObject is what was read directly from one object of the site.
type siteObject struct {
	id    client.ObjectID
	props map[uint16]string // the string properties read, by property
	errs  map[uint16]error
}

// siteDevice is what was read directly from one device of the site.
type siteDevice struct {
	dev     client.Device
	name    string
	list    []client.ObjectID
	objects []siteObject
}

// TestSmokeBench runs the shifter against a real site on the adapter named
// by SHIFTER_SMOKE_ADAPTER, with the consumer side on loopback. It first
// reads the site directly on port 47808, then closes that client, starts
// the shifter on the same port, and checks that every device comes through
// under a pseudonym, that object lists and errors match, and that nothing
// real crosses the consumer socket. Devices answer to port 47808, so the
// two phases cannot overlap. It is skipped unless the variable is set.
func TestSmokeBench(t *testing.T) {
	adapter := os.Getenv("SHIFTER_SMOKE_ADAPTER")
	if adapter == "" {
		t.Skip("set SHIFTER_SMOKE_ADAPTER to the name or address of the site adapter to run against a real site")
	}
	ifc, err := client.FindInterface(adapter)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	sampled := []uint16{objects.PropertyIdObjectName, objects.PropertyIdDescription}

	// Phase 1: the site, directly.
	var mu sync.Mutex
	realHeard := map[uint32]client.Device{}
	direct := ifc.Config(client.DefaultPort)
	direct.Timeout, direct.Retries = 3*time.Second, 2
	direct.OnIAm = func(d client.Device) { mu.Lock(); realHeard[d.Instance] = d; mu.Unlock() }
	dc, err := client.Open(direct)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := dc.WhoIs(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
	}
	mu.Lock()
	devices := make([]client.Device, 0, len(realHeard))
	for _, d := range realHeard {
		devices = append(devices, d)
	}
	mu.Unlock()
	if len(devices) == 0 {
		dc.Close()
		t.Fatalf("no device answered a Who-Is on %s", adapter)
	}
	var site []siteDevice
	for _, dev := range devices {
		sd := siteDevice{dev: dev}
		name, err := dc.ReadProperty(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectName)
		if err != nil || len(name) != 1 {
			t.Errorf("device %d at %v: name: %+v, %v", dev.Instance, dev.Addr, name, err)
			continue
		}
		sd.name = name[0].Str
		if sd.list, err = dc.ReadObjectList(ctx, dev, nil); err != nil {
			t.Errorf("device %d: object list: %v", dev.Instance, err)
			continue
		}
		for i, obj := range sd.list {
			if i >= 12 {
				break
			}
			so := siteObject{id: obj, props: map[uint16]string{}, errs: map[uint16]error{}}
			for _, prop := range sampled {
				v, err := dc.ReadProperty(ctx, dev.Addr, obj, prop)
				so.errs[prop] = err
				if err == nil && len(v) == 1 && v[0].Kind == client.KindString {
					so.props[prop] = v[0].Str
				}
			}
			sd.objects = append(sd.objects, so)
		}
		t.Logf("site: device %d %q at %v, %d objects", dev.Instance, sd.name, dev.Addr, len(sd.list))
		site = append(site, sd)
	}
	dc.Close()

	// Phase 2: through the shifter.
	dir := t.TempDir()
	key, _, err := pseudonym.LoadOrCreate(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	tb, err := table.Open(filepath.Join(dir, "table.json"), pseudonym.New(key), 9000)
	if err != nil {
		t.Fatal(err)
	}
	serverRec := &recorder{}
	siteCfg := ifc.Config(client.DefaultPort)
	siteCfg.Timeout, siteCfg.Retries = 3*time.Second, 2
	sh, err := shifter.Start(shifter.Config{
		Site:     siteCfg,
		Consumer: server.Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: time.Second, Retries: 1, OnPacket: serverRec.OnPacket},
		Table:    tb,
		Control:  control.Limited,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	heard := map[uint32]client.Device{}
	consumer, err := client.Open(client.Config{
		Local: netip.MustParseAddrPort("127.0.0.1:0"), Broadcast: sh.ConsumerAddr(), Timeout: 3 * time.Second, Retries: 2,
		OnIAm: func(d client.Device) { mu.Lock(); heard[d.Instance] = d; mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		consumer.WhoIs()
		time.Sleep(time.Second)
		mu.Lock()
		n := len(heard)
		mu.Unlock()
		if n >= len(site) {
			break
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(heard) != len(site) {
		t.Errorf("%d devices through the shifter, %d directly", len(heard), len(site))
	}

	var leak secrets
	byReal := map[uint32]client.Device{}
	for virtual, dev := range heard {
		rec, ok := tb.ByVirtual(virtual)
		if !ok {
			t.Fatalf("virtual device %d is not in the table", virtual)
		}
		byReal[rec.Instance] = dev
		if dev.Addr.IP != sh.ConsumerAddr() || dev.Addr.Net != 9000 || len(dev.Addr.MAC) != 2 {
			t.Errorf("device %d is announced at %v, want a routed address on 9000 through the shifter", rec.Instance, dev.Addr)
		}
	}
	for _, sd := range site {
		leak.addString(sd.name)
		leak.bytes = append(leak.bytes, encodedDeviceID(sd.dev.Instance))
		if !sd.dev.Addr.Routed() {
			ip := sd.dev.Addr.IP.Addr().As4()
			leak.bytes = append(leak.bytes, append(ip[:], byte(sd.dev.Addr.IP.Port()>>8), byte(sd.dev.Addr.IP.Port())))
		}
		dev, ok := byReal[sd.dev.Instance]
		if !ok {
			t.Errorf("device %d did not come through the shifter", sd.dev.Instance)
			continue
		}
		name, err := consumer.ReadProperty(ctx, dev.Addr, deviceObject(dev.Instance), objects.PropertyIdObjectName)
		if err != nil || len(name) != 1 {
			t.Errorf("device %d: name through the shifter: %+v, %v", sd.dev.Instance, name, err)
			continue
		}
		t.Logf("device %d %q at %v -> virtual %d %q at %v", sd.dev.Instance, sd.name, sd.dev.Addr, dev.Instance, name[0].Str, dev.Addr)
		if name[0].Str == sd.name || name[0].Str == "" {
			t.Errorf("device %d: the name %q came through unchanged", sd.dev.Instance, sd.name)
		}
		viaList, err := consumer.ReadObjectList(ctx, dev, nil)
		if err != nil {
			t.Errorf("device %d: object list through the shifter: %v", sd.dev.Instance, err)
			continue
		}
		if len(viaList) != len(sd.list) {
			t.Errorf("device %d: %d objects through the shifter, %d direct", sd.dev.Instance, len(viaList), len(sd.list))
			continue
		}
		for i := range sd.list {
			want := sd.list[i]
			if want.Type == objects.ObjectTypeDevice && want.Instance != translate.Wildcard {
				want.Instance = dev.Instance
			}
			if viaList[i] != want {
				t.Errorf("device %d: object %d is %v through the shifter, want %v", sd.dev.Instance, i, viaList[i], want)
			}
		}
		for i, so := range sd.objects {
			for _, prop := range sampled {
				vv, vErr := consumer.ReadProperty(ctx, dev.Addr, viaList[i], prop)
				if !sameOutcome(so.errs[prop], vErr) {
					t.Errorf("device %d, object %v, property %d: direct %v, through the shifter %v", sd.dev.Instance, so.id, prop, so.errs[prop], vErr)
					continue
				}
				real, has := so.props[prop]
				if !has || real == "" {
					continue
				}
				leak.addString(real)
				if len(vv) != 1 || vv[0].Str == real || vv[0].Str == "" {
					t.Errorf("device %d, object %v, property %d: %q came through as %+v", sd.dev.Instance, so.id, prop, real, vv)
				} else {
					t.Logf("  %v property %d: %q -> %q", so.id, prop, real, vv[0].Str)
				}
			}
		}
	}
	// A subscription to the first object with a present value of each
	// device, when the device takes one: the notification carries the
	// virtual identifiers and the consumer's process ID.
	for _, sd := range site {
		dev, ok := byReal[sd.dev.Instance]
		if !ok {
			continue
		}
		var target *client.ObjectID
		for _, obj := range sd.list {
			switch obj.Type {
			case objects.ObjectTypeAnalogInput, objects.ObjectTypeAnalogOutput, objects.ObjectTypeAnalogValue,
				objects.ObjectTypeBinaryInput, objects.ObjectTypeBinaryOutput, objects.ObjectTypeBinaryValue,
				objects.ObjectTypeMultiStateInput, objects.ObjectTypeMultiStateOutput, objects.ObjectTypeMultiStateValue:
				o := obj
				target = &o
			}
			if target != nil {
				break
			}
		}
		if target == nil {
			t.Logf("device %d: no object to subscribe to", sd.dev.Instance)
			continue
		}
		var got notes
		sub, err := consumer.SubscribeCOV(ctx, dev.Addr, *target, client.COVOptions{ProcessID: 9, Lifetime: time.Minute}, got.add)
		if err != nil {
			t.Logf("device %d: SubscribeCOV to %v through the shifter: %v (the device's own answer, or no answer)", sd.dev.Instance, *target, err)
			continue
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(got.all()) == 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if n := got.all(); len(n) == 0 {
			t.Errorf("device %d: subscribed to %v but no notification came", sd.dev.Instance, *target)
		} else {
			t.Logf("device %d: notification from virtual device %d for %v, process %d, %d properties, %s remaining",
				sd.dev.Instance, n[0].Device, n[0].Object, n[0].ProcessID, len(n[0].Props), n[0].Remaining)
			if n[0].Device != dev.Instance || n[0].ProcessID != 9 || n[0].Object != *target {
				t.Errorf("device %d: notification %+v carries the wrong identifiers", sd.dev.Instance, n[0])
			}
		}
		if err := sub.Cancel(ctx); err != nil {
			t.Errorf("device %d: Cancel: %v", sd.dev.Instance, err)
		}
	}
	checkLeak(t, serverRec.Events(), leak)
	t.Logf("the table holds %d records", len(tb.Listing("")))
}

type recorder struct {
	mu     sync.Mutex
	events []client.PacketEvent
}

func (r *recorder) OnPacket(e client.PacketEvent) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) Events() []client.PacketEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]client.PacketEvent(nil), r.events...)
}

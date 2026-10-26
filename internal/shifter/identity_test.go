package shifter_test

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"
	"github.com/jonalfarlinga/bacnet/services"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
	"github.com/jonalfarlinga/bacnet-shifter/internal/server"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
)

// The P3 tests: who is served, and at what level.

// A source outside consumer.allow gets nothing, and the drop is counted;
// one inside is served.
func TestConsumerAllowList(t *testing.T) {
	outside := harness.Start(t, harness.Options{Configure: func(cfg *shifter.Config) {
		cfg.Consumer.Allow = []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}
	}})
	for range 5 {
		if err := outside.Consumer.WhoIs(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if heard := outside.Heard(); len(heard) != 0 {
		t.Errorf("a consumer outside the allow list heard %d devices", len(heard))
	}
	if srv, _, _ := outside.Shifter.Dropped(); srv.Allow < 5 {
		t.Errorf("%d datagrams dropped by the allow list, want at least the 5 Who-Is", srv.Allow)
	}
	outside.Close()

	inside := harness.Start(t, harness.Options{Configure: func(cfg *shifter.Config) {
		cfg.Consumer.Allow = []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("127.0.0.1/32")}
	}})
	inside.AwaitDevices(simDevices, 10*time.Second)
	if srv, _, _ := inside.Shifter.Dropped(); srv.Allow != 0 {
		t.Errorf("%d datagrams dropped from a consumer inside the allow list", srv.Allow)
	}
}

// Two consumers from two prefixes under a global full-service: the one
// listed at no-write gets the documented refusals for a write and a
// subscription, the one listed at full-service and the one listed nowhere
// get them forwarded; and an entry above the global level is refused at
// start.
func TestPeerLevels(t *testing.T) {
	fake := &harness.FakeWriter{}
	b := harness.Start(t, harness.Options{Control: control.FullService, Writer: fake, Configure: func(cfg *shifter.Config) {
		cfg.Peers = []shifter.Peer{
			{Prefix: netip.MustParsePrefix("127.0.0.2/32"), Control: control.NoWrite},
			{Prefix: netip.MustParsePrefix("127.0.0.3/32"), Control: control.FullService},
		}
	}})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ahu := deviceByReal(t, b, heard, 1001)
	to := b.Shifter.ConsumerAddr()
	setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
	npdu := func() *plumbing.NPDU { return harness.NPDUTo(ahu.Addr.Net, ahu.Addr.MAC, 0, nil, true) }
	write := func(invoke uint8) *plumbing.APDU {
		return writeAPDU(invoke, setpoint, objects.PropertyIdPresentValue, nil, []objects.APDUPayload{objects.EncReal(21)}, nil)
	}
	subscribe := func(invoke uint8) *plumbing.APDU {
		a := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedSubscribeCOV, services.COVObjects(1, objects.ObjectTypeAnalogInput, 0, false, 60))
		a.InvokeID, a.MaxSize = invoke, 5
		a.SetAPDUFlags(true, false, false)
		return a
	}
	denied := func(got *harness.Received) bool {
		if got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
			return false
		}
		class, code := errorOf(got.APDU)
		return class == uint32(objects.ErrorClassServices) && code == uint32(objects.ErrorCodeServiceRequestDenied)
	}
	acked := func(got *harness.Received) bool {
		return got != nil && got.APDU != nil && got.APDU.Type == plumbing.SimpleAck
	}

	reader := harness.NewRawAt(t, netip.MustParseAddr("127.0.0.2"))
	writer := harness.NewRawAt(t, netip.MustParseAddr("127.0.0.3"))
	unlisted := harness.NewRaw(t)
	if got := reader.Exchange(t, to, npdu(), write(1), time.Second); !denied(got) {
		t.Errorf("a write from the no-write peer got %s, want service-request-denied", answer(got))
	}
	if got := reader.Exchange(t, to, npdu(), subscribe(2), time.Second); !denied(got) {
		t.Errorf("a subscription from the no-write peer got %s, want service-request-denied", answer(got))
	}
	if n := len(fake.Calls()); n != 0 {
		t.Errorf("%d writes reached the site from the no-write peer", n)
	}
	if got := writer.Exchange(t, to, npdu(), write(3), time.Second); !acked(got) {
		t.Errorf("a write from the full-service peer got %s, want SimpleACK", answer(got))
	}
	if got := unlisted.Exchange(t, to, npdu(), write(4), time.Second); !acked(got) {
		t.Errorf("a write from an unlisted source, at the global level, got %s, want SimpleACK", answer(got))
	}
	if got := unlisted.Exchange(t, to, npdu(), subscribe(5), time.Second); !acked(got) {
		t.Errorf("a subscription from an unlisted source got %s, want SimpleACK", answer(got))
	}
	if n := len(fake.Calls()); n != 2 {
		t.Errorf("%d writes reached the site, want 2", n)
	}

	// An entry above the ceiling does not start.
	dir := t.TempDir()
	key, _, err := pseudonym.LoadOrCreate(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	tb, err := table.Open("", pseudonym.New(key), 9000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = shifter.Start(shifter.Config{
		Site:     client.Config{Local: netip.MustParseAddrPort("127.0.0.1:0")},
		Consumer: server.Config{Local: netip.MustParseAddrPort("127.0.0.1:0")},
		Control:  control.Limited, Reserved: control.DefaultReserved(), Table: tb,
		Peers: []shifter.Peer{{Prefix: netip.MustParsePrefix("10.8.0.0/24"), Control: control.FullService}},
	})
	if err == nil || !strings.Contains(err.Error(), "above control") {
		t.Errorf("a peer above the ceiling started: %v", err)
	}
}

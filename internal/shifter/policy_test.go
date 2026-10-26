package shifter_test

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"
	"github.com/jonalfarlinga/bacnet/plumbing"

	"github.com/jonalfarlinga/bacnet-shifter/internal/audit"
	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
)

// The P4 tests: the write allow list, and the audit log read back.

// readAudit reads the audit file into entries.
func readAudit(t *testing.T, path string) []audit.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var entries []audit.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	return entries
}

// Test 8 with the allow list: a write is forwarded only when an entry
// covers its object type, property, device and consumer; the reserved set
// stays the floor under an entry; and the audit file holds one line per
// forwarded write with its outcome and one per refusal with its rule, the
// start line, and the subscription made and cancelled.
func TestWriteAllowListAndAudit(t *testing.T) {
	fake := &harness.FakeWriter{}
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	var ahuVirtual uint32
	b := harness.Start(t, harness.Options{Control: control.FullService, Writer: fake, Audit: auditFile, Configure: func(cfg *shifter.Config) {
		// The AHU's virtual instance is known before it is heard: the
		// table issues it on reference.
		d, err := cfg.Table.Reference(1001)
		if err != nil {
			t.Fatal(err)
		}
		ahuVirtual = d.Virtual
		cfg.WriteAllow = control.WriteAllow{
			{Object: objects.ObjectTypeAnalogValue, Property: uint32(objects.PropertyIdPresentValue)},
			{Object: objects.ObjectTypeBinaryOutput, AnyProperty: true, Device: &ahuVirtual, Consumer: netip.MustParsePrefix("127.0.0.1/32")},
		}
	}})
	heard := b.AwaitDevices(simDevices, 10*time.Second)
	ahu, meter := deviceByReal(t, b, heard, 1001), deviceByReal(t, b, heard, 3000)
	if ahu.Instance != ahuVirtual {
		t.Fatalf("the AHU is virtual device %d, the reference said %d", ahu.Instance, ahuVirtual)
	}
	to := b.Shifter.ConsumerAddr()
	npduTo := func(dev client.Device) *plumbing.NPDU {
		return harness.NPDUTo(dev.Addr.Net, dev.Addr.MAC, 0, nil, true)
	}
	setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 0}
	fan := client.ObjectID{Type: objects.ObjectTypeBinaryOutput, Instance: 0}
	real := []objects.APDUPayload{objects.EncReal(56)}
	active := []objects.APDUPayload{objects.EncEnumerated(1)}
	me := harness.NewRaw(t)
	other := harness.NewRawAt(t, netip.MustParseAddr("127.0.0.2"))

	denied := func(got *harness.Received) bool {
		if got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
			return false
		}
		class, code := errorOf(got.APDU)
		return class == uint32(objects.ErrorClassProperty) && code == uint32(control.ErrorCodeWriteAccessDenied)
	}
	acked := func(got *harness.Received) bool {
		return got != nil && got.APDU != nil && got.APDU.Type == plumbing.SimpleAck
	}
	cases := []struct {
		name   string
		from   *harness.Raw
		dev    client.Device
		obj    client.ObjectID
		prop   uint16
		value  []objects.APDUPayload
		wantOK bool
	}{
		{"covered by type and property", me, ahu, setpoint, objects.PropertyIdPresentValue, real, true},
		{"another property of the type", me, ahu, setpoint, objects.PropertyIdRelinquishDefault, real, false},
		{"covered by device and consumer", me, ahu, fan, objects.PropertyIdPresentValue, active, true},
		{"another consumer", other, ahu, fan, objects.PropertyIdPresentValue, active, false},
		{"another device", me, meter, fan, objects.PropertyIdPresentValue, active, false},
		{"the floor under an entry", me, ahu, fan, objects.PropertyIdOutOfService, []objects.APDUPayload{objects.EncBoolean(true)}, false},
	}
	forwarded, refused := 0, 0
	for i, tc := range cases {
		tc.from.Drain(t)
		got := tc.from.Exchange(t, to, npduTo(tc.dev), writeAPDU(uint8(i+1), tc.obj, tc.prop, nil, tc.value, nil), time.Second)
		switch {
		case tc.wantOK && !acked(got):
			t.Errorf("%s: got %s, want SimpleACK", tc.name, answer(got))
		case !tc.wantOK && !denied(got):
			t.Errorf("%s: got %s, want write-access-denied", tc.name, answer(got))
		}
		if tc.wantOK {
			forwarded++
		} else {
			refused++
		}
	}
	if n := len(fake.Calls()); n != forwarded {
		t.Errorf("%d writes reached the site, want %d", n, forwarded)
	}

	// A subscription, made and cancelled, for the audit record.
	ctx := b.Ctx()
	sub, err := b.Consumer.SubscribeCOV(ctx, ahu.Addr, client.ObjectID{Type: objects.ObjectTypeAnalogInput}, client.COVOptions{}, func(client.COVNotification) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	b.Close() // flushes the audit file

	entries := readAudit(t, auditFile)
	if len(entries) == 0 || entries[0].Event != audit.EventStart || entries[0].Control != "full-service" {
		t.Fatalf("the audit file does not start with the start line: %+v", entries)
	}
	count := map[string]int{}
	for _, e := range entries {
		count[e.Event]++
		if e.Time.IsZero() || e.Time.Location() != time.UTC {
			t.Errorf("an entry without a UTC time: %+v", e)
		}
		switch e.Event {
		case audit.EventWrite:
			if e.Outcome != "acked" || e.Priority != 13 || e.Device != ahuVirtual || e.Real != 1001 || e.Peer != me.Local().String() || e.Control != "full-service" || e.Property != "present-value" {
				t.Errorf("a write line is incomplete: %+v", e)
			}
		case audit.EventRefused:
			if e.Outcome == "" || e.Detail == "" || e.Service != "write-property" {
				t.Errorf("a refused line is incomplete: %+v", e)
			}
			if e.Detail != control.RuleAllow && e.Detail != control.RuleReserved {
				t.Errorf("a refusal for an unexpected rule: %+v", e)
			}
		case audit.EventSubscribe, audit.EventCancel:
			if e.Device != ahuVirtual || e.Object != "analog-input 0" {
				t.Errorf("a subscription line is incomplete: %+v", e)
			}
		}
	}
	if count[audit.EventWrite] != forwarded || count[audit.EventRefused] != refused || count[audit.EventSubscribe] != 1 || count[audit.EventCancel] != 1 || count[audit.EventStart] != 1 {
		t.Errorf("the audit file holds %v, want %d writes, %d refusals, a subscription, a cancellation and the start", count, forwarded, refused)
	}
	if info, err := os.Stat(auditFile); err != nil || info.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("the audit file has mode %v, %v", info.Mode(), err)
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }

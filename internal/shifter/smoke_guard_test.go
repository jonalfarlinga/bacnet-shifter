package shifter_test

import (
	"net/netip"
	"os"
	"path/filepath"
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

// TestSmokeGuard is the guard test against the real site named by
// SHIFTER_SMOKE_ADAPTER: at no-write and at limited a WriteProperty from a
// consumer is refused with service-request-denied and no WriteProperty
// leaves the site socket; a SubscribeCOV is refused at no-write and
// acknowledged at limited, so that the level in force is the one meant.
// The write allow list covers everything, so that the refusal is the
// level's and nothing else's. It is skipped unless the variable is set,
// and runs the two levels one after the other, since the site answers to
// port 47808 and the two shifters cannot share it.
func TestSmokeGuard(t *testing.T) {
	adapter := os.Getenv("SHIFTER_SMOKE_ADAPTER")
	if adapter == "" {
		t.Skip("set SHIFTER_SMOKE_ADAPTER to the name or address of the site adapter to run against a real site")
	}
	ifc, err := client.FindInterface(adapter)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []control.Level{control.NoWrite, control.Limited} {
		t.Run(level.String(), func(t *testing.T) { smokeGuardAt(t, ifc, level) })
	}
}

func smokeGuardAt(t *testing.T, ifc client.Interface, level control.Level) {
	dir := t.TempDir()
	key, _, err := pseudonym.LoadOrCreate(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	tb, err := table.Open(filepath.Join(dir, "table.json"), pseudonym.New(key), 9000)
	if err != nil {
		t.Fatal(err)
	}
	siteRec := &recorder{}
	siteCfg := ifc.Config(client.DefaultPort)
	siteCfg.Timeout, siteCfg.Retries, siteCfg.OnPacket = 3*time.Second, 2, siteRec.OnPacket
	sh, err := shifter.Start(shifter.Config{
		Site:       siteCfg,
		Consumer:   server.Config{Local: netip.MustParseAddrPort("127.0.0.1:0"), Timeout: time.Second, Retries: 1},
		Table:      tb,
		Control:    level,
		Reserved:   control.DefaultReserved(),
		WriteAllow: control.WriteAllowAll(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	to := sh.ConsumerAddr()
	raw := harness.NewRaw(t)

	// The first device the site announces, by its virtual address.
	var snet uint16
	var sadr []byte
	deadline := time.Now().Add(20 * time.Second)
	for sadr == nil && time.Now().Before(deadline) {
		raw.Send(t, to, plumbing.NewNPDU(false, false, false, false), plumbing.NewAPDU(plumbing.UnConfirmedReq, services.ServiceUnconfirmedWhoIs, nil))
		for rcv := raw.Receive(t, time.Second); rcv != nil && sadr == nil; rcv = raw.Receive(t, 200*time.Millisecond) {
			if rcv.APDU != nil && rcv.APDU.Type == plumbing.UnConfirmedReq && rcv.APDU.Service == services.ServiceUnconfirmedIAm && rcv.NPDU.Control&0x08 != 0 {
				snet, sadr = rcv.NPDU.SNET, append([]byte(nil), rcv.NPDU.SADR...)
			}
		}
	}
	if sadr == nil {
		t.Fatal("no device came through the shifter in 20 seconds")
	}
	t.Logf("%s: a site device at virtual network %d MAC %x", level, snet, sadr)
	npdu := func() *plumbing.NPDU { return harness.NPDUTo(snet, sadr, 0, nil, true) }
	denied := func(got *harness.Received) bool {
		if got == nil || got.APDU == nil || got.APDU.Type != plumbing.Error {
			return false
		}
		class, code := errorOf(got.APDU)
		return class == uint32(objects.ErrorClassServices) && code == uint32(objects.ErrorCodeServiceRequestDenied)
	}

	// A write to a setpoint-like object: refused at both levels.
	raw.Drain(t)
	setpoint := client.ObjectID{Type: objects.ObjectTypeAnalogValue, Instance: 1}
	got := raw.Exchange(t, to, npdu(), writeAPDU(1, setpoint, objects.PropertyIdPresentValue, nil, []objects.APDUPayload{objects.EncReal(1)}, nil), 5*time.Second)
	if !denied(got) {
		t.Errorf("%s: a write got %s, want Error services service-request-denied", level, answer(got))
	}
	// A subscription: refused at no-write, acknowledged at limited.
	raw.Drain(t)
	sub := plumbing.NewAPDU(plumbing.ConfirmedReq, services.ServiceConfirmedSubscribeCOV, services.COVObjects(9, objects.ObjectTypeAnalogInput, 0, false, 60))
	sub.InvokeID, sub.MaxSize = 2, 5
	sub.SetAPDUFlags(true, false, false)
	got = raw.Exchange(t, to, npdu(), sub, 10*time.Second)
	switch {
	case level == control.NoWrite && !denied(got):
		t.Errorf("no-write: a subscription got %s, want service-request-denied", answer(got))
	case level == control.Limited && (got == nil || got.APDU == nil || got.APDU.Type != plumbing.SimpleAck):
		t.Errorf("limited: a subscription got %s, want SimpleACK", answer(got))
	}

	// What left the site socket: no WriteProperty at either level, and a
	// SubscribeCOV at limited only.
	var sent [][]byte
	for _, e := range siteRec.Events() {
		if !e.Inbound {
			sent = append(sent, e.Data)
		}
	}
	if n := countService(t, sent, services.ServiceConfirmedWriteProperty); n != 0 {
		t.Errorf("%s: %d WriteProperty datagrams reached the site", level, n)
	}
	subs := countService(t, sent, services.ServiceConfirmedSubscribeCOV)
	if (level == control.NoWrite && subs != 0) || (level == control.Limited && subs == 0) {
		t.Errorf("%s: %d SubscribeCOV datagrams reached the site", level, subs)
	}
	t.Logf("%s: %d datagrams to the site, no WriteProperty among them, %d SubscribeCOV", level, len(sent), subs)
}

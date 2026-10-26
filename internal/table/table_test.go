package table

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"

	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
)

func key(fill byte) pseudonym.Key {
	k := make(pseudonym.Key, pseudonym.KeySize)
	for i := range k {
		k[i] = fill
	}
	return k
}

func device(instance uint32, ip string, net uint16, mac ...byte) client.Device {
	d := client.Device{Instance: instance, Addr: client.Address{IP: netip.MustParseAddrPort(ip), Net: net, MAC: mac}, MaxAPDU: 1476, VendorID: 999}
	return d
}

var (
	ai3 = objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogInput, InstanceNumber: 3}
	dev = func(i uint32) objects.ObjectIdentifier {
		return objects.ObjectIdentifier{ObjectType: objects.ObjectTypeDevice, InstanceNumber: i}
	}
)

func open(t *testing.T, path string, k pseudonym.Key) *Table {
	t.Helper()
	tb, err := Open(path, pseudonym.New(k), 9000)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// A device gets a virtual instance and MAC, is found by either, and by its
// virtual address; a routed device gets a virtual network; names and texts
// get pseudonyms; all of it survives a save and a reload.
func TestRecordsAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table.json")
	tb := open(t, path, key(1))

	seen, err := tb.EnsureDevice(device(1001, "10.0.0.3:47808", 0))
	if err != nil || !seen.Created || seen.Duplicate || seen.Moved {
		t.Fatalf("first device: %+v, %v", seen, err)
	}
	d := seen.Device
	if d.Referenced || d.Virtual >= pseudonym.Instances || d.MAC == 0 {
		t.Errorf("device record %+v", d)
	}
	if got, ok := tb.ByVirtual(d.Virtual); !ok || got.Instance != 1001 {
		t.Errorf("by virtual instance: %+v, %t", got, ok)
	}
	if net, mac := tb.VirtualAddress(d); net != 9000 || len(mac) != 2 {
		t.Errorf("virtual address %d %x, want network 9000 and 2 bytes", net, mac)
	}
	if got, ok := tb.At(9000, d.VirtualMAC()); !ok || got.Instance != 1001 {
		t.Errorf("at the virtual address: %+v, %t", got, ok)
	}
	if _, ok := tb.At(9001, d.VirtualMAC()); ok {
		t.Error("found on the wrong network")
	}
	if got, ok := tb.AtReal(0, []byte{10, 0, 0, 3, 0xBA, 0xC0}); !ok || got.Instance != 1001 {
		t.Errorf("by real BACnet/IP address: %+v, %t", got, ok)
	}

	// The same device again changes nothing.
	if seen, err := tb.EnsureDevice(device(1001, "10.0.0.3:47808", 0)); err != nil || seen.Created || seen.Moved || seen.Duplicate {
		t.Errorf("second I-Am: %+v, %v", seen, err)
	}
	// A device behind a site router is on a derived network.
	seen, err = tb.EnsureDevice(device(2101, "10.0.0.4:47808", 2001, 5))
	if err != nil || !seen.Created {
		t.Fatal(err)
	}
	vnet, _ := tb.VirtualAddress(seen.Device)
	if vnet == 9000 || vnet == 0 {
		t.Errorf("routed device is on network %d", vnet)
	}
	if real, ok := tb.RealNetwork(vnet); !ok || real != 2001 {
		t.Errorf("real network of %d is %d, %t", vnet, real, ok)
	}
	if nets := tb.VirtualNetworks(); len(nets) != 2 {
		t.Errorf("virtual networks %v", nets)
	}
	if got, ok := tb.AtReal(2001, []byte{5}); !ok || got.Instance != 2101 {
		t.Errorf("by real routed address: %+v, %t", got, ok)
	}
	if list := tb.Devices(0); len(list) != 2 {
		t.Errorf("%d devices listed, want 2", len(list))
	}
	if list := tb.Devices(vnet); len(list) != 1 || list[0].Instance != 2101 {
		t.Errorf("devices on %d: %+v", vnet, list)
	}

	name, err := tb.EnsureName(1001, ai3, "AHU1.OAT")
	if err != nil || name[:3] != "AI-" {
		t.Fatalf("name %q, %v", name, err)
	}
	if again, _ := tb.EnsureName(1001, ai3, "AHU1.OAT"); again != name {
		t.Errorf("the name changed: %s, %s", name, again)
	}
	text, err := tb.EnsureText(1001, ai3, uint32(objects.PropertyIdDescription), "Outside air")
	if err != nil || text[:5] != "desc-" {
		t.Fatalf("text %q, %v", text, err)
	}
	if found := tb.NamesByPseudonym(name); len(found) != 1 || found[0].Real != "AHU1.OAT" {
		t.Errorf("by pseudonym: %+v", found)
	}
	if found := tb.NamesOf(ai3); len(found) != 1 || found[0].Device != 1001 {
		t.Errorf("by identifier: %+v", found)
	}
	// A referenced device has pseudonyms but no address, and is not listed.
	ref, err := tb.Reference(7777)
	if err != nil || !ref.Referenced || ref.Virtual == d.Virtual {
		t.Fatalf("reference: %+v, %v", ref, err)
	}
	if list := tb.Devices(0); len(list) != 2 {
		t.Errorf("a referenced device is listed: %d", len(list))
	}
	if _, ok := tb.At(9000, ref.VirtualMAC()); ok {
		t.Error("a referenced device is reachable")
	}

	// Reload, once the pending write is flushed: everything is as it was.
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	again := open(t, path, key(1))
	if got, ok := again.Device(1001); !ok || got != d {
		t.Errorf("after reload: %+v, want %+v", got, d)
	}
	if got, ok := again.ByVirtual(ref.Virtual); !ok || !got.Referenced {
		t.Error("the referenced device was lost")
	}
	if n, ok := again.Name(1001, ai3); !ok || n.Pseudonym != name {
		t.Errorf("the name was lost: %+v", n)
	}
	if nets := again.VirtualNetworks(); len(nets) != 2 || nets[0] != 9000 && nets[1] != 9000 {
		t.Errorf("virtual networks after reload %v", nets)
	}
	if vn := again.VirtualNetwork(2001); vn != vnet {
		t.Errorf("network 2001 is %d after reload, was %d", vn, vnet)
	}
	// And a device heard now at a new address has moved.
	if seen, err := again.EnsureDevice(device(1001, "10.0.0.9:47808", 0)); err != nil || !seen.Moved || seen.Created {
		t.Errorf("moved device: %+v, %v", seen, err)
	}
	// A different address for an instance heard this run is a duplicate.
	if seen, err := again.EnsureDevice(device(1001, "10.0.0.10:47808", 0)); err != nil || !seen.Duplicate {
		t.Errorf("duplicate device: %+v, %v", seen, err)
	}
	if got, _ := again.Device(1001); got.Address.IP != "10.0.0.9:47808" {
		t.Errorf("the duplicate took the address: %s", got.Address.IP)
	}
}

// With the derivation narrowed so that everything collides, two objects
// whose names collide get distinct pseudonyms and both are recorded with
// their candidate index; the same for device instances, MACs and network
// numbers; and a device seen second on a restart keeps its first-run
// pseudonym.
func TestCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table.json")
	d := pseudonym.New(key(2))
	d.NameHex, d.Instances, d.MACs, d.Networks = 1, 4, 4, 4
	tb, err := Open(path, d, 9000)
	if err != nil {
		t.Fatal(err)
	}

	var devices []Device
	for i, inst := range []uint32{1, 2, 3, 4} {
		seen, err := tb.EnsureDevice(device(inst, "10.0.0.1:47808", uint16(10+i), byte(i)))
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, seen.Device)
	}
	virt, macs := map[uint32]bool{}, map[uint16]bool{}
	for _, dv := range devices {
		if virt[dv.Virtual] || macs[dv.MAC] {
			t.Errorf("device %d shares a pseudonym: %+v", dv.Instance, dv)
		}
		virt[dv.Virtual], macs[dv.MAC] = true, true
	}
	var candidates int
	for _, dv := range devices {
		candidates += dv.Candidate + dv.MACCandidate
	}
	if candidates == 0 {
		t.Error("no collision was resolved through a candidate")
	}
	nets := tb.VirtualNetworks()
	seenNet := map[uint16]bool{}
	for _, n := range nets {
		if seenNet[n] {
			t.Errorf("virtual network %d issued twice: %v", n, nets)
		}
		seenNet[n] = true
	}
	if len(nets) != 5 {
		t.Errorf("want V and 4 networks, got %v", nets)
	}

	names := map[string]bool{}
	for i := uint32(0); i < 12; i++ {
		obj := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogInput, InstanceNumber: i}
		p, err := tb.EnsureName(1, obj, "name")
		if err != nil {
			t.Fatal(err)
		}
		if names[p] {
			t.Errorf("name %s issued twice in one device", p)
		}
		names[p] = true
	}
	// The same pseudonym may be held in another device.
	if p, _ := tb.EnsureName(2, objects.ObjectIdentifier{ObjectType: 0, InstanceNumber: 0}, "name"); !names[p] {
		t.Log("the other device got a fresh pseudonym, which is allowed")
	}
	// Device names are unique across the site.
	p1, _ := tb.EnsureName(1, dev(1), "x")
	p2, _ := tb.EnsureName(2, dev(2), "x")
	if p1 == p2 {
		t.Errorf("two devices share the name %s", p1)
	}
	var withCandidate bool
	for _, n := range tb.Listing("") {
		if n.Kind == "name" {
			withCandidate = true
		}
	}
	if !withCandidate {
		t.Error("names are not in the listing")
	}

	// A restart in another order keeps every pseudonym.
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, d, 9000)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(devices) - 1; i >= 0; i-- {
		dv := devices[i]
		seen, err := again.EnsureDevice(device(dv.Instance, "10.0.0.1:47808", dv.Address.Net, dv.Address.Client().MAC...))
		if err != nil {
			t.Fatal(err)
		}
		if seen.Device.Virtual != dv.Virtual || seen.Device.MAC != dv.MAC || seen.Created {
			t.Errorf("device %d changed on restart: %+v, was %+v", dv.Instance, seen.Device, dv)
		}
	}
	for i := uint32(11); i < 12; i-- {
		obj := objects.ObjectIdentifier{ObjectType: objects.ObjectTypeAnalogInput, InstanceNumber: i}
		if p, _ := again.EnsureName(1, obj, "name"); !names[p] {
			t.Errorf("name of %v changed on restart: %s", obj, p)
		}
	}
}

// A renamed object gets a new pseudonym; the old record stays, marked, and
// still resolves for a consumer that holds it.
func TestRename(t *testing.T) {
	tb := open(t, filepath.Join(t.TempDir(), "table.json"), key(3))
	tb.Now = func() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) }
	old, _ := tb.EnsureName(1001, ai3, "before")
	now, _ := tb.EnsureName(1001, ai3, "after")
	if old == now {
		t.Fatal("the rename kept the pseudonym")
	}
	if n, ok := tb.Name(1001, ai3); !ok || n.Pseudonym != now || n.Real != "after" {
		t.Errorf("current name %+v", n)
	}
	found := tb.NamesByPseudonym(old)
	if len(found) != 1 || found[0].Renamed.IsZero() || found[0].Real != "before" {
		t.Errorf("old record %+v", found)
	}
	if rows := tb.Listing("before"); len(rows) != 1 || rows[0].Real[len(rows[0].Real)-1] != ')' {
		t.Errorf("listing of the old name: %+v", rows)
	}
	_, _, names, _ := tb.Counts()
	if names != 2 {
		t.Errorf("%d name records, want 2", names)
	}
}

// Without a file the table works in memory.
func TestInMemory(t *testing.T) {
	tb := open(t, "", key(4))
	if _, err := tb.EnsureDevice(device(1, "10.0.0.1:47808", 0)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Save(); err != nil {
		t.Fatal(err)
	}
}

// Writes within a second of one another are coalesced into one write when
// the second is up, Save writes now, and Close flushes what is pending.
func TestCoalescedWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table.json")
	tb := open(t, path, key(5))
	if _, err := tb.EnsureDevice(device(1, "10.0.0.1:47808", 0)); err != nil {
		t.Fatal(err)
	}
	if n := tb.Writes(); n != 1 {
		t.Fatalf("the first change made %d writes, want 1", n)
	}
	for i := uint32(2); i <= 50; i++ {
		if _, err := tb.EnsureDevice(device(i, "10.0.0.1:47808", 0)); err != nil {
			t.Fatal(err)
		}
	}
	if n := tb.Writes(); n != 1 {
		t.Errorf("49 changes in the same second made %d more writes, want 0 until the second is up", n-1)
	}
	deadline := time.Now().Add(3 * SaveInterval)
	for tb.Writes() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := tb.Writes(); n != 2 {
		t.Fatalf("%d writes after the interval, want 2", n)
	}
	if got := open(t, path, key(5)); len(got.Devices(0)) != 50 {
		t.Errorf("the scheduled write holds %d devices, want 50", len(got.Devices(0)))
	}
	if _, err := tb.EnsureDevice(device(51, "10.0.0.1:47808", 0)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	if n := tb.Writes(); n != 3 {
		t.Errorf("%d writes after Close, want 3", n)
	}
	if got := open(t, path, key(5)); len(got.Devices(0)) != 51 {
		t.Errorf("after Close the file holds %d devices, want 51", len(got.Devices(0)))
	}
	if err := tb.Save(); err != nil || tb.Writes() != 3 {
		t.Errorf("a Save with nothing pending wrote: %d, %v", tb.Writes(), err)
	}
}

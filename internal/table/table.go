// Package table keeps table.json: every pseudonym the shifter has issued,
// its real value, and when it was first seen (spec §6.3 and §6.4). It is
// the reverse index the consumer side is answered from, the audit record,
// and with the key, the de-anonymization secret.
//
// Four kinds of record are kept: a device (real instance and address,
// virtual instance and MAC), a site network (real and virtual number), an
// object's name (real and pseudonym) and a replaced text property (real and
// pseudonym). Names, instances, MACs and network numbers are identifiers and
// are unique in their namespace; a collision takes the next candidate of the
// derivation, and the candidate index is recorded. Once an entry exists it
// is never re-derived, so pseudonyms are stable across runs whatever order
// the site is seen in.
//
// The file is written after every change, to a temporary file renamed into
// place.
package table

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"

	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
)

// Address is a device's real address as the file holds it.
type Address struct {
	// IP is the device's BACnet/IP address, or its router's for a routed
	// device.
	IP string `json:"ip,omitempty"`
	// Net and MAC place a routed device: its network number and its MAC on
	// it, in hex.
	Net uint16 `json:"net,omitempty"`
	MAC string `json:"mac,omitempty"`
}

// AddressOf renders a client address for the file.
func AddressOf(a client.Address) Address {
	addr := Address{Net: a.Net, MAC: hex.EncodeToString(a.MAC)}
	if a.IP.IsValid() {
		addr.IP = a.IP.String()
	}
	return addr
}

// Client gives the address back as the client takes it.
func (a Address) Client() client.Address {
	addr := client.Address{Net: a.Net}
	if a.IP != "" {
		addr.IP, _ = netip.ParseAddrPort(a.IP)
	}
	if a.MAC != "" {
		addr.MAC, _ = hex.DecodeString(a.MAC)
	}
	return addr
}

// IsZero reports whether no address is recorded.
func (a Address) IsZero() bool { return a.IP == "" && a.Net == 0 && a.MAC == "" }

func (a Address) String() string { return a.Client().String() }

// Device is one site device.
type Device struct {
	Instance uint32 `json:"instance"`
	// Virtual is the device's virtual instance, Candidate the index of the
	// derivation that gave it.
	Virtual   uint32 `json:"virtual"`
	Candidate int    `json:"candidate,omitempty"`
	// MAC is the device's virtual MAC, MACCandidate likewise.
	MAC          uint16 `json:"virtual_mac"`
	MACCandidate int    `json:"mac_candidate,omitempty"`
	// Address is where the device was last heard from; empty while it is
	// only Referenced.
	Address Address `json:"address"`
	// Referenced marks a device that has been named in a value, as a trend
	// log names the device it logs, but has not been heard from.
	Referenced bool `json:"referenced,omitempty"`
	// What the device's I-Am said, kept so that the device can be announced
	// from the table before it is heard again.
	MaxAPDU      uint16    `json:"max_apdu,omitempty"`
	Segmentation uint8     `json:"segmentation,omitempty"`
	VendorID     uint16    `json:"vendor_id,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
}

// VirtualMAC is the virtual MAC as it goes on the wire: two bytes.
func (d Device) VirtualMAC() []byte { return []byte{byte(d.MAC >> 8), byte(d.MAC)} }

// Network is one site network behind a site router.
type Network struct {
	Number    uint16    `json:"number"`
	Virtual   uint16    `json:"virtual"`
	Candidate int       `json:"candidate,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

// Name is the pseudonym of one object's name.
type Name struct {
	Device    uint32    `json:"device"`
	Type      uint16    `json:"type"`
	Instance  uint32    `json:"instance"`
	Real      string    `json:"real"`
	Pseudonym string    `json:"pseudonym"`
	Candidate int       `json:"candidate,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	// Renamed is set on the old record when the object's name changed on
	// the site: the record stays, since a consumer may still hold its
	// pseudonym, and a new record carries the new name.
	Renamed time.Time `json:"renamed,omitempty"`
}

// Object is the identifier of the named object.
func (n Name) Object() objects.ObjectIdentifier {
	return objects.ObjectIdentifier{ObjectType: n.Type, InstanceNumber: n.Instance}
}

// Text is the pseudonym of one replaced string property other than the
// name.
type Text struct {
	Device    uint32    `json:"device"`
	Type      uint16    `json:"type"`
	Instance  uint32    `json:"instance"`
	Property  uint32    `json:"property"`
	Real      string    `json:"real"`
	Pseudonym string    `json:"pseudonym"`
	FirstSeen time.Time `json:"first_seen"`
}

// file is the layout of table.json.
type file struct {
	Devices  []*Device  `json:"devices"`
	Networks []*Network `json:"networks"`
	Names    []*Name    `json:"names"`
	Texts    []*Text    `json:"texts"`
}

type nameKey struct {
	device   uint32
	typ      uint16
	instance uint32
}

type textKey struct {
	nameKey
	property uint32
}

// Table is the loaded table.
type Table struct {
	path string
	d    *pseudonym.Deriver
	v    uint16
	// Now is the clock, replaceable by tests.
	Now func() time.Time

	mu   sync.Mutex
	file file
	// indexes over file
	devices  map[uint32]*Device // by real instance
	byVirt   map[uint32]*Device // by virtual instance
	byMAC    map[uint16]*Device // by virtual MAC
	networks map[uint16]*Network
	byVNet   map[uint16]*Network
	names    map[nameKey]*Name // the current name of each object
	byPseudo map[string][]*Name
	texts    map[textKey]*Text
	// heard is the devices heard from this run, which a later I-Am at a
	// different address is a duplicate of rather than a move.
	heard map[uint32]bool
}

// Open loads the table at path, or starts an empty one when there is no file
// yet. d derives new pseudonyms; v is the configured virtual network number,
// which counts as taken among the virtual network numbers.
func Open(path string, d *pseudonym.Deriver, v uint16) (*Table, error) {
	t := &Table{path: path, d: d, v: v, Now: time.Now}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &t.file); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	t.index()
	return t, nil
}

// index rebuilds the maps from the file.
func (t *Table) index() {
	t.devices = map[uint32]*Device{}
	t.byVirt = map[uint32]*Device{}
	t.byMAC = map[uint16]*Device{}
	for _, d := range t.file.Devices {
		t.devices[d.Instance] = d
		t.byVirt[d.Virtual] = d
		t.byMAC[d.MAC] = d
	}
	t.networks = map[uint16]*Network{}
	t.byVNet = map[uint16]*Network{}
	for _, n := range t.file.Networks {
		t.networks[n.Number] = n
		t.byVNet[n.Virtual] = n
	}
	t.names = map[nameKey]*Name{}
	t.byPseudo = map[string][]*Name{}
	for _, n := range t.file.Names {
		key := nameKey{n.Device, n.Type, n.Instance}
		if n.Renamed.IsZero() {
			t.names[key] = n
		}
		t.byPseudo[n.Pseudonym] = append(t.byPseudo[n.Pseudonym], n)
	}
	t.texts = map[textKey]*Text{}
	for _, x := range t.file.Texts {
		t.texts[textKey{nameKey{x.Device, x.Type, x.Instance}, x.Property}] = x
	}
	t.heard = map[uint32]bool{}
}

// Save writes the table to its file, through a temporary file renamed into
// place. The caller holds t.mu.
func (t *Table) save() error {
	if t.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(&t.file, "", "  ")
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// Save writes the table to its file.
func (t *Table) Save() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.save()
}

// V is the configured virtual network number.
func (t *Table) V() uint16 { return t.v }

// ---- devices ---------------------------------------------------------------

// Seen is what EnsureDevice says about the device it was given.
type Seen struct {
	Device Device
	// Created says the device got its pseudonyms just now.
	Created bool
	// Moved says the device's address changed from an earlier run's.
	Moved bool
	// Duplicate says another device at another address was heard with
	// this instance earlier in this run: a site fault. The first keeps the
	// instance, and this one is not recorded.
	Duplicate bool
}

// EnsureDevice records a device heard from the site: its real instance and
// address, and what its I-Am said. A device not in the table gets a virtual
// instance and MAC; one heard earlier at another address is a duplicate.
func (t *Table) EnsureDevice(dev client.Device) (Seen, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	addr := AddressOf(dev.Addr)
	d := t.devices[dev.Instance]
	var seen Seen
	switch {
	case d == nil:
		d = t.newDevice(dev.Instance)
		seen.Created = true
	case t.heard[dev.Instance] && d.Address != addr:
		seen.Duplicate = true
		seen.Device = *d
		return seen, nil
	case !d.Referenced && !d.Address.IsZero() && d.Address != addr:
		seen.Moved = true
	}
	changed := seen.Created || seen.Moved || d.Referenced ||
		d.MaxAPDU != dev.MaxAPDU || d.Segmentation != dev.Segmentation || d.VendorID != dev.VendorID
	if dev.Addr.Net != 0 && t.networks[dev.Addr.Net] == nil {
		t.ensureNetwork(dev.Addr.Net)
		changed = true
	}
	d.Address = addr
	d.Referenced = false
	d.MaxAPDU, d.Segmentation, d.VendorID = dev.MaxAPDU, dev.Segmentation, dev.VendorID
	t.heard[dev.Instance] = true
	seen.Device = *d
	if !changed {
		return seen, nil
	}
	return seen, t.save()
}

// newDevice issues the pseudonyms of a device. The caller holds t.mu.
func (t *Table) newDevice(instance uint32) *Device {
	d := &Device{Instance: instance, Referenced: true, FirstSeen: t.Now().UTC()}
	for k := 0; ; k++ {
		if v := t.d.Instance(instance, k); t.byVirt[v] == nil {
			d.Virtual, d.Candidate = v, k
			break
		}
	}
	for k := 0; ; k++ {
		if m := t.d.MAC(instance, k); t.byMAC[m] == nil {
			d.MAC, d.MACCandidate = m, k
			break
		}
	}
	t.file.Devices = append(t.file.Devices, d)
	t.devices[instance] = d
	t.byVirt[d.Virtual] = d
	t.byMAC[d.MAC] = d
	return d
}

// Reference gives the virtual instance of a device named in a value, whether
// or not the device has been heard from: one not in the table gets a record
// marked as referenced, so that references to it are consistent before and
// after it appears.
func (t *Table) Reference(instance uint32) (Device, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.devices[instance]; d != nil {
		return *d, nil
	}
	d := t.newDevice(instance)
	return *d, t.save()
}

// Device looks a device up by its real instance.
func (t *Table) Device(instance uint32) (Device, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.devices[instance]
	if d == nil {
		return Device{}, false
	}
	return *d, true
}

// Known reports whether a device instance is in the table, heard or
// referenced.
func (t *Table) Known(instance uint32) bool {
	_, ok := t.Device(instance)
	return ok
}

// ByVirtual looks a device up by its virtual instance.
func (t *Table) ByVirtual(virtual uint32) (Device, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.byVirt[virtual]
	if d == nil {
		return Device{}, false
	}
	return *d, true
}

// VirtualNetworkOf is the virtual network a device is on: V for a device on
// the site's own subnet or reached through the BBMD, the derived number for
// one behind a site router. The caller holds t.mu.
func (t *Table) virtualNetworkOf(d *Device) uint16 {
	if d.Address.Net == 0 {
		return t.v
	}
	return t.ensureNetwork(d.Address.Net).Virtual
}

// VirtualAddress is where the consumer reaches a device: its virtual network
// and MAC.
func (t *Table) VirtualAddress(d Device) (net uint16, mac []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.virtualNetworkOf(&d), d.VirtualMAC()
}

// At looks up the device at a virtual address.
func (t *Table) At(vnet uint16, mac []byte) (Device, bool) {
	if len(mac) != 2 {
		return Device{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.byMAC[uint16(mac[0])<<8|uint16(mac[1])]
	if d == nil || d.Referenced || t.virtualNetworkOf(d) != vnet {
		return Device{}, false
	}
	return *d, true
}

// AtReal looks up the device at a real address: a routed one by network and
// MAC, one with an address of its own by the six bytes of its BACnet/IP
// address.
func (t *Table) AtReal(net uint16, mac []byte) (Device, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.file.Devices {
		if d.Referenced {
			continue
		}
		a := d.Address.Client()
		switch {
		case net != 0:
			if a.Net == net && hex.EncodeToString(mac) == d.Address.MAC {
				return *d, true
			}
		case a.Net == 0 && a.IP.IsValid() && len(mac) == 6:
			ip := a.IP.Addr().As4()
			port := a.IP.Port()
			if string(mac[:4]) == string(ip[:]) && uint16(mac[4])<<8|uint16(mac[5]) == port {
				return *d, true
			}
		}
	}
	return Device{}, false
}

// Devices lists the devices heard from, on one virtual network, or on every
// one when vnet is 0. Referenced devices are not listed: they have no
// address.
func (t *Table) Devices(vnet uint16) []Device {
	t.mu.Lock()
	defer t.mu.Unlock()
	var list []Device
	for _, d := range t.file.Devices {
		if d.Referenced || d.Address.IsZero() {
			continue
		}
		if vnet == 0 || t.virtualNetworkOf(d) == vnet {
			list = append(list, *d)
		}
	}
	return list
}

// ---- networks --------------------------------------------------------------

// ensureNetwork gives a site network its virtual number. The caller holds
// t.mu.
func (t *Table) ensureNetwork(number uint16) *Network {
	if n := t.networks[number]; n != nil {
		return n
	}
	n := &Network{Number: number, FirstSeen: t.Now().UTC()}
	for k := 0; ; k++ {
		if v := t.d.Network(number, k); v != t.v && t.byVNet[v] == nil {
			n.Virtual, n.Candidate = v, k
			break
		}
	}
	t.file.Networks = append(t.file.Networks, n)
	t.networks[number] = n
	t.byVNet[n.Virtual] = n
	return n
}

// EnsureNetwork records a site network and returns its record, and whether
// it was new.
func (t *Table) EnsureNetwork(number uint16) (Network, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := t.networks[number]; n != nil {
		return *n, false, nil
	}
	n := t.ensureNetwork(number)
	return *n, true, t.save()
}

// VirtualNetwork is the virtual number of a real network: V for 0, the
// derived number otherwise, issued now if it was not before.
func (t *Table) VirtualNetwork(number uint16) uint16 {
	if number == 0 {
		return t.v
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := t.networks[number]; n != nil {
		return n.Virtual
	}
	n := t.ensureNetwork(number)
	t.save()
	return n.Virtual
}

// RealNetwork is the real number of a virtual network, false for V and for
// a number that is not one.
func (t *Table) RealNetwork(vnet uint16) (uint16, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.byVNet[vnet]
	if n == nil {
		return 0, false
	}
	return n.Number, true
}

// IsVirtualNetwork reports whether a number is V or a virtual network in the
// table.
func (t *Table) IsVirtualNetwork(vnet uint16) bool {
	if vnet == t.v {
		return true
	}
	_, ok := t.RealNetwork(vnet)
	return ok
}

// VirtualNetworks lists V and every virtual network in the table, sorted.
func (t *Table) VirtualNetworks() []uint16 {
	t.mu.Lock()
	defer t.mu.Unlock()
	nets := []uint16{t.v}
	for _, n := range t.file.Networks {
		nets = append(nets, n.Virtual)
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i] < nets[j] })
	return nets
}

// ---- names and texts -------------------------------------------------------

// EnsureName gives an object's name its pseudonym, issuing one the first
// time the name is seen, and a new one when the name has changed since: the
// old record is kept and marked renamed.
func (t *Table) EnsureName(device uint32, obj objects.ObjectIdentifier, real string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := nameKey{device, obj.ObjectType, obj.InstanceNumber}
	if n := t.names[key]; n != nil {
		if n.Real == real {
			return n.Pseudonym, nil
		}
		n.Renamed = t.Now().UTC()
		delete(t.names, key)
	}
	n := &Name{Device: device, Type: obj.ObjectType, Instance: obj.InstanceNumber, Real: real, FirstSeen: t.Now().UTC()}
	for k := 0; ; k++ {
		p := t.d.Name(device, obj.ObjectType, obj.InstanceNumber, real, k)
		if p == "" || !t.nameTaken(p, n) {
			n.Pseudonym, n.Candidate = p, k
			break
		}
	}
	t.file.Names = append(t.file.Names, n)
	t.names[key] = n
	t.byPseudo[n.Pseudonym] = append(t.byPseudo[n.Pseudonym], n)
	return n.Pseudonym, t.save()
}

// nameTaken reports whether a pseudonym is held by another object in the
// namespace of n: the site for a device object's name, the device for any
// other object's. The caller holds t.mu.
func (t *Table) nameTaken(p string, n *Name) bool {
	for _, held := range t.byPseudo[p] {
		if held.Type == objects.ObjectTypeDevice && n.Type == objects.ObjectTypeDevice {
			return true
		}
		if held.Device == n.Device && !(held.Type == n.Type && held.Instance == n.Instance) {
			return true
		}
	}
	return false
}

// Name looks up the current name record of an object.
func (t *Table) Name(device uint32, obj objects.ObjectIdentifier) (Name, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.names[nameKey{device, obj.ObjectType, obj.InstanceNumber}]
	if n == nil {
		return Name{}, false
	}
	return *n, true
}

// NamesByPseudonym lists the records whose pseudonym is the one given,
// renamed ones included: what a Who-Has by name finds.
func (t *Table) NamesByPseudonym(pseudonym string) []Name {
	t.mu.Lock()
	defer t.mu.Unlock()
	var list []Name
	for _, n := range t.byPseudo[pseudonym] {
		list = append(list, *n)
	}
	return list
}

// NamesOf lists the current name records of the objects with an identifier,
// on every device: what a Who-Has by identifier finds.
func (t *Table) NamesOf(obj objects.ObjectIdentifier) []Name {
	t.mu.Lock()
	defer t.mu.Unlock()
	var list []Name
	for _, n := range t.file.Names {
		if n.Renamed.IsZero() && n.Type == obj.ObjectType && n.Instance == obj.InstanceNumber {
			list = append(list, *n)
		}
	}
	return list
}

// EnsureText gives a replaced string property its pseudonym.
func (t *Table) EnsureText(device uint32, obj objects.ObjectIdentifier, property uint32, real string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := textKey{nameKey{device, obj.ObjectType, obj.InstanceNumber}, property}
	if x := t.texts[key]; x != nil && x.Real == real {
		return x.Pseudonym, nil
	}
	x := &Text{Device: device, Type: obj.ObjectType, Instance: obj.InstanceNumber, Property: property, Real: real,
		Pseudonym: t.d.Text(device, obj.ObjectType, obj.InstanceNumber, property, real), FirstSeen: t.Now().UTC()}
	if old := t.texts[key]; old != nil {
		*old = *x
		x = old
	} else {
		t.file.Texts = append(t.file.Texts, x)
		t.texts[key] = x
	}
	return x.Pseudonym, t.save()
}

// ---- the listing -----------------------------------------------------------

// Row is one line of the -table listing.
type Row struct {
	Kind      string
	Pseudonym string
	Real      string
	FirstSeen time.Time
}

// Listing renders every record, pseudonym and real side by side, or with a
// filter, the records whose pseudonym or real side contains it.
func (t *Table) Listing(filter string) []Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	var rows []Row
	add := func(kind, pseudonym, real string, at time.Time) {
		if filter == "" || strings.Contains(pseudonym, filter) || strings.Contains(real, filter) {
			rows = append(rows, Row{kind, pseudonym, real, at})
		}
	}
	for _, d := range t.file.Devices {
		real := "device " + strconv.FormatUint(uint64(d.Instance), 10)
		if d.Referenced {
			real += " (referenced, not heard)"
		} else {
			real += " at " + d.Address.String()
		}
		add("device", fmt.Sprintf("device %d at network %d MAC %04x", d.Virtual, t.virtualNetworkOf(d), d.MAC), real, d.FirstSeen)
	}
	for _, n := range t.file.Networks {
		add("network", fmt.Sprintf("network %d", n.Virtual), fmt.Sprintf("network %d", n.Number), n.FirstSeen)
	}
	for _, n := range t.file.Names {
		obj := fmt.Sprintf("%s %d of device %d", objects.ObjectTypeName(n.Type), n.Instance, n.Device)
		if n.Type == objects.ObjectTypeDevice {
			obj = fmt.Sprintf("the device object of device %d", n.Device)
		}
		real := fmt.Sprintf("%q, %s", n.Real, obj)
		if !n.Renamed.IsZero() {
			real += " (renamed " + n.Renamed.Format(time.RFC3339) + ")"
		}
		add("name", n.Pseudonym, real, n.FirstSeen)
	}
	for _, x := range t.file.Texts {
		add("text", x.Pseudonym, fmt.Sprintf("%q, %s of %s %d of device %d", x.Real, objects.PropertyName(x.Property),
			objects.ObjectTypeName(x.Type), x.Instance, x.Device), x.FirstSeen)
	}
	return rows
}

// Counts says how many records of each kind the table holds.
func (t *Table) Counts() (devices, networks, names, texts int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.file.Devices), len(t.file.Networks), len(t.file.Names), len(t.file.Texts)
}

package survey

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Describe says which device is at an address, and what it routes.
func Describe(d Device) string {
	which := "would not say which device it is"
	if !d.Unnamed {
		which = fmt.Sprintf("device %d", d.Instance)
		if d.Name != "" {
			which += "  " + d.Name
		}
		if made := strings.TrimSpace(strings.Join([]string{d.Vendor, d.Model}, " ")); made != "" {
			which += "  (" + made + ")"
		}
	}
	if r := Routes(d); r != "" {
		which += "; routes " + r
	}
	return which
}

// Routes lists the networks a router serves, with the devices heard on each.
func Routes(d Device) string {
	if len(d.Routed) == 0 {
		return ""
	}
	nets := make([]int, 0, len(d.Routed))
	for n := range d.Routed {
		nets = append(nets, int(n))
	}
	sort.Ints(nets)
	parts := make([]string, len(nets))
	for i, n := range nets {
		parts[i] = fmt.Sprintf("network %d: %s", n, Plural(d.Routed[uint16(n)], "device"))
	}
	return strings.Join(parts, ", ")
}

// What names what a survey covers: the subnet, or the ranges asked for.
func (r *Result) What() string {
	if len(r.Ranges) == 0 {
		return r.Subnet.String()
	}
	parts := make([]string, len(r.Ranges))
	for i, rg := range r.Ranges {
		parts[i] = rg.String()
	}
	return strings.Join(parts, ", ")
}

// Summary is the survey in a sentence: what was tried, in how long, and
// the counts.
func (r *Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s tried in %s", r.What(), Plural(r.Tried, "address"), r.Took.Round(time.Second))
	if r.Beyond > 0 {
		fmt.Fprintf(&b, ", %d of them beyond the subnet %s", r.Beyond, r.Subnet)
	}
	if r.Stopped {
		fmt.Fprintf(&b, ", stopped with %d to go", r.Total-r.Tried)
	}
	fmt.Fprintf(&b, "; %s, %s, %s", Plural(len(r.Devices), "BACnet device"), Plural(len(r.Hosts), "other host"), Plural(len(r.Vacant), "vacant address"))
	if len(r.Unrouted) > 0 {
		fmt.Fprintf(&b, ", %s with no network", Plural(len(r.Unrouted), "address"))
	}
	if len(r.Silent) > 0 {
		fmt.Fprintf(&b, ", %s that answered nothing", Plural(len(r.Silent), "address"))
	}
	if r.PingErr != nil {
		fmt.Fprintf(&b, "; pings could not be sent (%v)", r.PingErr)
	}
	if r.NeighborsErr != nil {
		fmt.Fprintf(&b, "; the neighbor table could not be read (%v)", r.NeighborsErr)
	}
	return b.String()
}

// Plural counts a noun.
func Plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "s") {
		noun += "e"
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

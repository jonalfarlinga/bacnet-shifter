package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jonalfarlinga/bacnet/client"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/survey"
)

// File is config.yaml. Every key has a default; a key left out takes it.
type File struct {
	Site struct {
		Adapter        string        `yaml:"adapter"`
		Port           uint16        `yaml:"port"`
		BBMD           string        `yaml:"bbmd"`
		BBMDTTL        time.Duration `yaml:"bbmd_ttl"`
		Add            []string      `yaml:"add"`
		Timeout        time.Duration `yaml:"timeout"`
		Retries        int           `yaml:"retries"`
		MaxRPS         float64       `yaml:"max_rps"`
		MaxInFlightNet int           `yaml:"max_in_flight_net"`
		WhoIsInterval  time.Duration `yaml:"whois_interval"`
		COVLifetime    time.Duration `yaml:"cov_lifetime"`
	} `yaml:"site"`
	Consumer struct {
		Adapter        string        `yaml:"adapter"`
		Port           uint16        `yaml:"port"`
		Network        uint16        `yaml:"network"`
		Recent         time.Duration `yaml:"recent"`
		COVMaxLifetime time.Duration `yaml:"cov_max_lifetime"`
	} `yaml:"consumer"`
	Control string `yaml:"control"`
	Data    string `yaml:"data"`
	Log     struct {
		Level  string `yaml:"level"`
		Frames bool   `yaml:"frames"`
	} `yaml:"log"`
	Sim    string `yaml:"sim"`
	Survey struct {
		Enabled bool     `yaml:"enabled"`
		At      string   `yaml:"at"`
		OnStart bool     `yaml:"on_start"`
		Ranges  []string `yaml:"ranges"`
		Rate    float64  `yaml:"rate"`
	} `yaml:"survey"`
	Pseudonym struct {
		Replaced []string `yaml:"replaced"`
	} `yaml:"pseudonym"`
	Reserved struct {
		Services   []string `yaml:"services"`
		Objects    []string `yaml:"objects"`
		Properties []string `yaml:"properties"`
	} `yaml:"reserved"`
}

// Defaults is the defaults table: every key at its default.
func Defaults() File {
	var f File
	f.Site.Port = client.DefaultPort
	f.Site.BBMDTTL = client.DefaultTTL
	f.Site.Add = []string{}
	f.Site.Timeout = 3 * time.Second
	f.Site.Retries = 2
	f.Site.MaxRPS = client.DefaultMaxRequestsPerSec
	f.Site.MaxInFlightNet = client.DefaultMaxInFlightNet
	f.Site.WhoIsInterval = time.Second
	f.Site.COVLifetime = 5 * time.Minute
	f.Consumer.Port = client.DefaultPort
	f.Consumer.Network = 9000
	f.Consumer.Recent = 10 * time.Minute
	f.Consumer.COVMaxLifetime = 24 * time.Hour
	f.Control = control.NoWrite.String()
	f.Data = "data"
	f.Log.Level = "info"
	f.Survey.At = "02:00"
	f.Survey.Ranges = []string{}
	f.Survey.Rate = survey.DefaultPerSec
	f.Pseudonym.Replaced = append([]string(nil), control.DefaultReplacedNames...)
	f.Reserved.Services = append([]string(nil), control.DefaultReservedNames.Services...)
	f.Reserved.Objects = append([]string(nil), control.DefaultReservedNames.Objects...)
	f.Reserved.Properties = append([]string(nil), control.DefaultReservedNames.Properties...)
	return f
}

// Load reads config.yaml over the defaults.
func Load(path string) (File, error) {
	f := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Validate checks what can be checked without opening anything.
func (f File) Validate() error {
	if _, err := control.Parse(f.Control); err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(f.Log.Level)); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	switch f.Sim {
	case "", "default", "remote":
	default:
		return fmt.Errorf("sim %q is not \"\", default or remote", f.Sim)
	}
	if f.Sim == "" {
		if strings.TrimSpace(f.Site.Adapter) == "" {
			return errors.New("site.adapter is not set: name or IPv4 address of the adapter on the site network")
		}
		if strings.TrimSpace(f.Consumer.Adapter) == "" {
			return errors.New("consumer.adapter is not set: name or IPv4 address of the adapter consumers reach the shifter on")
		}
	}
	if f.Site.Port == 0 || f.Consumer.Port == 0 {
		return errors.New("site.port and consumer.port must be UDP ports")
	}
	if f.Consumer.Network == 0 || f.Consumer.Network == 0xFFFF {
		return errors.New("consumer.network must be 1 to 65534")
	}
	if f.Site.Timeout <= 0 || f.Site.Retries < 0 || f.Site.WhoIsInterval <= 0 || f.Site.COVLifetime <= 0 ||
		f.Consumer.Recent <= 0 || f.Consumer.COVMaxLifetime <= 0 || f.Site.BBMDTTL <= 0 || f.Site.MaxInFlightNet <= 0 {
		return errors.New("a duration or count is zero or negative")
	}
	if f.Site.BBMD != "" {
		if _, err := parseAddrPort(f.Site.BBMD, f.Site.Port); err != nil {
			return fmt.Errorf("site.bbmd: %w", err)
		}
	}
	for _, a := range f.Site.Add {
		if _, err := parseAddrPort(a, f.Site.Port); err != nil {
			return fmt.Errorf("site.add: %w", err)
		}
	}
	if _, err := survey.ParseClock(f.Survey.At); err != nil {
		return fmt.Errorf("survey.at: %w", err)
	}
	if f.Survey.Rate <= 0 {
		return errors.New("survey.rate must be above zero")
	}
	ranges, err := survey.ParseRangeList(f.Survey.Ranges)
	if err != nil {
		return fmt.Errorf("survey.ranges: %w", err)
	}
	if f.Survey.Enabled && f.Sim != "" && len(ranges) == 0 {
		return errors.New("survey.ranges is required under sim: the simulated devices are on loopback, which has no subnet to survey")
	}
	if _, err := control.ParseReplaced(f.Pseudonym.Replaced); err != nil {
		return err
	}
	if _, err := control.ParseReserved(f.Reserved.Services, f.Reserved.Objects, f.Reserved.Properties); err != nil {
		return err
	}
	if strings.TrimSpace(f.Data) == "" {
		return errors.New("data is not set")
	}
	return nil
}

// parseAddrPort reads an IP with an optional port.
func parseAddrPort(s string, defaultPort uint16) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IP address or IP:port", s)
	}
	return netip.AddrPortFrom(addr, defaultPort), nil
}

// ---- rendering -------------------------------------------------------------

// duration writes a duration the short way: 5m, not 5m0s; 24h, not 24h0m0s.
func duration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Render writes the file with every key and a comment each, section by
// section. The repository's config.yaml.example is Render(Defaults()).
func Render(f File) string {
	var b strings.Builder
	line := func(indent int, key, value, comment string) {
		kv := fmt.Sprintf("%s%s: %s", strings.Repeat("  ", indent), key, value)
		if value == "" {
			kv = fmt.Sprintf("%s%s:", strings.Repeat("  ", indent), key)
		}
		if comment == "" {
			b.WriteString(kv + "\n")
			return
		}
		for len(kv) < 26 {
			kv += " "
		}
		b.WriteString(kv + "# " + comment + "\n")
	}
	list := func(indent int, key string, items []string, comment string) {
		if len(items) == 0 {
			line(indent, key, "[]", comment)
			return
		}
		line(indent, key, "", comment)
		for _, item := range items {
			b.WriteString(fmt.Sprintf("%s- %s\n", strings.Repeat("  ", indent+1), item))
		}
	}
	quoted := func(s string) string { return fmt.Sprintf("%q", s) }

	b.WriteString("# bacnet-shifter configuration. Every key is shown at its default; a key left\n")
	b.WriteString("# out takes it. The file is read from the directory the shifter starts in.\n")
	b.WriteString("# Durations are Go durations: 3s, 5m, 1h.\n\n")

	b.WriteString("# The site: the real BACnet network, reached through the bacnet library's client.\n")
	b.WriteString("site:\n")
	line(1, "adapter", quoted(f.Site.Adapter), "name or IPv4 address of the adapter on the site network; required unless sim is set")
	line(1, "port", fmt.Sprint(f.Site.Port), "UDP port on that adapter")
	line(1, "bbmd", quoted(f.Site.BBMD), "IP[:port] of a BBMD to register with as a foreign device, to reach a site on another subnet")
	line(1, "bbmd_ttl", duration(f.Site.BBMDTTL), "registration lifetime, renewed halfway through")
	list(1, "add", f.Site.Add, "IP[:port] of devices no Who-Is reaches, read at start as the explorer's -add does")
	line(1, "timeout", duration(f.Site.Timeout), "wait for each reply from the site")
	line(1, "retries", fmt.Sprint(f.Site.Retries), "resends of a read or a notification that got no reply; a write is never resent")
	line(1, "max_rps", fmt.Sprint(f.Site.MaxRPS), "requests the shifter sends the site in a second, all consumers together")
	line(1, "max_in_flight_net", fmt.Sprint(f.Site.MaxInFlightNet), "requests in flight at once to all the devices of one routed site network")
	line(1, "whois_interval", duration(f.Site.WhoIsInterval), "a consumer's Who-Is is forwarded to the site at most this often")
	line(1, "cov_lifetime", duration(f.Site.COVLifetime), "lifetime of the shifter's own subscriptions on the site, renewed by the client")
	b.WriteString("\n")

	b.WriteString("# The consumer side: the socket the shifter serves consumers on, as a router to the virtual network.\n")
	b.WriteString("consumer:\n")
	line(1, "adapter", quoted(f.Consumer.Adapter), "name or IPv4 address of the adapter on the consumer network; required unless sim is set; 127.0.0.1 for a consumer on this machine")
	line(1, "port", fmt.Sprint(f.Consumer.Port), "on Windows the two sides may share a port on two adapters; on Linux and macOS they cannot")
	line(1, "network", fmt.Sprint(f.Consumer.Network), "V: the virtual network the site's own IP subnet appears as; each site network behind a router gets a derived number of its own")
	line(1, "recent", duration(f.Consumer.Recent), "a new device or network is also announced by unicast to every consumer heard from within this long")
	line(1, "cov_max_lifetime", duration(f.Consumer.COVMaxLifetime), "ceiling on a consumer subscription's lifetime; 0 or absent in the request means this")
	b.WriteString("\n")

	b.WriteString("# What the shifter will send to the site: no-write | limited | full-service.\n")
	b.WriteString("# Each level includes the ones before it.\n")
	line(0, "control", f.Control, "")
	b.WriteString("\n")
	b.WriteString("# Directory for the key and table.json. It must be readable by the shifter's account only.\n")
	line(0, "data", f.Data, "")
	b.WriteString("\n")
	b.WriteString("log:\n")
	line(1, "level", f.Log.Level, "debug | info | warn | error")
	line(1, "frames", fmt.Sprint(f.Log.Frames), "log every datagram on both sockets, at debug")
	b.WriteString("\n")
	b.WriteString("# Run against the library's simulated devices on loopback instead of the adapters:\n")
	b.WriteString("# \"\" (off), default (sim.Start) or remote (sim.RemoteSite: a BBMD, a router and routed devices).\n")
	line(0, "sim", quoted(f.Sim), "")
	b.WriteString("\n")
	b.WriteString("# A daily survey of the site's addresses, the bacnet-survey utility run through the site client: one read\n")
	b.WriteString("# to each address, to find and announce the devices no Who-Is reaches. Results are logged, with no\n")
	b.WriteString("# survey history saved. To the network it looks like a port scan\n")
	b.WriteString("# of UDP 47808, and each vacant address on the subnet costs an ARP broadcast: tell whoever watches it.\n")
	b.WriteString("survey:\n")
	line(1, "enabled", fmt.Sprint(f.Survey.Enabled), "")
	line(1, "at", quoted(f.Survey.At), "local time of day, HH:MM")
	line(1, "on_start", fmt.Sprint(f.Survey.OnStart), "also run one when the shifter starts")
	list(1, "ranges", f.Survey.Ranges, "addresses to survey instead of the whole subnet of site.adapter: 192.168.1.20-192.168.1.60, or one address; those beyond the subnet are pinged too; required under sim")
	line(1, "rate", fmt.Sprint(f.Survey.Rate), "addresses tried in a second; a /24 takes half a minute at 10, a /16 two hours")
	b.WriteString("\n")
	b.WriteString("pseudonym:\n")
	list(1, "replaced", f.Pseudonym.Replaced, "properties whose character-string values are replaced with pseudonyms, on every object")
	b.WriteString("\n")
	b.WriteString("# The life-safety and alarm set: refused at every level, full-service included.\n")
	b.WriteString("reserved:\n")
	list(1, "services", f.Reserved.Services, "")
	list(1, "objects", f.Reserved.Objects, "")
	list(1, "properties", f.Reserved.Properties, "")
	return b.String()
}

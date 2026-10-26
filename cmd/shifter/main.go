// shifter is a BACnet anonymizing proxy: it sits between a site's BACnet/IP
// network and a consumer's, passes reads through, and replaces every name,
// description, device instance, address and network number of the site
// with a pseudonym on the way out. The README says what it does.
//
// It runs with no arguments and reads config.yaml from the directory it is
// started in; when the file is absent it writes one with every key at its
// default and exits. The one switch, -table, prints the table of pseudonyms
// and real values and exits:
//
//	shifter
//	shifter -table
//	shifter -table AHU
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/client/sim"

	"github.com/jonalfarlinga/bacnet-shifter/internal/audit"
	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/pseudonym"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/survey"
	"github.com/jonalfarlinga/bacnet-shifter/internal/table"
)

const configFile = "config.yaml"

func main() {
	flagTable := flag.Bool("table", false, "print the table, pseudonym and real side by side, and exit; a text after it keeps only the records that contain it")
	flag.Parse()
	if err := run(*flagTable, strings.Join(flag.Args(), " ")); err != nil {
		fmt.Fprintln(os.Stderr, "shifter:", err)
		os.Exit(1)
	}
}

func run(listTable bool, filter string) error {
	f, err := Load(configFile)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(configFile, []byte(Render(Defaults())), 0o644); err != nil {
			return err
		}
		abs, _ := filepath.Abs(configFile)
		fmt.Printf("wrote %s with every key at its default.\nSet site.adapter and consumer.adapter, or sim, and start again.\n", abs)
		return nil
	}
	if err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	var level slog.Level
	level.UnmarshalText([]byte(f.Log.Level))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := os.MkdirAll(f.Data, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	key, created, err := pseudonym.LoadOrCreate(filepath.Join(f.Data, "key"))
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	if created {
		logger.Warn("key file created; with table.json it is the de-anonymization secret, to back up and never copy to the consumer side", "path", filepath.Join(f.Data, "key"))
	}
	tb, err := table.Open(filepath.Join(f.Data, "table.json"), pseudonym.New(key), f.Consumer.Network)
	if err != nil {
		return fmt.Errorf("table: %w", err)
	}
	if listTable {
		return printTable(tb, filter)
	}

	cfg, cleanup, err := build(f, logger, tb)
	if err != nil {
		return err
	}
	defer cleanup()
	sh, err := shifter.Start(cfg)
	if err != nil {
		if inUse(err) {
			return fmt.Errorf("%w: another BACnet program on this machine has the port open", err)
		}
		return err
	}
	fmt.Printf("shifter: site side %s, consumer side %s, control %s, virtual network %d\n", sh.SiteAddr(), sh.ConsumerAddr(), cfg.Control, f.Consumer.Network)

	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	<-interrupted
	fmt.Println("shifter: stopping")
	return sh.Close()
}

// inUse reports whether err is a bind to an address that is taken.
func inUse(err error) bool {
	text := err.Error()
	return strings.Contains(text, "address already in use") || strings.Contains(text, "Only one usage of each socket address")
}

// printTable prints the listing.
func printTable(tb *table.Table, filter string) error {
	rows := tb.Listing(strings.TrimSpace(filter))
	if len(rows) == 0 {
		fmt.Println("no records")
		return nil
	}
	for _, r := range rows {
		fmt.Printf("%-8s %-44s %s  (first seen %s)\n", r.Kind, r.Pseudonym, r.Real, r.FirstSeen.Format(time.RFC3339))
	}
	return nil
}

// build turns the file into the shifter's configuration, opening the sim
// when the file asks for it. cleanup stops what build started.
func build(f File, logger *slog.Logger, tb *table.Table) (cfg shifter.Config, cleanup func(), err error) {
	cleanup = func() {}
	cfg = shifter.Config{
		WhoIsInterval: f.Site.WhoIsInterval, COVLifetime: f.Site.COVLifetime, MaxInFlightNet: f.Site.MaxInFlightNet,
		MaxSubscriptionsPerDevice: f.Site.MaxSubscriptionsPerDevice, MaxSubscriptions: f.Site.MaxSubscriptions,
		MaxNewDevicesPerMinute: f.Site.MaxNewDevicesPerMinute,
		Recent:                 f.Consumer.Recent, COVMaxLifetime: f.Consumer.COVMaxLifetime,
		MaxSubscriptionsPerSource: f.Consumer.MaxSubscriptionsPerSource,
		Table:                     tb, Logger: logger,
	}
	cfg.Consumer.MaxInFlight, cfg.Consumer.MaxRPSPerSource = f.Consumer.MaxInFlight, f.Consumer.MaxRPSPerSource
	cfg.Consumer.MaxSources, cfg.Consumer.SegmentTimeout = f.Consumer.MaxSources, f.Consumer.SegmentTimeout
	if cfg.Consumer.Allow, err = parsePrefixes(f.Consumer.Allow); err != nil {
		return cfg, cleanup, fmt.Errorf("consumer.allow: %w", err)
	}
	if cfg.Peers, err = parsePeers(f.Consumer.Peers, cfg.Control); err != nil {
		return cfg, cleanup, err
	}
	if cfg.WriteAllow, err = parseWriteAllow(f.Writes.Allow); err != nil {
		return cfg, cleanup, err
	}
	if f.Audit.File != "" {
		log, err := audit.Open(f.Audit.File)
		if err != nil {
			return cfg, cleanup, err
		}
		cfg.Audit = log
		cleanup = func() { log.Close() }
	}
	if cfg.Control, err = control.Parse(f.Control); err != nil {
		return cfg, cleanup, err
	}
	if cfg.Reserved, err = control.ParseReserved(f.Reserved.Services, f.Reserved.Objects, f.Reserved.Properties); err != nil {
		return cfg, cleanup, err
	}
	if cfg.PassThrough, err = control.ParsePassThrough(f.Pseudonym.PassThrough); err != nil {
		return cfg, cleanup, err
	}
	if cfg.Hidden, err = control.ParseHidden(f.Pseudonym.HiddenObjects); err != nil {
		return cfg, cleanup, err
	}
	cfg.Strict = f.Pseudonym.Strict
	cfg.Site.Timeout, cfg.Site.Retries, cfg.Site.MaxRequestsPerSec = f.Site.Timeout, f.Site.Retries, f.Site.MaxRPS
	cfg.Consumer.Timeout, cfg.Consumer.Retries = f.Site.Timeout, f.Site.Retries

	if f.Survey.Enabled {
		sv := &shifter.SurveyConfig{PerSec: f.Survey.Rate, OnStart: f.Survey.OnStart}
		if sv.At, err = survey.ParseClock(f.Survey.At); err != nil {
			return cfg, cleanup, fmt.Errorf("survey.at: %w", err)
		}
		if sv.Ranges, err = survey.ParseRangeList(f.Survey.Ranges); err != nil {
			return cfg, cleanup, fmt.Errorf("survey.ranges: %w", err)
		}
		cfg.Survey = sv
	}

	if f.Sim != "" {
		stations := sim.Default()
		if f.Sim == "remote" {
			stations = sim.RemoteSite(false)
		}
		network, err := sim.StartDevices(stations)
		if err != nil {
			return cfg, cleanup, fmt.Errorf("starting the simulated devices: %w", err)
		}
		cleanup = network.Close
		cfg.Site.Local = netip.MustParseAddrPort("127.0.0.1:0")
		cfg.Site.Broadcast = network.Addr()
		if f.Sim == "remote" {
			cfg.Site.ForeignDevice = &client.ForeignDeviceConfig{BBMD: network.Addr(), TTL: f.Site.BBMDTTL}
		}
		cfg.Consumer.Local = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.Consumer.Port)
		if cfg.Survey != nil {
			// The simulated devices are all at 127.0.0.1, on the first
			// station's port; nothing is this machine's own address.
			cfg.Survey.Subnet, cfg.Survey.Port = netip.MustParsePrefix("127.0.0.0/8"), network.Addr().Port()
		}
	} else {
		site, err := bindOn(f.Site.Adapter, f.Site.Port)
		if err != nil {
			return cfg, cleanup, fmt.Errorf("site.adapter: %w", err)
		}
		cfg.Site.Local, cfg.Site.BindAny, cfg.Site.Broadcast, cfg.Site.Exclude = site.Local, site.BindAny, site.Broadcast, site.Exclude
		if cfg.Survey != nil {
			cfg.Survey.Subnet, cfg.Survey.Local, cfg.Survey.Port = site.Subnet, site.Local.Addr(), f.Site.Port
		}
		if f.Site.BBMD != "" {
			bbmd, _ := parseAddrPort(f.Site.BBMD, f.Site.Port)
			cfg.Site.ForeignDevice = &client.ForeignDeviceConfig{BBMD: bbmd, TTL: f.Site.BBMDTTL}
		}
		for _, a := range f.Site.Add {
			ap, _ := parseAddrPort(a, f.Site.Port)
			cfg.Add = append(cfg.Add, client.Address{IP: ap})
		}
		consumer, err := bindOn(f.Consumer.Adapter, f.Consumer.Port)
		if err != nil {
			return cfg, cleanup, fmt.Errorf("consumer.adapter: %w", err)
		}
		cfg.Consumer.Local, cfg.Consumer.BindAny, cfg.Consumer.Broadcast, cfg.Consumer.Exclude = consumer.Local, consumer.BindAny, consumer.Broadcast, consumer.Exclude
	}
	if f.Log.Frames {
		cfg.Site.OnPacket = frames(logger.With("socket", "site"))
		cfg.Consumer.OnPacket = frames(logger.With("socket", "consumer"))
	}
	return cfg, cleanup, nil
}

// binding is where one side binds and broadcasts, and the subnet it is on.
type binding struct {
	Local     netip.AddrPort
	BindAny   bool
	Broadcast netip.AddrPort
	Exclude   []netip.Prefix
	Subnet    netip.Prefix
}

// bindOn says where a side binds, by the client's rules for the adapter
// named or addressed, or on loopback for a consumer on this machine: a
// loopback address binds there, with no broadcast.
func bindOn(adapter string, port uint16) (binding, error) {
	adapter = strings.TrimSpace(adapter)
	if ip, err := netip.ParseAddr(adapter); err == nil && ip.IsLoopback() {
		return binding{Local: netip.AddrPortFrom(ip, port), Subnet: netip.PrefixFrom(ip, 8)}, nil
	}
	ifc, err := client.FindInterface(adapter)
	if err != nil {
		return binding{}, err
	}
	c := ifc.Config(port)
	return binding{Local: c.Local, BindAny: c.BindAny, Broadcast: c.Broadcast, Exclude: c.Exclude, Subnet: ifc.Addr}, nil
}

// frames logs every datagram in hex at debug.
func frames(logger *slog.Logger) func(client.PacketEvent) {
	var mu sync.Mutex
	return func(e client.PacketEvent) {
		dir := "to"
		if e.Inbound {
			dir = "from"
		}
		mu.Lock()
		logger.Debug("frame", dir, e.Peer, "bytes", fmt.Sprintf("%x", e.Data))
		mu.Unlock()
	}
}

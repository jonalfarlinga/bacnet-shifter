package shifter_test

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client/sim"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
	"github.com/jonalfarlinga/bacnet-shifter/internal/survey"
)

// The survey finds a device the Who-Is never reaches, and the shifter
// proxies it: the site is the default sim less its legacy panel, which runs
// as a network of its own that the shifter's broadcast does not reach. The
// survey of 127.0.0.1 to 127.0.0.3 on that network's port finds the panel,
// which is then in the table and announced to the consumer under a pseudonym.
func TestSurveyFindsUnreached(t *testing.T) {
	stations := sim.Default()
	apart, err := sim.StartDevices(stations[3:])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(apart.Close)
	ranges, _ := survey.ParseRanges("127.0.0.1-127.0.0.3")
	b := harness.Start(t, harness.Options{
		Stations: stations[:3], Control: control.NoWrite,
		Survey: &shifter.SurveyConfig{
			Subnet: netip.MustParsePrefix("127.0.0.0/8"), Port: apart.Addr().Port(), Ranges: ranges,
			PerSec: 1000, At: -1,
		},
	})
	reached := b.AwaitDevices(simDevices-1, 5*time.Second)
	for _, d := range reached {
		if realOf(t, b, d).Instance == 4000 {
			t.Fatal("the legacy panel was heard without the survey; the test needs it out of the broadcast's reach")
		}
	}
	if _, ok := b.Shifter.Table().Device(4000); ok {
		t.Fatal("the legacy panel is in the table before the survey")
	}

	res, err := b.Shifter.RunSurvey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Tried != 3 || res.Total != 3 || res.Beyond != 0 || res.Stopped {
		t.Errorf("the survey counted %+v", res)
	}
	if len(res.Devices) != 1 || res.Devices[0].Addr != netip.MustParseAddr("127.0.0.1") || res.Devices[0].Instance != 4000 || res.Devices[0].Name != "BOILER-1" {
		t.Fatalf("the survey found %+v, want the legacy panel 4000 at 127.0.0.1", res.Devices)
	}

	// The panel is now a device of the shifter's: in the table, named, and
	// announced to the consumer, who reads it under its pseudonym.
	d, ok := b.Shifter.Table().Device(4000)
	if !ok {
		t.Fatal("the legacy panel is not in the table after the survey")
	}
	if d.Address.IP != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), apart.Addr().Port()).String() {
		t.Errorf("the panel is recorded at %s", d.Address.IP)
	}
	heard := b.AwaitDevices(simDevices, 5*time.Second)
	if _, ok := heard[d.Virtual]; !ok {
		t.Errorf("the consumer heard %v, not the panel's virtual instance %d", heard, d.Virtual)
	}
	values, err := b.Consumer.ReadProperty(b.Ctx(), heard[d.Virtual].Addr, deviceObject(d.Virtual), 77)
	if err != nil || len(values) != 1 || values[0].Str == "BOILER-1" || values[0].Str == "" {
		t.Errorf("the panel's name through the shifter is %v, %v; want a pseudonym", values, err)
	}

	// A second survey finds the same device and probes it no further: it
	// has been heard this run. The panel gets the knock and the reads of
	// its name, vendor and model, and nothing else: a ReadPropertyMultiple
	// it declines, being the legacy panel, and then one read each.
	before := len(b.SiteRec.Events())
	if _, err := b.Shifter.RunSurvey(context.Background()); err != nil {
		t.Fatal(err)
	}
	toPanel := 0
	for _, e := range b.SiteRec.Events()[before:] {
		if !e.Inbound && e.Peer == apart.Addr() {
			toPanel++
		}
	}
	if toPanel != 5 {
		t.Errorf("the second survey sent the panel %d datagrams, want the knock and the four name reads only", toPanel)
	}

	// A survey under a context that has ended returns what it found.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err = b.Shifter.RunSurvey(ctx)
	if err == nil || res == nil || !res.Stopped || res.Tried != 0 {
		t.Errorf("a stopped survey gave %+v, %v", res, err)
	}
}

// The schedule: a survey on start when asked, and the next at the time of
// day set, today or tomorrow.
func TestSurveySchedule(t *testing.T) {
	completed := make(chan struct{}, 1)
	stations := sim.Default()
	ranges, _ := survey.ParseRanges("127.0.0.1")
	b := harness.Start(t, harness.Options{
		Stations: stations[3:], Control: control.NoWrite,
		Logger: slog.New(slog.NewTextHandler(surveyScheduleLog{completed}, nil)),
		Survey: &shifter.SurveyConfig{
			Subnet: netip.MustParsePrefix("127.0.0.0/8"), Ranges: ranges,
			PerSec: 1000, At: 25 * time.Hour, OnStart: true,
		},
	})
	// The next scheduled survey is logged after the start-up run completes.
	select {
	case <-completed:
	case <-time.After(10 * time.Second):
		t.Fatal("the start-up survey did not complete in 10s")
	}
	// A second cannot start while one runs; after one, another may.
	if _, err := b.Shifter.RunSurvey(context.Background()); err != nil {
		t.Errorf("a survey after the start-up one failed: %v", err)
	}

	loc := time.FixedZone("test", 0)
	now := time.Date(2026, 10, 20, 1, 30, 0, 0, loc)
	if next := shifter.NextAt(now, 2*time.Hour); !next.Equal(time.Date(2026, 10, 20, 2, 0, 0, 0, loc)) {
		t.Errorf("at 01:30 the next 02:00 is %s", next)
	}
	if next := shifter.NextAt(now, time.Hour); !next.Equal(time.Date(2026, 10, 21, 1, 0, 0, 0, loc)) {
		t.Errorf("at 01:30 the next 01:00 is %s", next)
	}
	if next := shifter.NextAt(now, 90*time.Minute); !next.Equal(time.Date(2026, 10, 21, 1, 30, 0, 0, loc)) {
		t.Errorf("at 01:30 the next 01:30 is %s, want tomorrow", next)
	}
}

type surveyScheduleLog struct{ completed chan struct{} }

func (w surveyScheduleLog) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "next survey") {
		select {
		case w.completed <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

package shifter_test

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	// The transition tests need America/Chicago, which Windows does not
	// ship; the embedded database stands in.
	_ "time/tzdata"

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

// The schedule across daylight-saving transitions, in America/Chicago: the
// clock goes forward from 02:00 CST to 03:00 CDT on 2026-03-08, and back
// from 02:00 CDT to 01:00 CST on 2026-11-01. The survey runs at the hour
// the clock reads, not an elapsed number of hours after midnight; a time
// the clock skips is run at the first instant after the skip; a time the
// clock reads twice is run at the first reading, and once that day.
func TestSurveyScheduleDST(t *testing.T) {
	chicago, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatal(err)
	}
	utc := func(month time.Month, day, hour, minute int) time.Time {
		return time.Date(2026, month, day, hour, minute, 0, 0, time.UTC)
	}
	clock := func(hour, minute int) time.Duration {
		return time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		at   time.Duration
		want time.Time
	}{
		// Spring forward. 03:00 CST = 09:00 UTC on the day before; 03:00
		// CDT = 08:00 UTC on the day of.
		{"spring: an hour after the skip is on the clock", utc(time.March, 8, 7, 0), clock(3, 30), utc(time.March, 8, 8, 30)},
		{"spring: a time in the skip runs at its end", utc(time.March, 8, 7, 0), clock(2, 30), utc(time.March, 8, 8, 0)},
		{"spring: the day before, the skipped time exists", utc(time.March, 7, 7, 0), clock(2, 30), utc(time.March, 7, 8, 30)},
		{"spring: after it passes, tomorrow is at the skip's end", utc(time.March, 7, 9, 0), clock(2, 30), utc(time.March, 8, 8, 0)},
		{"spring: a later hour is not shifted", utc(time.March, 8, 7, 0), clock(23, 0), utc(time.March, 9, 4, 0)},
		// Fall back. 01:30 CDT = 06:30 UTC, then 01:30 CST = 07:30 UTC;
		// 03:00 CST = 09:00 UTC.
		{"autumn: the repeated time runs at its first reading", utc(time.November, 1, 5, 30), clock(1, 30), utc(time.November, 1, 6, 30)},
		{"autumn: after the first reading, not the second", utc(time.November, 1, 6, 30), clock(1, 30), utc(time.November, 2, 7, 30)},
		{"autumn: between the readings, still not the second", utc(time.November, 1, 7, 0), clock(1, 30), utc(time.November, 2, 7, 30)},
		{"autumn: a later hour is on the clock, not 25 hours in", utc(time.November, 1, 5, 30), clock(3, 0), utc(time.November, 1, 9, 0)},
		{"autumn: the day after is back to the standard offset", utc(time.November, 2, 5, 0), clock(2, 0), utc(time.November, 2, 8, 0)},
	} {
		got := shifter.NextAt(tc.now.In(chicago), tc.at)
		if !got.Equal(tc.want) {
			t.Errorf("%s: at %s the next %02d:%02d is %s, want %s", tc.name, tc.now.In(chicago).Format(time.RFC3339),
				int(tc.at/time.Hour), int(tc.at%time.Hour/time.Minute), got.Format(time.RFC3339), tc.want.In(chicago).Format(time.RFC3339))
		}
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

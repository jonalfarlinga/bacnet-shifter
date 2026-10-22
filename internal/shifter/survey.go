package shifter

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jonalfarlinga/bacnet/client"

	"github.com/jonalfarlinga/bacnet-shifter/internal/survey"
)

// SurveyConfig is the daily survey of the site's addresses (spec §9.2): the
// bacnet-survey utility run through the shifter's own site client, so that
// devices no Who-Is reaches are found and announced. It is off when nil.
type SurveyConfig struct {
	// Subnet is the site adapter's, and Local the shifter's address on it,
	// which is not tried; Local may be left invalid when there is none.
	Subnet netip.Prefix
	Local  netip.Addr
	// Port is the devices' port; 0 is 47808.
	Port uint16
	// Ranges is the addresses to survey instead of the whole subnet.
	Ranges []survey.Range
	// PerSec is the pace, addresses a second; 0 is survey.DefaultPerSec.
	PerSec float64
	// At is the local time of day the survey runs each day, as the time
	// since midnight. Negative runs none on a schedule: only OnStart and
	// RunSurvey do.
	At time.Duration
	// OnStart runs a survey when the shifter starts as well.
	OnStart bool
}

// surveyor runs the surveys: on the schedule, and on demand.
type surveyor struct {
	s   *Shifter
	cfg SurveyConfig
}

// startSurveys starts the schedule, and the start-up survey if asked for.
func (s *Shifter) startSurveys() {
	if s.cfg.Survey == nil {
		return
	}
	sv := &surveyor{s: s, cfg: *s.cfg.Survey}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		sv.loop()
	}()
}

// loop runs the start-up survey, then one a day at the time set, until the
// shifter closes. A survey that runs past the next time slot is not run
// twice; the schedule picks up at the slot after it ends.
func (sv *surveyor) loop() {
	ctx := sv.s.ctx
	if sv.cfg.OnStart {
		if _, err := sv.s.RunSurvey(ctx); err != nil && ctx.Err() == nil {
			sv.s.log.Warn("the start-up survey failed", "error", err)
		}
	}
	if sv.cfg.At < 0 {
		return
	}
	for {
		next := NextAt(time.Now(), sv.cfg.At)
		sv.s.log.Info("next survey", "at", next.Format(time.RFC3339))
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if _, err := sv.s.RunSurvey(ctx); err != nil && ctx.Err() == nil {
			sv.s.log.Warn("the daily survey failed", "error", err)
		}
	}
}

// NextAt is the next occurrence of a local time of day after now, today
// or tomorrow.
func NextAt(now time.Time, at time.Duration) time.Time {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	next := day.Add(at)
	if !next.After(now) {
		next = day.AddDate(0, 0, 1).Add(at)
	}
	return next
}

// RunSurvey runs one survey now and feeds every BACnet device it found
// into discovery, so that one no Who-Is reached is announced to consumers.
// Results are kept in memory and logged. A survey stopped by ctx returns
// what it found by then with the context's error.
func (s *Shifter) RunSurvey(ctx context.Context) (*survey.Result, error) {
	if s.cfg.Survey == nil {
		return nil, errors.New("no survey is configured")
	}
	cfg := *s.cfg.Survey
	s.mu.Lock()
	if s.surveying != nil {
		s.mu.Unlock()
		return nil, errors.New("a survey is already running")
	}
	sv, err := survey.New(survey.Options{
		Client: s.site, Subnet: cfg.Subnet, Local: cfg.Local, Port: cfg.Port, Ranges: cfg.Ranges,
		PerSec: cfg.PerSec, Timeout: s.cfg.Site.Timeout, Logger: s.log.With("task", "survey"),
		Progress: func(p survey.Progress) {
			if p.Identifying {
				s.log.Debug("survey: all addresses tried; reading the devices found", "devices", p.Devices)
				return
			}
			s.log.Debug("survey", "tried", p.Tried, "total", p.Total, "at", p.At, "devices", p.Devices, "hosts", p.Hosts)
		},
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.surveying = sv
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.surveying = nil
		s.mu.Unlock()
	}()

	perSec := cfg.PerSec
	if perSec <= 0 {
		perSec = survey.DefaultPerSec
	}
	takes := time.Duration(float64(sv.Total())/perSec) * time.Second
	s.log.Info("survey started", "addresses", sv.Total(), "about", takes.Round(time.Minute).String(), "rate", perSec)

	res, runErr := sv.Run(ctx)
	s.log.Info("survey done", "result", res.Summary())
	for _, d := range res.Devices {
		s.log.Info("survey: BACnet device", "address", d.Addr, "mac", d.MAC, "which", survey.Describe(d))
	}
	if ctx.Err() == nil {
		s.adopt(ctx, res, cfg.Port)
	}
	return res, runErr
}

// adopt feeds the devices a survey found into discovery: each one that said
// which device it is and has not been heard this run is probed, as an
// address in site.add is, and so gets its pseudonyms and its announcement.
func (s *Shifter) adopt(ctx context.Context, res *survey.Result, port uint16) {
	if port == 0 {
		port = client.DefaultPort
	}
	for _, d := range res.Devices {
		if ctx.Err() != nil {
			return
		}
		if d.Unnamed {
			s.log.Warn("survey: a BACnet device would not say which it is, and cannot be proxied", "address", d.Addr)
			continue
		}
		s.mu.Lock()
		heard := s.heard[d.Instance]
		s.mu.Unlock()
		if heard {
			continue
		}
		addr := client.Address{IP: netip.AddrPortFrom(d.Addr, port)}
		pctx, cancel := context.WithTimeout(ctx, time.Minute)
		dev, err := s.site.Probe(pctx, addr, d.Instance)
		cancel()
		if err != nil {
			s.log.Warn("survey: the device found did not answer the probe", "address", addr, "instance", d.Instance, "error", err)
			continue
		}
		s.log.Info("survey: device found that no Who-Is reached", "address", addr, "instance", d.Instance, "name", d.Name)
		s.discovered(dev)
	}
}

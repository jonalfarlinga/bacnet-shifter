package shifter_test

import (
	"bytes"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jonalfarlinga/bacnet/client"
	"github.com/jonalfarlinga/bacnet/objects"

	"github.com/jonalfarlinga/bacnet-shifter/internal/control"
	"github.com/jonalfarlinga/bacnet-shifter/internal/harness"
	"github.com/jonalfarlinga/bacnet-shifter/internal/shifter"
)

// lockedBuffer is a bytes.Buffer the log may write from any goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// With the redaction a run that discovers the site, serves a write and
// refuses one logs no real name, instance or address; without it, it does.
func TestLogWithoutRealValues(t *testing.T) {
	for _, redact := range []bool{true, false} {
		var out lockedBuffer
		opts := &slog.HandlerOptions{Level: slog.LevelDebug}
		if redact {
			opts.ReplaceAttr = shifter.RedactReal
		}
		b := harness.Start(t, harness.Options{Control: control.FullService, Writer: &harness.FakeWriter{}, Logger: slog.New(slog.NewTextHandler(&out, opts)),
			Configure: func(cfg *shifter.Config) { cfg.RedactLog = redact }})
		heard := b.AwaitDevices(simDevices, 10*time.Second)
		ahu := deviceByReal(t, b, heard, 1001)
		ctx := b.Ctx()
		b.Consumer.ReadProperty(ctx, ahu.Addr, deviceObject(ahu.Instance), objects.PropertyIdObjectName)
		if _, err := b.Consumer.SubscribeCOV(ctx, ahu.Addr, supplyAir, client.COVOptions{}, func(client.COVNotification) {}); err != nil {
			t.Fatal(err)
		}
		siteAddr := b.Sim.Addr().String()
		b.Close()
		log := out.String()
		if !bytes.Contains([]byte(log), []byte("device")) {
			t.Fatalf("redact %t: the log has no device line:\n%s", redact, log)
		}
		real := []string{"AHU-1", siteAddr, "instance=1001", "real=1001"}
		for _, s := range real {
			found := bytes.Contains([]byte(log), []byte(s))
			if redact && found {
				t.Errorf("redacted log carries %q", s)
			}
		}
		if !redact && !bytes.Contains([]byte(log), []byte("AHU-1")) {
			t.Error("the unredacted log has no real name")
		}
		if redact && !bytes.Contains([]byte(log), []byte("virtual="+strconv.Itoa(int(ahu.Instance)))) {
			t.Error("the redacted log lost the virtual instance too")
		}
	}
}

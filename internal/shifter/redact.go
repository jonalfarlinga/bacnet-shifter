package shifter

import (
	"context"
	"log/slog"
)

// RealKeys are the log attributes whose values are the site's real
// names, instances and addresses, beside the pseudonyms: what a log that
// leaves the host must not carry. "device" is the real instance in the
// subscription and write lines, where "virtual" is the pseudonym;
// "instance", "address", "old", "new" and "first" are a device's real
// instance and addresses in the discovery lines; "name" and "which" are
// real names; "real" is the real side of any pair.
var RealKeys = map[string]bool{
	"real": true, "name": true, "instance": true, "device": true, "address": true,
	"old": true, "new": true, "first": true, "which": true, "mac": true,
}

// Redacted is the value a real one is replaced by.
const Redacted = "[real]"

// RedactReal is a ReplaceAttr for slog.HandlerOptions that replaces every
// real value with Redacted, for log.real_values: false. The error text of
// a request the site did not answer may still name a site address, and
// the frames log is the datagrams themselves; the README says so.
func RedactReal(_ []string, a slog.Attr) slog.Attr {
	if RealKeys[a.Key] {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// siteHandler is the handler of the site client's logger under
// redaction: the library's lines are about site devices and their
// addresses under keys of the library's own, so every attribute but the
// side goes, and the message stays.
type siteHandler struct {
	inner slog.Handler
}

func (h siteHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h siteHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "side" {
			out.AddAttrs(a)
		} else {
			out.AddAttrs(slog.String(a.Key, Redacted))
		}
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h siteHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return siteHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h siteHandler) WithGroup(name string) slog.Handler {
	return siteHandler{inner: h.inner.WithGroup(name)}
}

// siteLogger is the logger the site client gets: the shifter's, marked
// as the site side, and under redaction with every attribute blanked.
func siteLogger(base *slog.Logger, redact bool) *slog.Logger {
	l := base.With("side", "site")
	if !redact {
		return l
	}
	return slog.New(siteHandler{inner: l.Handler()})
}

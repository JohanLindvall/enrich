package enrich

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandKlogTime(t *testing.T) {
	june := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "20260615 12:00:00", expandKlogTime("0615 12:00:00", june))

	// A December timestamp seen in January belongs to the previous year.
	january := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "20251231 23:59:59", expandKlogTime("1231 23:59:59", january))

	// A January timestamp seen in December belongs to the next year.
	december := time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "20270101 00:00:01", expandKlogTime("0101 00:00:01", december))
}

func TestParseLayoutTime(t *testing.T) {
	clp := &compiledLineParser{ts: []string{time.RFC3339Nano, "2006-01-02 15:04:05"}}

	// A 'T'-separated timestamp matches the RFC3339Nano layout.
	ts, ok := clp.parseLayoutTime("2026-07-06T12:00:00Z")
	require.True(t, ok)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", ts.String())

	// A space-separated timestamp skips the RFC3339Nano layout (the 'T'
	// disagreement at index 10) and matches the second layout.
	ts, ok = clp.parseLayoutTime("2026-07-06 12:00:00")
	require.True(t, ok)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", ts.String())

	// No layout matches.
	_, ok = clp.parseLayoutTime("not a timestamp")
	assert.False(t, ok)
}

func TestParseSyslogTime(t *testing.T) {
	ts, ok := parseSyslogTime("1700000000.5")
	require.True(t, ok)
	assert.Equal(t, time.Unix(1700000000, 500000000).UTC(), ts)

	_, ok = parseSyslogTime("abc")
	assert.False(t, ok)
}

func TestParse_Librdkafka(t *testing.T) {
	enriched := Parse(`%4|1700000000.123|FAIL|rdkafka#producer-1| [thrd:main]: broker connection down`)
	assert.Equal(t, "warn", enriched.Severity)
	// The syslog timestamp goes through a float64, so allow sub-ms rounding.
	assert.WithinDuration(t, time.Unix(1700000000, 123000000).UTC(), enriched.Time, time.Millisecond)
}

func TestParseException_NoType(t *testing.T) {
	// A first line without ": " carries only a message; a second line becomes
	// the stack trace.
	var r Result
	r.parseException("something went wrong\nat main.go:1")
	assert.Empty(t, r.ExceptionType)
	assert.Equal(t, "something went wrong", r.ExceptionMessage)
	assert.Equal(t, "at main.go:1", r.ExceptionStackTrace)
}

func TestApplySubmatch_TimeWithoutLayouts(t *testing.T) {
	// A parser with named time group but no layouts leaves the time untouched.
	clp := &compiledLineParser{re: regexp.MustCompile(`x`)}
	var r Result
	clp.applySubmatch(&r, "time", "2026-07-06 12:00:00", "line")
	assert.True(t, r.Time.IsZero())
}

func TestWarnParseFailure_RateLimited(t *testing.T) {
	clp := compiledLineParsers[0]
	before := clp.lastWrn
	clp.warnParseFailure("some line")
	require.NotEqual(t, before, clp.lastWrn, "first call warns and stamps lastWrn")

	stamped := clp.lastWrn
	clp.warnParseFailure("another line")
	assert.Equal(t, stamped, clp.lastWrn, "a second call within ten minutes is suppressed")
}

func TestApplySubmatch_BadTime(t *testing.T) {
	// A time submatch that fails every layout leaves the time zero and logs
	// the (rate-limited) warning.
	clp := &compiledLineParser{re: regexp.MustCompile(`x`), ts: []string{time.RFC3339Nano}}
	var r Result
	clp.applySubmatch(&r, "time", "garbage", "line")
	assert.True(t, r.Time.IsZero())
}

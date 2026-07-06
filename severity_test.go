package enrich

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSeverityText(t *testing.T) {
	testCases := []struct {
		in   int
		want string
	}{
		{0, ""},
		{1, TraceLevel},
		{4, TraceLevel},
		{5, DebugLevel},
		{9, InfoLevel},
		{13, WarnLevel},
		{17, ErrorLevel},
		{21, FatalLevel},
		{24, FatalLevel},
		{25, ""},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, GetSeverityText(tc.in), "severity %d", tc.in)
	}
}

func TestGetSyslogSeverityText(t *testing.T) {
	testCases := []struct {
		in   string
		want string
	}{
		{"0", FatalLevel},
		{"1", FatalLevel},
		{"2", FatalLevel},
		{"3", ErrorLevel},
		{"4", WarnLevel},
		{"5", InfoLevel},
		{"6", InfoLevel},
		{"7", DebugLevel},
		{"8", ""},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, getSyslogSeverityText(tc.in), "syslog level %s", tc.in)
	}
}

func TestParseUnixTime(t *testing.T) {
	ts, ok := parseUnixTime("1700000000")
	require.True(t, ok)
	assert.Equal(t, time.Unix(1700000000, 0).UTC(), ts)

	// A fractional part shorter than nanosecond precision is right-padded.
	ts, ok = parseUnixTime("1700000000.5")
	require.True(t, ok)
	assert.Equal(t, time.Unix(1700000000, 500000000).UTC(), ts)

	ts, ok = parseUnixTime("1700000000.123456789")
	require.True(t, ok)
	assert.Equal(t, time.Unix(1700000000, 123456789).UTC(), ts)

	_, ok = parseUnixTime("abc")
	assert.False(t, ok)

	_, ok = parseUnixTime("1700000000.xyz")
	assert.False(t, ok)
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

package enrich

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeverityFromNumber(t *testing.T) {
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
		assert.Equal(t, tc.want, SeverityFromNumber(tc.in), "severity %d", tc.in)
	}
}

func TestSeverityFromText(t *testing.T) {
	testCases := []struct {
		in     string
		want   string
		wantNo int
	}{
		{"", "", 0},
		{"unknown", "", 0},
		{"trc", TraceLevel, TraceLevelNo},
		{"TRACE", TraceLevel, TraceLevelNo},
		{"d", DebugLevel, DebugLevelNo},
		{"dbg", DebugLevel, DebugLevelNo},
		{"Debug", DebugLevel, DebugLevelNo},
		{"i", InfoLevel, InfoLevelNo},
		{"info", InfoLevel, InfoLevelNo},
		{"Information", InfoLevel, InfoLevelNo},
		{"informational", InfoLevel, InfoLevelNo},
		{"normal", InfoLevel, InfoLevelNo},
		{"log", InfoLevel, InfoLevelNo},
		{"w", WarnLevel, WarnLevelNo},
		{"WRN", WarnLevel, WarnLevelNo},
		{"Warning", WarnLevel, WarnLevelNo},
		{"e", ErrorLevel, ErrorLevelNo},
		{"err", ErrorLevel, ErrorLevelNo},
		{"ERROR", ErrorLevel, ErrorLevelNo},
		// Fatal aliases must still normalize to fatal.
		{"fatal", FatalLevel, FatalLevelNo},
		{"FATAL", FatalLevel, FatalLevelNo},
		{"f", FatalLevel, FatalLevelNo},
		{"ftl", FatalLevel, FatalLevelNo},
		{"crit", FatalLevel, FatalLevelNo},
		{"critical", FatalLevel, FatalLevelNo},
		{"panic", FatalLevel, FatalLevelNo},
		{"pnc", FatalLevel, FatalLevelNo},
		// Regression: the unanchored fatal alternation used to match any string
		// containing "f", "crit" or "panic" (e.g. the "[configuration]" tag from
		// the Go standard logger). These must NOT be classified as fatal.
		{"configuration", "", 0},
		{"default", "", 0},
		{"profile", "", 0},
		{"critique", "", 0},
		{"panicking", "", 0},
	}
	for _, tc := range testCases {
		got, gotNo := SeverityFromText(tc.in)
		assert.Equal(t, tc.want, got, "severity %q", tc.in)
		assert.Equal(t, tc.wantNo, gotNo, "severity number %q", tc.in)
	}
}

func TestHTTPStatusSeverity(t *testing.T) {
	testCases := []struct {
		code int64
		kind StatusKind
		want string
	}{
		{0, StatusObserved, ErrorLevel},  // Envoy: no response at all
		{100, StatusObserved, InfoLevel}, // informational
		{200, StatusObserved, InfoLevel}, // success
		{304, StatusObserved, InfoLevel}, // redirect
		{404, StatusObserved, WarnLevel}, // client error, merely observed
		{404, StatusFailure, ErrorLevel}, // client error, reported as the failure
		{500, StatusObserved, WarnLevel}, // server error
		{500, StatusFailure, WarnLevel},  // StatusFailure only escalates 4xx
		{50, StatusObserved, WarnLevel},  // below 100 but valid range
		{-1, StatusObserved, ""},         // out of range
		{600, StatusObserved, ""},        // out of range
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, HTTPStatusSeverity(tc.code, tc.kind), "code %d kind %v", tc.code, tc.kind)
	}
}

func TestParseHTTPResponseSeverity(t *testing.T) {
	assert.Equal(t, InfoLevel, parseHTTPResponseSeverity("200", StatusObserved))
	assert.Equal(t, ErrorLevel, parseHTTPResponseSeverity("404", StatusFailure))
	assert.Equal(t, "", parseHTTPResponseSeverity("abc", StatusObserved), "non-numeric")
	assert.Equal(t, "", parseHTTPResponseSeverity("9999", StatusObserved), "out of range")
}

func TestSyslogSeverity(t *testing.T) {
	testCases := []struct {
		in     int
		want   string
		wantNo int
	}{
		{0, FatalLevel, FatalLevelNo},
		{1, FatalLevel, FatalLevelNo},
		{2, FatalLevel, FatalLevelNo},
		{3, ErrorLevel, ErrorLevelNo},
		{4, WarnLevel, WarnLevelNo},
		{5, InfoLevel, Info2LevelNo}, // notice: finer-grained INFO2
		{6, InfoLevel, InfoLevelNo},
		{7, DebugLevel, DebugLevelNo},
		{8, "", 0},
	}
	for _, tc := range testCases {
		got, gotNo := syslogSeverity(tc.in)
		assert.Equal(t, tc.want, got, "syslog level %d", tc.in)
		assert.Equal(t, tc.wantNo, gotNo, "syslog level %d number", tc.in)
	}
}

func TestPinoSeverity(t *testing.T) {
	testCases := []struct {
		in   string
		want string
	}{
		{`{"level":10,"msg":"x"}`, TraceLevel},
		{`{"level":20,"msg":"x"}`, DebugLevel},
		{`{"level":30,"msg":"x"}`, InfoLevel},
		{`{"level":40,"msg":"x"}`, WarnLevel},
		{`{"level":50,"msg":"x"}`, ErrorLevel},
		{`{"level":60,"msg":"x"}`, FatalLevel},
		{`{"level":35,"msg":"x"}`, InfoLevel}, // custom in-between level
		{`{"level":70,"msg":"x"}`, ""},        // out of range
		{`{"level":300,"msg":"x"}`, ""},       // too many digits
		{`{"level":"info","msg":"x"}`, ""},    // textual: handled by the decoder
		{`{"msg":"no level here"}`, ""},       // absent
		{`{"msg":"\"level\":30 quoted"}`, ""}, // escaped quote cannot match
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, pinoSeverity(tc.in), "line %s", tc.in)
	}
}

func TestGetRedisSeverityText(t *testing.T) {
	testCases := []struct {
		in   string
		want string
	}{
		{".", DebugLevel},
		{"-", DebugLevel},
		{"*", InfoLevel},
		{"#", WarnLevel},
		{"!", ""},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, getRedisSeverityText(tc.in), "redis level %q", tc.in)
	}
}

// TestSeverityLUTMatchesRegexes pins the fast-path LUT to the regex table: for
// every LUT key and its case variants, both paths must agree, and forms the
// LUT misses (digit suffixes, unknown words) must reach the regexes unchanged.
func TestSeverityLUTMatchesRegexes(t *testing.T) {
	regexWalk := func(input string) (string, int) {
		for _, reg := range normalizeReg {
			if reg.regexp.MatchString(input) {
				return reg.replace, reg.number
			}
		}
		return "", 0
	}
	variants := func(s string) []string {
		return []string{s, strings.ToUpper(s), strings.ToTitle(s[:1]) + s[1:]}
	}
	for key := range severityLUT {
		for _, v := range variants(key) {
			gotText, gotNo := SeverityFromText(v)
			wantText, wantNo := regexWalk(v)
			assert.Equal(t, wantText, gotText, "severity %q", v)
			assert.Equal(t, wantNo, gotNo, "severity %q", v)
		}
	}
	for _, v := range []string{"trace2", "TRC1", "dbg3", "debug10", "informative", "warned", "eror", "x", "", "įnfo", "informationall"} {
		gotText, gotNo := SeverityFromText(v)
		wantText, wantNo := regexWalk(v)
		assert.Equal(t, wantText, gotText, "severity %q", v)
		assert.Equal(t, wantNo, gotNo, "severity %q", v)
	}
}

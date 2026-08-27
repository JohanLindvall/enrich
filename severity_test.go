package enrich

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		// Microsoft.Extensions.Logging's console-formatter spellings.
		{"trce", TraceLevel, TraceLevelNo},
		{"dbug", DebugLevel, DebugLevelNo},
		{"fail", ErrorLevel, ErrorLevelNo},
		{"failed", "", 0},
		{"failure", "", 0},
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
		code int
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

func TestSetHTTPResponseCode(t *testing.T) {
	// The code is recorded whatever the severity ends up being.
	var r Result
	setHTTPResponseCode(&r, 200, StatusObserved)
	assert.Equal(t, InfoLevel, r.Severity)
	assert.Equal(t, 200, r.HTTPStatusCode)

	r = Result{Severity: DebugLevel}
	setHTTPResponseCode(&r, 404, StatusObserved)
	assert.Equal(t, DebugLevel, r.Severity, "an explicit level is not overridden by an observed code")
	assert.Equal(t, 404, r.HTTPStatusCode)

	r = Result{Severity: DebugLevel}
	setHTTPResponseCode(&r, 404, StatusFailure)
	assert.Equal(t, ErrorLevel, r.Severity, "a reported failure does override it")

	// Values that are not HTTP statuses are not recorded as one.
	r = Result{}
	setHTTPResponseCode(&r, 0, StatusObserved)
	assert.Equal(t, ErrorLevel, r.Severity, "no response at all")
	assert.Zero(t, r.HTTPStatusCode)
	setHTTPResponseCode(&r, 9999, StatusObserved)
	assert.Zero(t, r.HTTPStatusCode)
}

func TestSyslogSeverity(t *testing.T) {
	testCases := []struct {
		in     int
		want   string
		wantNo int
	}{
		// The three fatal syslog severities keep their grading in the OTLP
		// number, as the OpenTelemetry logs data model maps them.
		{0, FatalLevel, Fatal3LevelNo}, // emergency
		{1, FatalLevel, Fatal2LevelNo}, // alert
		{2, FatalLevel, FatalLevelNo},  // critical
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

func TestRedisSeverity(t *testing.T) {
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
		assert.Equal(t, tc.want, redisSeverity(tc.in), "redis level %q", tc.in)
	}
}

// normalizeReg is the original implementation, kept here as the oracle for the
// lookup table that replaced it in severity.go. The table must accept exactly
// the same language — including the accidental "infrmation"/"wrning" forms
// these patterns allow.
var normalizeReg = []struct {
	regexp  *regexp.Regexp
	replace string
	number  int
}{
	{regexp.MustCompile(`^(?i)(trace?|trc)\d*$`), TraceLevel, TraceLevelNo},
	{regexp.MustCompile(`^(?i)(d|debug?|dbg)\d*$`), DebugLevel, DebugLevelNo},
	{regexp.MustCompile(`^(?i)(i(nfo?(rmation(al)?)?)?)$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)normal$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)log$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)(w(a?rn(ing)?)?)$`), WarnLevel, WarnLevelNo},
	{regexp.MustCompile(`^(?i)(e(rr(or)?)?)$`), ErrorLevel, ErrorLevelNo},
	{regexp.MustCompile(`^(?i)(fatal|f(tl)?|crit(ical)?|panic|pnc)$`), FatalLevel, FatalLevelNo},

	// Added after the table replaced the regexes; kept in the same form so the
	// differential test covers the whole accepted language, not just its
	// historical core.
	{regexp.MustCompile(`^(?i)(notice|ntc)$`), InfoLevel, Info2LevelNo},
	{regexp.MustCompile(`^(?i)alert$`), FatalLevel, Fatal2LevelNo},
	{regexp.MustCompile(`^(?i)emerg(ency)?$`), FatalLevel, Fatal3LevelNo},
	{regexp.MustCompile(`^(?i)(verbose|vrb)$`), TraceLevel, TraceLevelNo},
	{regexp.MustCompile(`^(?i)severe$`), ErrorLevel, ErrorLevelNo},
	{regexp.MustCompile(`^(?i)fine$`), DebugLevel, DebugLevelNo},
	{regexp.MustCompile(`^(?i)fine(r|st)$`), TraceLevel, TraceLevelNo},

	// Microsoft.Extensions.Logging's console-formatter abbreviations. The
	// trace and debug ones take the same numeric suffix every other spelling
	// of their level does; "fail" does not, because only trace and debug are
	// graded that way.
	{regexp.MustCompile(`^(?i)trce\d*$`), TraceLevel, TraceLevelNo},
	{regexp.MustCompile(`^(?i)dbug\d*$`), DebugLevel, DebugLevelNo},
	{regexp.MustCompile(`^(?i)fail$`), ErrorLevel, ErrorLevelNo},
}

func regexSeverity(input string) (string, int) {
	for _, reg := range normalizeReg {
		if reg.regexp.MatchString(input) {
			return reg.replace, reg.number
		}
	}
	return "", 0
}

// TestSeverityLUTMatchesRegexes differential-tests the lookup table against the
// regexes it replaced: every LUT key and its case variants, hand-picked edge
// cases, and a large randomized sweep over the alphabet the patterns are built
// from (plus digits, which only trace and debug accept as a suffix).
func TestSeverityLUTMatchesRegexes(t *testing.T) {
	check := func(v string) {
		t.Helper()
		gotText, gotNo := SeverityFromText(v)
		wantText, wantNo := regexSeverity(v)
		assert.Equal(t, wantText, gotText, "severity %q", v)
		assert.Equal(t, wantNo, gotNo, "severity number %q", v)
	}

	for key := range severityLUT {
		for _, v := range []string{key, strings.ToUpper(key), strings.ToTitle(key[:1]) + key[1:]} {
			check(v)
		}
	}
	for _, v := range []string{
		"trace2", "TRC1", "dbg3", "debug10", "d1", "D5", "info2", "warn1", "e9",
		"informative", "warned", "eror", "x", "", "įnfo", "informationall",
		"configuration", "upstream", "0", "42", "-", "trace-", "f", "log",
	} {
		check(v)
	}

	// Randomized sweep over the pattern alphabet: any disagreement between the
	// table and the regexes shows up here.
	const alphabet = "abcdefgilmnoprstuvwy0123456789"
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 0, 14)
	for i := 0; i < 500000; i++ {
		buf = buf[:0]
		for n := rng.Intn(14); n > 0; n-- {
			buf = append(buf, alphabet[rng.Intn(len(alphabet))])
		}
		check(string(buf))
	}
}

// The perfect-hash table's collision guard is a maintainer safety net: a new
// spelling whose hash lands on an occupied slot must panic at init with
// replacement constants, never silently shadow an existing key. Rebuild the
// table with a deliberately colliding spelling and check both halves of that
// promise. The globals are snapshotted and restored; tests in this package
// never run in parallel.
func TestBuildSevTablePanicsOnCollision(t *testing.T) {
	// Find a spelling that is not in the LUT but hashes onto an occupied slot.
	used := map[uint32]bool{}
	for key := range severityLUT {
		used[sevHash(key)] = true
	}
	collider := ""
search:
	for a := byte('a'); a <= 'z'; a++ {
		for b := byte('a'); b <= 'z'; b++ {
			cand := string([]byte{a, b})
			if _, exists := severityLUT[cand]; !exists && used[sevHash(cand)] {
				collider = cand
				break search
			}
		}
	}
	require.NotEmpty(t, collider, "no two-letter collider found; widen the search")

	saved := sevTable
	sevTable = [sevTableSize]sevSlot{}
	severityLUT[collider] = struct {
		text string
		no   int
	}{InfoLevel, InfoLevelNo}
	defer func() {
		delete(severityLUT, collider)
		sevTable = saved
		r := recover()
		if assert.NotNil(t, r, "buildSevTable accepted a colliding spelling") {
			msg := fmt.Sprint(r)
			assert.Contains(t, msg, strconv.Quote(collider))
			assert.Contains(t, msg, "sevHashLen=", "the panic must carry replacement constants")
		}
	}()
	buildSevTable()
	t.Fatal("unreachable: buildSevTable must panic")
}

// searchSevHash only ever runs on the collision panic path; hold it to its
// promise anyway: the constants it prints must really be injective over the
// current spellings, or the panic would hand a maintainer broken advice.
func TestSearchSevHashFindsInjectiveConstants(t *testing.T) {
	found := searchSevHash()
	var a, b, c, size uint32
	n, err := fmt.Sscanf(found, "sevHashLen=%d sevHashFirst=%d sevHashLast=%d sevTableSize=%d", &a, &b, &c, &size)
	require.NoError(t, err, "searchSevHash returned %q", found)
	require.Equal(t, 4, n)
	seen := map[uint32]string{}
	for k := range severityLUT {
		h := (uint32(len(k))*a + uint32(k[0])*b + uint32(k[len(k)-1])*c) % size
		if prev, dup := seen[h]; dup {
			t.Fatalf("constants %q collide for %q and %q", found, prev, k)
		}
		seen[h] = k
	}
}

// The severity numbers must line up with the OpenTelemetry SeverityNumber
// values (TRACE=1..4, DEBUG=5..8, INFO=9..12, WARN=13..16, ERROR=17..20,
// FATAL=21..24), and every number in a level's range must resolve back to it.
func TestSeverityNumbersFollowOTLP(t *testing.T) {
	assert.Equal(t, 1, TraceLevelNo)
	assert.Equal(t, 5, DebugLevelNo)
	assert.Equal(t, 9, InfoLevelNo)
	assert.Equal(t, 10, Info2LevelNo)
	assert.Equal(t, 13, WarnLevelNo)
	assert.Equal(t, 17, ErrorLevelNo)
	assert.Equal(t, 21, FatalLevelNo)
	assert.Equal(t, 24, Fatal4LevelNo)

	for _, r := range []struct {
		first, last int
		level       string
	}{
		{TraceLevelNo, Trace4LevelNo, TraceLevel},
		{DebugLevelNo, Debug4LevelNo, DebugLevel},
		{InfoLevelNo, Info4LevelNo, InfoLevel},
		{WarnLevelNo, Warn4LevelNo, WarnLevel},
		{ErrorLevelNo, Error4LevelNo, ErrorLevel},
		{FatalLevelNo, Fatal4LevelNo, FatalLevel},
	} {
		assert.Equal(t, r.first+3, r.last, "%s range is four wide", r.level)
		for n := r.first; n <= r.last; n++ {
			assert.Equal(t, r.level, SeverityFromNumber(n), "number %d", n)
		}
	}
}

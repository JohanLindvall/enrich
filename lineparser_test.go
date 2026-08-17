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
	clp := &compiledLineParser{ts: []tsLayout{
		{time.RFC3339Nano, true},
		{"2006-01-02 15:04:05", false},
	}}

	// A 'T'-separated timestamp matches the RFC3339Nano layout, which carries
	// a zone.
	ts, zoned, ok := clp.parseLayoutTime("2026-07-06T12:00:00Z")
	require.True(t, ok)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", ts.String())
	assert.True(t, zoned)

	// A space-separated timestamp skips the RFC3339Nano layout (the 'T'
	// disagreement at index 10) and matches the second layout, which does not:
	// the answer belongs to the layout that claimed the value, not the entry.
	ts, zoned, ok = clp.parseLayoutTime("2026-07-06 12:00:00")
	require.True(t, ok)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", ts.String())
	assert.False(t, zoned)

	// No layout matches.
	_, _, ok = clp.parseLayoutTime("not a timestamp")
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
	clp.applySubmatch(&r, "time", "2026-07-06 12:00:00")
	assert.True(t, r.Time.IsZero())
}

func TestFirstBytes(t *testing.T) {
	testCases := []struct {
		re   string
		want string
	}{
		{`^"?(?P<time>\d{4}-\d{2})`, `"0123456789`},
		{`^(?P<time>\d{4}/\d{2})`, "0123456789"},
		{`^\d+:[XCSM]`, "0123456789"},
		{`^\[stuff`, "["},
		{`^<(?P<syslogpri>\d+)>`, "<"},
		{`^%(?P<sysloglevel>[0-7])`, "%"},
		{`^(?P<level>[IWEF])`, "IWEF"},
		{`^(?P<level>INFO|WARN|ERROR|DEBUG|TRACE|FATAL):`, "IWEDTF"},
		{`(?s)^Unhandled exception\.`, "U"},
		{`^[^[\s-]+\s-\s`, ""}, // unclassified anchored shape
		{`unanchored`, ""},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, firstBytes(tc.re), "regex %s", tc.re)
	}
}

func TestApplySubmatch_BadTime(t *testing.T) {
	// A time submatch that fails every layout leaves the time zero.
	clp := &compiledLineParser{re: regexp.MustCompile(`x`), ts: []tsLayout{{time.RFC3339Nano, true}}}
	var r Result
	clp.applySubmatch(&r, "time", "garbage")
	assert.True(t, r.Time.IsZero())
	assert.False(t, r.TimeHasZone, "no time parsed, so nothing to report a zone for")
}

// requiredByte must prove nothing for shapes it cannot reason about: a
// case-folded literal matches two bytes, an alternation guarantees neither
// branch, an optional repeat may be absent, and an unparseable pattern
// proves nothing at all. A wrongly proven byte would silently reject
// matching lines, which TestRequiredByteNeverRejectsMatches would only catch
// for shapes its corpus happens to contain.
func TestRequiredByteUnprovableShapes(t *testing.T) {
	assert.Equal(t, byte('='), requiredByte(`^level=x`), "sanity: mandatory literals do prove")
	assert.Zero(t, requiredByte(`(?i)error`))
	assert.Zero(t, requiredByte(`error|warn`))
	assert.Zero(t, requiredByte(`x{0,3}`))
	assert.Zero(t, requiredByte(`((`))
}

// byteScore's rarity ranking drives both gate derivations; pin the class
// order: control < heavy punctuation < brackets < separators < digits <
// uppercase < lowercase-and-space.
func TestByteScoreClassOrder(t *testing.T) {
	classes := [][]byte{
		{'\t', '\n'}, {'|', '=', '<', '%'}, {'[', '"', '('},
		{':', '-', '/'}, {'0', '9'}, {'A', 'Z'}, {'a', ' ', '.'},
	}
	for score, bytes := range classes {
		for _, c := range bytes {
			assert.Equal(t, score, byteScore(c), "byte %q", c)
		}
	}
}

// TestRareByteInContain pins the gate's correctness invariant: the rare byte
// is always a byte of the contain needle, so needle-present implies
// gate-passes and the gate can never reject a line the needle would accept.
func TestRareByteInContain(t *testing.T) {
	for _, clp := range compiledLineParsers {
		if clp.rare == 0 {
			assert.Less(t, len(clp.contain), 2, "contain %q: multi-byte needles must gate", clp.contain)
			continue
		}
		assert.Contains(t, clp.contain, string(clp.rare), "contain %q", clp.contain)
	}
}

// gateCorpus covers every timestamp family the positional gates distinguish,
// plus the quoted, short and empty edge cases of the prefix windows.
var gateCorpus = []string{
	`2026/07/11 10:00:00 error contacting upstream`,
	`2026/07/11 10:00:00.123456 message`,
	`2026-07-11 10:00:00.123  WARN 1 --- [main] message`,
	`2026-07-11 10:00:00,123 message`,
	`2026-07-11T10:00:00.123Z info message`,
	`2026-07-11T10:00:00+02:00 ERROR message`,
	`"2026-07-11T10:00:00.123Z" message`,
	`"2026-07-11 10:00:00.123 +02:00" [x] INFO: message`,
	`2026-07-11 10:00:00 message`,
	`2026-07`, `"2026`, `"`, `x`, ``,
	"2026-07-11T10:00:0", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

// TestPosGatesNeverRejectMatches pins the positional gates to their regexes:
// on lines of every timestamp family (and quoted/short/empty edge cases), a
// gated parser's gate may only reject lines its regex would reject anyway.
func TestPosGatesNeverRejectMatches(t *testing.T) {
	for _, clp := range compiledLineParsers {
		if clp.gateMask == 0 {
			continue
		}
		for _, line := range gateCorpus {
			if clp.re.MatchString(line) {
				var r Result
				assert.True(t, clp.passes(lineGates(line)) && clp.apply(&r, line, new(byteMemo)),
					"gate rejected a matching line: re=%s line=%q", clp.re, line)
			}
		}
	}
}

// TestGateWordsMatchPosGates pins the masked-word gate test to the per-byte
// posGate form it compiles from — the same oracle discipline the timestamp and
// severity fast paths follow. lineParsers and compiledLineParsers are built in
// one pass, so index i of each describes the same entry.
func TestGateWordsMatchPosGates(t *testing.T) {
	require.Equal(t, len(lineParsers), len(compiledLineParsers))
	lines := append([]string{}, gateCorpus...)
	lines = append(lines, fuzzCorpusLines(t)...)
	for i, p := range lineParsers {
		clp := compiledLineParsers[i]
		quoted, gates := posGates(p.re)
		for _, line := range lines {
			off := 0
			if quoted && len(line) > 0 && line[0] == '"' {
				off = 1
			}
			want := true
			for _, g := range gates {
				if j := g.idx + off; j >= len(line) || line[j] != g.want {
					want = false
				}
			}
			assert.Equal(t, want, clp.passes(lineGates(line)), "re=%s line=%q", p.re, line)
		}
	}
}

// TestRequiredByteNeverRejectsMatches pins requiredByte to its regex: on a
// corpus covering every pattern family, a line the regex matches must contain
// the derived byte (the gate may only reject lines the regex rejects too).
func TestRequiredByteNeverRejectsMatches(t *testing.T) {
	lines := []string{
		`2026/07/11 10:00:00 [error] worker process exited`,
		`2026/07/11 10:00:00 error contacting upstream`,
		`2026-07-11T10:00:00.123Z info message`,
		"2026-07-11T10:00:00.123Z\t00000000-0000-0000-0000-000000000001\tERROR\tmessage",
		`2026-07-11 10:00:00.123  WARN 1 --- [main] message`,
		`[2026-07-11 10:00:00,123][42][info] message`,
		`203.0.113.1 - - [11/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612`,
		`I0711 10:00:00.123456 1 main.go:42] started`,
		`2026/07/11 10:00:00 GET / "curl/8" 200 12`,
		`1:M 11 Jul 2026 10:00:00.123 * Ready to accept connections`,
		`[Thu Jun 27 11:55:44.569531 2024] [core:error] [pid 42] message`,
		`2026-07-11 10:00:00,123 - app.module - ERROR - failed`,
		`<134>1 2026-07-11T10:00:00.123Z host app 1234 ID47 - event`,
		`<11>Jul 11 10:00:00 host app[42]: failed`,
		`[ERROR] something`,
		`ERROR: something`,
		`audit: type=Warn msg=denied`,
		`%4|1720686000.123|FAIL|rdkafka#producer-1| down`,
		`2026-07-11 10:00:00 message`,
		`panic: runtime error: invalid memory address or nil pointer dereference`,
		"Unhandled exception. System.NullReferenceException: x\n at Y",
		"Traceback (most recent call last):\n  File \"x.py\"",
		"java.lang.NullPointerException: x\n\tat com.example.Y",
	}
	for _, clp := range compiledLineParsers {
		if clp.req == 0 {
			continue
		}
		for _, line := range lines {
			if clp.re.MatchString(line) {
				assert.Contains(t, line, string(clp.req), "required byte %q rejects a matching line: re=%s line=%q", clp.req, clp.re, line)
			}
		}
	}
}

// TestEveryNamedGroupIsApplied pins the table to applySubmatch: a named group
// whose name the switch does not know is captured and then silently dropped,
// which no test would otherwise notice. Extend both together.
func TestEveryNamedGroupIsApplied(t *testing.T) {
	known := map[string]bool{
		"level": true, "time": true, "ktime": true, "stamptime": true,
		"syslogtime": true, "sysloglevel": true, "syslogpri": true,
		"response_code": true, "redis_level": true, "logaserror": true,
		"unhandled": true,
	}
	for _, clp := range compiledLineParsers {
		for _, name := range clp.names {
			if name == "" {
				continue
			}
			assert.True(t, known[name], "group %q in %s is captured but applySubmatch ignores it", name, clp.re)
		}
	}
	// And the other way: a name the switch handles but the table never uses is
	// dead code.
	used := map[string]bool{}
	for _, clp := range compiledLineParsers {
		for _, name := range clp.names {
			used[name] = true
		}
	}
	for name := range known {
		assert.True(t, used[name], "applySubmatch handles %q but no table entry captures it", name)
	}
}

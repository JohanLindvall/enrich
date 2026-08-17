package enrich

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fuzzCorpusLines loads every input from the checked-in fuzz corpus, which
// doubles as a broad differential corpus here.
func fuzzCorpusLines(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/fuzz/FuzzParse/*")
	require.NoError(t, err)
	var lines []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, ln := range strings.Split(string(data), "\n") {
			if rest, ok := strings.CutPrefix(ln, "string("); ok {
				if s, err := strconv.Unquote(strings.TrimSuffix(rest, ")")); err == nil {
					lines = append(lines, s)
				}
			}
		}
	}
	require.NotEmpty(t, lines)
	return lines
}

// TestFastMatchersMatchRegex differential-tests every hand matcher against
// its entry's regex: a decided verdict must agree with the regex (including
// the captured time span on a match); fastUndecided is always allowed. Inputs
// are the fuzz corpus, canonical lines, shape mutations, and random junk.
func TestFastMatchersMatchRegex(t *testing.T) {
	inputs := append(fuzzCorpusLines(t),
		"2026/07/11 10:00:00 error contacting upstream",
		"2026/07/11 10:00:00.123456 message",
		"2026/07/11 10:00:00.123456789012 message", // over-long fraction
		"2026/07/11 10:00:00Z: message",
		"2026/07/11 10:00:00.5Z: message",
		"2026/07/11 10:00:00", // no trailing \s
		"2026/07/11 10:00:00.", "2026/07/11 10:00:00.x",
		"2026/07/11 10:00:00\tx", "2026/07/11 10:00:00\nx",
		"2026/07/11 10:00:00\vx",                           // \v is NOT \s in regexp
		"2026/07/11 10:00:00\fx", "2026/07/11 10:00:00\rx", // \f and \r ARE
		"2026/07/11 10:00:00,123 message", // comma fraction: \. only in these regexes
		"2026-07-11 10:00:00,123 x", "2026-07-11T10:00:00,123Z info x",
		"2026-07-11 10:00:00 message",
		"2026-07-11 10:00:00.123 message", // fraction on the fraction-less entry
		"2026-07-11 10:00:00Z: x",
		"9999/99/99 99:99:99 structurally valid, semantically absurd",
		"1:M 11 Jul 2026 10:00:00.123 * Ready to accept connections",
		"1:X 11 Jul 2026 10:00:00 . x",
		"12345:C ok", "1:Q 11 Jul 2026", ":M x", "1:M", "1:Mx",
		"", " ", "2", "2026", "2026/07/11",
	)
	inputs = append(inputs,
		// RFC3339-entry shapes: quotes, levels, zones, casing.
		"2026-07-11T10:00:00.123Z info message",
		"2026-07-11T10:00:00.123Z INFO message",
		"2026-07-11T10:00:00.123Z Info message", // mixed case: no level
		"2026-07-11T10:00:00.123Z info",         // level not followed by \s
		"2026-07-11T10:00:00+02:00 ERROR x",
		"2026-07-11T10:00:00-02:30  error  x", // multiple spaces
		"2026-07-11T10:00:00Z",                // no trailing \s at all
		"2026-07-11T10:00:00.123", "2026-07-11T10:00:00x ",
		`"2026-07-11T10:00:00.123Z" info message`,
		`"2026-07-11T10:00:00.123Z info message`, // unbalanced quote
		`2026-07-11T10:00:00.123Z" info message`,
		"2026-07-11 10:00:00.123Z warn x",      // space-separated Z variant
		"2026-07-11 10:00:00.123+02:00 warn x", // offset on the Z-only variant
		`"2026-07-11 10:00:00.5Z"`+"\t"+`x`,
		// Non-ASCII bytes in the level/space region: regexp classes are
		// rune-based, the matchers byte-based — pin that they agree.
		"2026-07-11T10:00:00Z h\xc3\xa9llo x",
		"2026-07-11 10:00:00Z h\xc3\xa9llo x",
		"2026-07-11 10:00:00\xc2\xa0x", // NBSP is not \s
		"2026-07-11T10:00:00Z\xc2\xa0info x",
		"2026-07-11T10:00:00Z \xc3\x89RROR x",
	)
	inputs = append(inputs,
		// Bracketed-level, nginx and Lambda shapes: the entries the table tries
		// BEFORE the generic ones, two of whose matchers only pre-decide their
		// own prefix. The http-echo lines exercise the entry that has none.
		"2026/07/11 10:00:00 [error] worker process exited",
		"2026/07/11 10:00:00.123 [Warn] x", "2026/07/11 10:00:00 [] x",
		"2026/07/11 10:00:00 [error x", "2026/07/11 10:00:00 [err0r] x",
		"2026/07/11 10:00:00\t[error] x", "2026/07/11 10:00:00  [error] x",
		"2026/07/11 10:00:00 [\xc3\xa9rror] x",
		`2026/07/11 10:00:00 GET / "curl/8" 200 12`,
		`2026/07/11 10:00:00Z: GET / "curl/8" 200 12`,
		`2026/07/11 10:00:00 GET "curl/8" 200 12`, `2026/07/11 10:00:00 GET / curl 200`,
		`2026/07/11 10:00:00 GET  / "curl/8" 200 12`, `2026/07/11 10:00:00 a b"c" 1 `,
		`203.0.113.1 - - [11/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612`,
		`203.0.113.1 - user [11/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612`,
		`203.0.113.1 -- [x] "GET" 200 `, `203.0.113.1 - `, ` - - [x] "y" 200 `,
		`-203.0.113.1 - - [x] "y" 200 `, `[203.0.113.1] - - [x] "y" 200 `,
		"203.0.113.1\t-\t- [x] \"y\" 200 ", "203.0.113.1 -\t- [x] \"y\" 200 ",
		"2026-07-11T10:00:00.123Z\t11111111-2222-3333-4444-555555555555\tERROR\tboom",
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-555555555555\tINFO\tx",
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-55555555555\tINFO\tx",   // 35
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-5555555555555\tINFO\tx", // 37
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-55555555555g\tINFO\tx",
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-555555555555\tInfo\tx",
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-555555555555\t\tx",
		"2026-07-11T10:00:00Z\t11111111-2222-3333-4444-555555555555\tINFO x",
		`"2026-07-11T10:00:00Z"`+"\t11111111-2222-3333-4444-555555555555\tINFO\tx",
	)
	rng := rand.New(rand.NewSource(7))
	seeds := []string{
		"2026/07/11 10:00:00.123456 message",
		"2026-07-11 10:00:00 message",
		"2026/07/11 10:00:00Z: message",
		"1:M 11 Jul 2026 10:00:00.123 * Ready",
		"2026-07-11T10:00:00.123Z info message",
		`"2026-07-11 10:00:00.5Z" WARN x`,
		"2026-07-11T10:00:00+02:00 ERROR x",
		"2026/07/11 10:00:00 [error] worker exited",
		`2026/07/11 10:00:00 GET / "curl/8" 200 12`,
		`203.0.113.1 - - [11/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612`,
		"2026-07-11T10:00:00.123Z\t11111111-2222-3333-4444-555555555555\tERROR\tboom",
	}
	const chars = "0123456789/:-.,+ TZXCSMabz\"eEiIrRoO[]GET\t\n\v\f\r\x80\xff\xc3\xa9"
	for i := 0; i < 40000; i++ {
		s := []byte(seeds[rng.Intn(len(seeds))])
		for n := 1 + rng.Intn(3); n > 0; n-- {
			s[rng.Intn(len(s))] = chars[rng.Intn(len(chars))]
		}
		if rng.Intn(6) == 0 {
			s = s[:rng.Intn(len(s))]
		}
		inputs = append(inputs, string(s))
	}

	// groupSpan projects a regex loc onto what the application loop would use
	// for a named group: an empty or absent group is skipped there, which the
	// fastSpans encoding represents as the zero span.
	groupSpan := func(clp *compiledLineParser, loc []int, group string) [2]int {
		for i, name := range clp.names {
			if name == group && loc[2*i] >= 0 && loc[2*i] < loc[2*i+1] {
				return [2]int{loc[2*i], loc[2*i+1]}
			}
		}
		return [2]int{}
	}

	covered := 0
	for _, clp := range compiledLineParsers {
		if clp.fast == nil {
			continue
		}
		covered++
		var decided, matchedRE int
		for _, in := range inputs {
			spans, v := clp.fast(in)
			if v != fastUndecided {
				decided++
			}
			if clp.re.MatchString(in) {
				matchedRE++
			}
			if v == fastUndecided {
				continue
			}
			loc := clp.re.FindStringSubmatchIndex(in)
			if v == fastNoMatch {
				assert.Nil(t, loc, "fast says no-match but regex matches: re=%s in=%q", clp.re, in)
				continue
			}
			// fastMatched: the regex must match, with exactly these time and
			// level spans and no other participating named group.
			if assert.NotNil(t, loc, "fast says match but regex misses: re=%s in=%q", clp.re, in) {
				assert.Equal(t, groupSpan(clp, loc, "time"), spans.time,
					"time span differs: re=%s in=%q", clp.re, in)
				assert.Equal(t, groupSpan(clp, loc, "level"), spans.level,
					"level span differs: re=%s in=%q", clp.re, in)
				for i, name := range clp.names {
					if name != "" && name != "time" && name != "level" {
						assert.Less(t, loc[2*i], 0, "unexpected group %q participates: re=%s in=%q", name, clp.re, in)
					}
				}
			}
		}
		// Agreement alone is satisfied by a matcher that has rotted into
		// always-fastUndecided (correct, but doing no work) or that no input
		// reaches. Both would make every assertion above vacuous.
		assert.NotZero(t, decided, "matcher never decides anything: re=%s", clp.re)
		assert.NotZero(t, matchedRE, "no input exercises the match side: re=%s", clp.re)
	}
	// The table must actually carry the matchers (all nine shapes present).
	assert.Equal(t, 9, covered, "expected exactly the nine hand-matched entries")
}

// TestByteMemo pins the memo to strings.IndexByte over every byte value.
func TestByteMemo(t *testing.T) {
	lines := []string{"", "a", "abc=def:ghi\n\x00\xff", "lorem ipsum"}
	for _, s := range lines {
		var m byteMemo
		for c := 0; c < 256; c++ {
			want := strings.IndexByte(s, byte(c)) >= 0
			assert.Equal(t, want, m.has(s, byte(c)), "line %q byte %#x", s, c)
			// And again, from the memo.
			assert.Equal(t, want, m.has(s, byte(c)), "memoized line %q byte %#x", s, c)
		}
	}
}

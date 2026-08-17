package enrich

import (
	"encoding/json"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestParseStampTimeMatchesOldPath differential-tests parseStampTime against
// the expandStampTime + "2006 Jan _2 15:04:05" layout composite it bypasses,
// across year-boundary clocks.
func TestParseStampTimeMatchesOldPath(t *testing.T) {
	oracle := func(in string, now time.Time) (time.Time, bool) {
		if len(in) < 3 {
			return time.Time{}, false
		}
		return layoutOracle([]string{"2006 Jan _2 15:04:05"}, expandStampTime(in, now))
	}
	nows := []time.Time{
		time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 30, 0, 0, time.UTC),
		time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC),
	}
	inputs := []string{
		"Jul 11 10:00:00", "Jul  1 10:00:00", "Jul 1 10:00:00", "Jul  11 10:00:00",
		"Dec 31 23:59:59", "Jan  1 00:00:00", "Feb 29 10:00:00", "Feb 30 10:00:00",
		"jul 11 10:00:00", "JUL 11 10:00:00", "Jux 11 10:00:00",
		"Jul 00 10:00:00", "Jul 32 10:00:00", "Jul 11 24:00:00",
		"Jul 11 10:60:00", "Jul 11 10:00:60", "Jul 11 10:00:0",
		"Jul 11 10:00:00 ", "Jul 111 10:00:00", "Jul\t11 10:00:00",
		"Jul   1 10:00:00", "May 5 5:00:00", "Sep  9 09:09:09",
	}
	rng := rand.New(rand.NewSource(8))
	const chars = "0123456789 :JulFebMarSepDecx\t"
	for i := 0; i < 20000; i++ {
		s := []byte("Jul 11 10:00:00")
		for n := 1 + rng.Intn(3); n > 0; n-- {
			s[rng.Intn(len(s))] = chars[rng.Intn(len(chars))]
		}
		if rng.Intn(6) == 0 {
			s = s[:rng.Intn(len(s))]
		}
		inputs = append(inputs, string(s))
	}
	for _, now := range nows {
		for _, in := range inputs {
			got, ok := parseStampTime(in, now)
			if ok {
				want, wantOK := oracle(in, now)
				assert.True(t, wantOK, "parseStampTime claims %q (now %v) but the old path rejects it", in, now)
				assert.Equal(t, want, got, "parseStampTime disagrees on %q (now %v)", in, now)
			}
		}
	}
	for _, in := range []string{"Jul 11 10:00:00", "Jul  1 10:00:00"} {
		_, ok := parseStampTime(in, nows[0])
		assert.True(t, ok, "parseStampTime must claim %q", in)
	}
}

// traceparentOracleRE is the regex scanTraceparent replaced, kept as its
// oracle (the same pattern as resourceGroupRE below in enrich_test.go).
var traceparentOracleRE = regexp.MustCompile(`^traceparent[:=]\s*"?([0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2})`)

// TestScanTraceparentMatchesRegex differential-tests the hand scan against
// the regex + parseTraceparent composite over canonical, mutated, and junk
// suffixes of a "traceparent" occurrence.
func TestScanTraceparentMatchesRegex(t *testing.T) {
	oracle := func(rest string) (string, string) {
		if m := traceparentOracleRE.FindStringSubmatch("traceparent" + rest); m != nil {
			return parseTraceparent(m[1])
		}
		return "", ""
	}
	inputs := []string{
		`: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`,
		`=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`,
		`: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`,
		": \t 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		":\f00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // \f and \r are regexp \s
		":\r00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		":\v00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // \v is NOT
		`: 00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01`,  // uppercase: regex rejects
		`: 00-00000000000000000000000000000000-00f067aa0ba902b7-01`,  // all-zero trace
		`: 00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01`,  // all-zero span
		`  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`,  // no separator
		`: 00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`,
		`: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0`, // short
		`:`, `=`, ``, `: "`,
	}
	rng := rand.New(rand.NewSource(9))
	const chars = "0123456789abcdefABCDEF-=:\" x\t\f\r\v"
	for i := 0; i < 30000; i++ {
		s := []byte(`: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`)
		for n := 1 + rng.Intn(3); n > 0; n-- {
			s[rng.Intn(len(s))] = chars[rng.Intn(len(chars))]
		}
		if rng.Intn(6) == 0 {
			s = s[:rng.Intn(len(s))]
		}
		inputs = append(inputs, string(s))
	}
	for _, rest := range inputs {
		wantT, wantS := oracle(rest)
		gotT, gotS := scanTraceparent(rest)
		assert.Equal(t, wantT, gotT, "trace ID differs for %q", rest)
		assert.Equal(t, wantS, gotS, "span ID differs for %q", rest)
	}
}

// TestIndexAnchoredMatchesIndex pins the rare-byte-anchored scan to
// strings.Index, over every anchor position of each needle the package uses
// and a randomized haystack sweep built from the needles' own alphabets (so
// near-misses and overlapping candidates are dense).
func TestIndexAnchoredMatchesIndex(t *testing.T) {
	needles := []string{traceparentKey, `"level":`, "ab", "aa", "x"}
	haystacks := []string{
		"", "x", "traceparent", "traceparent=00-", "xtraceparent", "tracepareny",
		"tracepare", `{"a":1,"level":30}`, `{"level":"info"}`, `"lev"level":`,
		"aaaaaa", "ababab", "abab", "traceparenttraceparent",
	}
	rng := rand.New(rand.NewSource(12))
	const chars = "traceponx\"l:v01{}ab"
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(40))
		for j := range b {
			b[j] = chars[rng.Intn(len(chars))]
		}
		haystacks = append(haystacks, string(b))
	}
	for _, needle := range needles {
		for anchor := 0; anchor < len(needle); anchor++ {
			for _, s := range haystacks {
				assert.Equal(t, strings.Index(s, needle), indexAnchored(s, needle, anchor),
					"needle %q anchor %d haystack %q", needle, anchor, s)
			}
		}
	}
	// The constants the call sites pass must select the byte they document.
	assert.Equal(t, byte('p'), traceparentKey[traceparentAnchor])
}

// slowValidGUID is the pre-SWAR per-byte implementation, as validGUID's
// oracle.
func slowValidGUID(s string) bool {
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

// TestValidGUIDMatchesSlow differential-tests the word-parallel validGUID:
// every single-byte corruption of a valid GUID at every position and value
// class, plus a randomized sweep and non-36 lengths.
func TestValidGUIDMatchesSlow(t *testing.T) {
	valid := "00000000-0000-0000-0000-000000000000"
	for pos := 0; pos < len(valid); pos++ {
		for _, c := range []byte{'0', '9', 'a', 'f', 'A', 'F', 'g', 'G', '-', '/', ':', '`', '@', 0x00, 0x80, 0xff} {
			b := []byte(valid)
			b[pos] = c
			s := string(b)
			assert.Equal(t, slowValidGUID(s), validGUID(s), "guid %q", s)
		}
	}
	// Non-36 lengths take the per-byte path; shapes whose dashes still sit at
	// 8/13/18/23 with hex everywhere else reach its final "all checks passed".
	for _, s := range []string{valid[:34], valid[:35], valid + "0", valid + "ff", "", "0123"} {
		assert.Equal(t, slowValidGUID(s), validGUID(s), "guid %q", s)
	}
	rng := rand.New(rand.NewSource(10))
	const chars = "0123456789abcdefABCDEF-g\x80"
	buf := make([]byte, 0, 40)
	for i := 0; i < 100000; i++ {
		buf = buf[:0]
		n := 34 + rng.Intn(5) // lengths straddling 36
		for j := 0; j < n; j++ {
			buf = append(buf, chars[rng.Intn(len(chars))])
		}
		s := string(buf)
		assert.Equal(t, slowValidGUID(s), validGUID(s), "guid %q", s)
	}
}

// TestJsonIntMatchesParseInt pins jsonInt's digits fast path to the
// strconv.ParseInt behavior it shortcuts.
func TestJsonIntMatchesParseInt(t *testing.T) {
	oracle := func(n json.Number) (int64, bool) {
		if n == "" {
			return 0, false
		}
		v, err := strconv.ParseInt(string(n), 10, 64)
		return v, err == nil
	}
	cases := []string{
		"", "0", "200", "404", "007", "-1", "+1", "1.5", "1e3", "1_0",
		"999999999999999999", "1000000000000000000", "9223372036854775807",
		"9223372036854775808", "-9223372036854775808", "18446744073709551615",
		"x", "1x", "x1", " 1", "1 ",
	}
	rng := rand.New(rand.NewSource(11))
	const chars = "0123456789+-.e_x"
	for i := 0; i < 50000; i++ {
		n := 1 + rng.Intn(21)
		b := make([]byte, n)
		for j := range b {
			b[j] = chars[rng.Intn(len(chars))]
		}
		cases = append(cases, string(b))
	}
	for _, c := range cases {
		wantV, wantOK := oracle(json.Number(c))
		gotV, gotOK := jsonInt(json.Number(c))
		assert.Equal(t, wantOK, gotOK, "ok differs for %q", c)
		if wantOK {
			assert.Equal(t, wantV, gotV, "value differs for %q", c)
		}
	}
}

// TestSeverityCanonicalFastPath pins the canonical-constant switch in
// SeverityFromText to the LUT it shortcuts (the sweep in severity_test.go
// covers the rest of the language).
func TestSeverityCanonicalFastPath(t *testing.T) {
	for _, lvl := range []string{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel} {
		text, no := SeverityFromText(lvl)
		wantText, wantNo, ok := lookupSeverity(lvl)
		assert.True(t, ok)
		assert.Equal(t, wantText, text, lvl)
		assert.Equal(t, wantNo, no, lvl)
	}
}

// TestSeverityInitialMask pins the bitmask to the severityInitials string it
// was derived from, over every possible first byte.
func TestSeverityInitialMask(t *testing.T) {
	for c := 0; c < 256; c++ {
		folded := byte(c) | 0x20
		want := strings.IndexByte(severityInitials, folded) >= 0
		got := folded-'a' <= 'z'-'a' && severityInitialMask&(1<<(folded-'a')) != 0
		assert.Equal(t, want, got, "byte %#x", c)
	}
}

// TestLogfmtKeyGate pins the first-byte-and-length gate to the spelling list it
// is built from: every listed key must pass, and no other (byte, length) pair
// may — the gate is what stands between a browser-telemetry line's fifty keys
// and the switch.
func TestLogfmtKeyGate(t *testing.T) {
	pass := func(key string) bool {
		return len(key) != 0 && logfmtKeyGate[key[0]]&(uint32(1)<<uint(len(key))) != 0
	}
	want := map[[2]int]bool{}
	for _, k := range logfmtKeys {
		want[[2]int{int(k[0]), len(k)}] = true
		assert.True(t, pass(k), "listed key %q is gated out", k)
	}
	assert.False(t, pass(""), "the empty key must be gated out")
	key := make([]byte, 40)
	for c := 0; c < 256; c++ {
		for n := 1; n <= len(key); n++ {
			key[0] = byte(c)
			for i := 1; i < n; i++ {
				key[i] = 'x'
			}
			assert.Equal(t, want[[2]int{c, n}], pass(string(key[:n])), "byte %#x length %d", c, n)
		}
	}

	// Every listed spelling must also BE a case in the switch: an entry the
	// switch does not know is a probe every line carrying it pays for nothing.
	for _, k := range logfmtKeys {
		lower := strings.ToLower(k)
		value := "info" // level, msg, message
		switch {
		case lower == "traceparent":
			value = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
		case strings.Contains(lower, "span"):
			value = "0123456789abcdef"
		case strings.Contains(lower, "trace"):
			value = "aaaabbbbccccdddd0000111122223333"
		case lower == "t" || lower == "ts" || lower == "time" || lower == "timestamp":
			value = "2026-07-11T10:00:00Z"
		}
		var r Result
		var memo byteMemo
		r.enrichFromLogFmt(k+"="+value+" other=1", &memo)
		assert.NotEqual(t, Result{}, r, "key %q is listed but the switch ignores it", k)
	}
}

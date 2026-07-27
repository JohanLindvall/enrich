package enrich

import (
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/JohanLindvall/logfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// layoutOracle is the time.Parse loop each family parser replaces: first
// layout that parses wins, result in UTC.
func layoutOracle(layouts []string, value string) (time.Time, bool) {
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// tsFamilies pairs every hand-rolled family parser with the layout list it
// covers. fastLayoutTime is looked up with the same lists, so a mapping
// mistake there shows up here too.
var tsFamilies = []struct {
	name    string
	layouts []string
	claimed []string // canonical shapes the fast path MUST claim
}{
	{"ymdSlash", []string{"2006/01/02 15:04:05.999999999"}, []string{
		"2026/07/11 10:00:00", "2026/07/11 10:00:00.123", "2026/12/31 23:59:59.999999999",
	}},
	{"ymdSlash6", []string{"2006/01/02 15:04:05.000000"}, []string{
		"2026/07/11 10:00:00.123456",
	}},
	{"msSpace", []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"}, []string{
		"2026-07-11 10:00:00.123", "2026-07-11 10:00:00",
	}},
	{"msSpaceTS", []string{"2006-01-02 15:04:05.000 -07:00", "2006-01-02 15:04:05 -07:00"}, []string{
		"2026-07-11 10:00:00.123 +01:00", "2026-07-11 10:00:00 -05:30",
	}},
	{"rfc3339NanoSpace", []string{rfc3339NanoSpaceLayout}, []string{
		"2026-07-11 10:00:00.123456789Z", "2026-07-11 10:00:00Z", "2026-07-11 10:00:00.5+02:00",
	}},
	{"plain", []string{"2006-01-02 15:04:05"}, []string{
		"2026-07-11 10:00:00",
	}},
}

// tsFuzzInputs generates the shared adversarial input set: canonical shapes,
// hand-picked quirk cases, and random mutations of valid stamps.
func tsFuzzInputs(rng *rand.Rand) []string {
	inputs := []string{
		"", " ", "2026", "2026-07-11", "10:00:00",
		// Range edges time.Parse checks: month, leap day, hour, minute, second.
		"2026-00-11 10:00:00", "2026-13-11 10:00:00", "2026-02-29 10:00:00",
		"2024-02-29 10:00:00", "2000-02-29 10:00:00", "1900-02-28 10:00:00",
		"2026-04-31 10:00:00", "2026-07-00 10:00:00", "2026-07-32 10:00:00",
		"2026-07-11 24:00:00", "2026-07-11 10:60:00", "2026-07-11 10:00:60",
		"0000-01-01 00:00:00",
		// Fraction quirks: comma separators, over-long fractions, empty and
		// signed fractions, fraction on the fraction-less family.
		"2026-07-11 10:00:00,123", "2026-07-11 10:00:00.", "2026-07-11 10:00:00.x",
		"2026-07-11 10:00:00.1234567891234", "2026-07-11 10:00:00.+12",
		"2026-07-11 10:00:00.-12", "2026-07-11 10:00:00.12",
		"2026/07/11 10:00:00,123456789", "2026/07/11 10:00:00.12345",
		"2026/07/11 10:00:00.1234567", "2026/07/11 10:00:00.123456x",
		// Zone quirks: the hr<=24/min<=60 in-range oddities, bad signs,
		// missing colons, trailing junk.
		"2026-07-11 10:00:00 +24:60", "2026-07-11 10:00:00 +25:00",
		"2026-07-11 10:00:00 +01:61", "2026-07-11 10:00:00 *01:00",
		"2026-07-11 10:00:00 +0100", "2026-07-11 10:00:00.123 +01:00x",
		"2026-07-11 10:00:00.123Z", "2026-07-11 10:00:00Zx",
		"2026-07-11 10:00:00+02:00", "2026-07-11T10:00:00Z",
		// Whitespace and separator confusion.
		"2026-07-11  10:00:00", "2026/07-11 10:00:00", "2026-07/11 10:00:00",
		" 2026-07-11 10:00:00", "2026-07-11 10:00:00 ",
	}
	stamps := []string{
		"2026-07-11 10:00:00.123 +01:00", "2026/07/11 10:00:00.123456789",
		"2026-07-11 10:00:00.123456789Z", "2026-07-11 10:00:00", "2026/07/11 10:00:00.123456",
	}
	const chars = "0123456789 :./,-+Zx"
	for i := 0; i < 30000; i++ {
		s := []byte(stamps[rng.Intn(len(stamps))])
		for n := 1 + rng.Intn(3); n > 0; n-- {
			s[rng.Intn(len(s))] = chars[rng.Intn(len(chars))]
		}
		// Occasionally truncate or extend.
		switch rng.Intn(6) {
		case 0:
			s = s[:rng.Intn(len(s))]
		case 1:
			s = append(s, chars[rng.Intn(len(chars))])
		}
		inputs = append(inputs, string(s))
	}
	return inputs
}

// TestFastLayoutTimeMatchesParse differential-tests every family parser
// against its own time.Parse layout loop: a claimed input must produce
// exactly the loop's result, and the canonical shapes must be claimed.
func TestFastLayoutTimeMatchesParse(t *testing.T) {
	inputs := tsFuzzInputs(rand.New(rand.NewSource(4)))
	for _, fam := range tsFamilies {
		fast := fastLayoutTime(fam.layouts)
		require.NotNil(t, fast, "family %s has no fast parser wired", fam.name)

		for _, in := range fam.claimed {
			_, ok := fast(in)
			assert.True(t, ok, "family %s must claim %q", fam.name, in)
		}
		for _, in := range append(inputs, fam.claimed...) {
			got, ok := fast(in)
			want, wantOK := layoutOracle(fam.layouts, in)
			if ok {
				assert.True(t, wantOK, "family %s claims %q but time.Parse rejects it", fam.name, in)
				assert.Equal(t, want, got, "family %s disagrees on %q", fam.name, in)
			}
			// A miss is always allowed: the caller falls back to the loop.
		}
	}
}

// TestParseKlogTimeMatchesOldPath differential-tests parseKlogTime against
// the expandKlogTime + layout-loop composite it bypasses, across both
// year-boundary clock settings.
func TestParseKlogTimeMatchesOldPath(t *testing.T) {
	nows := []time.Time{
		time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 30, 0, 0, time.UTC),
		time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), // leap day clock
	}
	inputs := []string{
		"0711 10:00:00.123456", "0711 10:00:00", "1231 23:59:59.999999",
		"0101 00:00:00.000000", "0229 10:00:00.000000", "0230 10:00:00.000000",
		"1301 10:00:00.000000", "0000 10:00:00.000000", "0711 24:00:00.000000",
		"0711 10:60:00.000000", "0711 10:00:60.000000", "0711 10:00:00,123456",
		"0711 10:00:00.12345", "0711 10:00:00.1234567", "0711 10:00:00.12345x",
		"07x1 10:00:00.123456", "0711-10:00:00.123456", "0711 10:00:00.",
	}
	rng := rand.New(rand.NewSource(5))
	const chars = "0123456789 :.,x"
	for i := 0; i < 20000; i++ {
		s := []byte("0711 10:00:00.123456")
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
			want, wantOK := layoutOracle(timeLayoutsKlog, expandKlogTime2(in, now))
			got, ok := parseKlogTime(in, now)
			if ok {
				assert.True(t, wantOK, "parseKlogTime claims %q (now %v) but the old path rejects it", in, now)
				assert.Equal(t, want, got, "parseKlogTime disagrees on %q (now %v)", in, now)
			}
		}
	}

	// The canonical shapes must be claimed, or the fast path has rotted.
	for _, in := range []string{"0711 10:00:00.123456", "0711 10:00:00"} {
		_, ok := parseKlogTime(in, nows[0])
		assert.True(t, ok, "parseKlogTime must claim %q", in)
	}
}

// expandKlogTime2 is expandKlogTime guarded against the short inputs the
// fuzzing above generates (the real caller only sees regex-shaped values).
func expandKlogTime2(ts string, now time.Time) string {
	if len(ts) < 2 {
		return ts
	}
	return expandKlogTime(ts, now)
}

// TestParseGoStringTimeMatchesParseTime differential-tests the logfmt-path
// fast parser against logfmt.ParseTime, which it short-circuits: any claimed
// value must yield exactly ParseTime's result.
func TestParseGoStringTimeMatchesParseTime(t *testing.T) {
	inputs := []string{
		"2026-03-14 06:11:46.397 +0000 UTC",   // the faro shape
		"2026-03-14 06:11:46 +0000 UTC",       // no fraction
		"2026-03-14 06:11:46.397 +0100 CET",   // positive offset, 3-letter zone
		"2026-03-14 06:11:46.397 -0500 EST",   // negative offset
		"2026-03-14 06:11:46.397 +0930 ACST",  // 4-letter zone ending in T
		"2026-03-14 06:11:46.397 +1345 CHADT", // 5-letter zone ending in T
		"2026-03-14 06:11:46.397 +0000 GMT",   // bare GMT
		"2026-03-14 06:11:46.397 +0100 GMT",   // nonzero offset: GMT is NOT the UTC special case
		"2026-03-14 06:11:46.397 -0500 GMT",
		"2026-03-14 06:11:46.397 +0800 GMT+8", // GMT with suffix: not claimed, ParseTime decides
		"2026-03-14 06:11:46.397 +0000 GMTT",  // GMT-prefixed 4-letter: parseTimeZone eats only "GMT"
		"2026-03-14 06:11:46.397 +1100 GMTST", // GMT-prefixed 5-letter ending in T
		"2026-03-14 06:11:46.397 +0200 MESZ",  // 4 letters not ending in T
		"2026-03-14 06:11:46.397 +1000 ChST",  // lower-case special zone
		"2026-03-14 06:11:46.397 +0000 UT",    // too short
		"2026-03-14 06:11:46.397 +0000 ABCDEF",
		"2026-03-14 06:11:46.397 +2460 UTC", // in-range offset oddity
		"2026-03-14 06:11:46.397 +2501 UTC", // out-of-range offset
		"2026-03-14 06:11:46.397 0000 UTC",  // missing sign
		"2026-03-14 06:11:46.397+0000 UTC",  // missing space
		"2026-03-14 06:11:46.397 +0000UTC",
		"2026-03-14 06:11:46.397 +0000 utc",
		"2026-03-14T06:11:46.397Z",         // RFC3339: not claimed, ParseTime handles
		"2026-03-14 06:11:46.397Z",         // space-separated RFC3339-ish
		"1748239806", "1748239806.3691056", // epochs
		`2026-03-14 06:11:46.397 +0000 UTC"`, // trailing trim set
		"2026-03-14 06:11:46.397 +0000 UTC}]",
		"2026-03-14 06:11:46.397 +0000 UTC x",
		"2026-02-29 06:11:46.397 +0000 UTC", // invalid leap day
		"2024-02-29 06:11:46.397 +0000 UTC", // valid leap day
		"",
	}
	rng := rand.New(rand.NewSource(6))
	const chars = "0123456789 :.,+-ABCGMSTUZchx\"}"
	for i := 0; i < 30000; i++ {
		s := []byte("2026-03-14 06:11:46.397 +0000 UTC")
		for n := 1 + rng.Intn(4); n > 0; n-- {
			s[rng.Intn(len(s))] = chars[rng.Intn(len(chars))]
		}
		if rng.Intn(6) == 0 {
			s = s[:rng.Intn(len(s))]
		}
		inputs = append(inputs, string(s))
	}

	for _, in := range inputs {
		got, ok := parseGoStringTime([]byte(in))
		if ok {
			want, wantOK := logfmt.ParseTime([]byte(in))
			assert.True(t, wantOK, "parseGoStringTime claims %q but logfmt.ParseTime rejects it", in)
			assert.Equal(t, want, got, "parseGoStringTime disagrees on %q", in)
		}
	}

	// The canonical shapes must be claimed.
	for _, in := range []string{
		"2026-03-14 06:11:46.397 +0000 UTC",
		"2026-03-14 06:11:46 +0100 CET",
	} {
		_, ok := parseGoStringTime([]byte(in))
		assert.True(t, ok, "parseGoStringTime must claim %q", in)
	}
}

// TestFastTSWiredIntoTable asserts the compiled table actually carries fast
// parsers for the families that have one, so a layout-list edit cannot
// silently drop the fast path.
func TestFastTSWiredIntoTable(t *testing.T) {
	n := 0
	for _, clp := range compiledLineParsers {
		if clp.fastTS != nil {
			n++
		}
	}
	assert.GreaterOrEqual(t, n, 10, "expected most table entries to carry a fast timestamp parser, got "+strconv.Itoa(n))
}

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
		"2026-03-14 06:11:46.397 +0000 UTCT",  // UTC-prefixed 4-letter: parse eats "UTC", fails on the rest
		"2026-03-14 06:11:46.397 +0500 UTCDT", // UTC-prefixed 5-letter ending in T
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

// monthByName claims exact-case abbreviations only — anything else stays on
// the time.Parse path, which folds case itself.
func TestMonthByName(t *testing.T) {
	for i, name := range []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"} {
		assert.Equal(t, i+1, monthByName(name), name)
	}
	for _, bad := range []string{"", "jan", "JAN", "Xyz", "Janu"} {
		assert.Zero(t, monthByName(bad), bad)
	}
}

// layoutZoneOracle decides, the one way that cannot be argued with, whether a
// layout carries a zone: format ONE instant with it twice, once in UTC and
// once five hours east, and parse both texts back. A layout with a zone
// element reproduces the instant from either text; a zone-less one writes two
// wall clocks five hours apart and reads both as UTC, so they disagree.
//
// Comparing the two round trips rather than either against the original makes
// the oracle immune to what a layout cannot express (a dropped fraction, a
// dropped weekday): both sides lose exactly the same components.
//
// It would call a layout carrying ONLY an unresolvable abbreviation ("MST"
// with no numeric offset) zone-less, since time.Parse gives such a name offset
// zero. No layout here is that shape; one added later shows up as a
// disagreement with layoutHasZone, which is the conversation to have.
func layoutZoneOracle(t *testing.T, layout string) bool {
	t.Helper()
	instant := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	east := instant.In(time.FixedZone("TST", 5*60*60))
	a, errA := time.Parse(layout, instant.Format(layout))
	b, errB := time.Parse(layout, east.Format(layout))
	require.NoError(t, errA, "layout %q does not round-trip its own output", layout)
	require.NoError(t, errB, "layout %q does not round-trip its own output", layout)
	return a.UTC().Equal(b.UTC())
}

// TestLayoutHasZoneMatchesRoundTrip pins layoutHasZone — a substring test over
// the reference-layout tokens — to the round-trip oracle, for every layout the
// table actually uses. It is what keeps Result.TimeHasZone honest as entries
// are added: a new layout whose zonedness the token test reads wrong fails
// here rather than mislabelling a fleet's timestamps.
func TestLayoutHasZoneMatchesRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for _, clp := range compiledLineParsers {
		for _, l := range clp.ts {
			seen[l.layout] = true
			assert.Equal(t, layoutZoneOracle(t, l.layout), l.zoned,
				"layout %q: compiled zone flag disagrees with the round trip", l.layout)
			assert.Equal(t, l.zoned, layoutHasZone(l.layout),
				"layout %q: compiled flag is not layoutHasZone's answer", l.layout)
		}
	}
	// The table must contain layouts of BOTH kinds, or the assertions above
	// would pass on a function that answers one way for everything.
	var zoned, bare int
	for layout := range seen {
		if layoutHasZone(layout) {
			zoned++
		} else {
			bare++
		}
	}
	assert.Greater(t, zoned, 0, "no zoned layout in the table")
	assert.Greater(t, bare, 0, "no zone-less layout in the table")
}

// TestFastFamilyLayoutsAgreeOnZone pins the promise fastTSZoned makes: a
// family parser claims values from its whole layout list, so it may report a
// zone only when every layout in that list carries one. A mixed family would
// have to answer per claimed shape, not per family.
func TestFastFamilyLayoutsAgreeOnZone(t *testing.T) {
	for _, fam := range tsFamilies {
		want := layoutHasZone(fam.layouts[0])
		for _, layout := range fam.layouts {
			assert.Equal(t, want, layoutHasZone(layout),
				"family %s mixes zoned and zone-less layouts; fastTSZoned cannot answer for it", fam.name)
		}
		assert.Equal(t, want, allLayoutsHaveZone(fam.layouts), "family %s", fam.name)
	}
	// And the compiled table wires that answer through: every entry with a
	// fast parser reports what its layouts say.
	for _, clp := range compiledLineParsers {
		if clp.fastTS == nil {
			continue
		}
		for _, l := range clp.ts {
			assert.Equal(t, clp.fastTSZoned, l.zoned,
				"layout %q disagrees with its entry's fastTSZoned", l.layout)
		}
	}
}

// TestTimeHasZoneByFormat is the end-to-end statement: for a line of each
// shape the package parses, does Result.Time state its own offset? A caller
// weighing the line's timestamp against a runtime's own ingest time keys on
// this, so the answers are pinned per format rather than left to the layouts.
func TestTimeHasZoneByFormat(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want bool
	}{
		// Zone-less: a bare wall clock, which this package reads as UTC
		// because nothing in the line says otherwise.
		{"klog", `I0711 10:00:00.123456       1 controller.go:42] Reconciled deployment`, false},
		{"spring boot", `2026-07-06 12:00:00.123  WARN 1 --- [main] c.e.ClientApp : Connection refused`, false},
		{"python logging", `2026-07-06 12:00:00,123 - app.web - WARNING - disk almost full`, false},
		{"slash date", `2026/07/06 12:00:00 [error] upstream timed out`, false},
		{"syslog rfc3164", `<11>Jul  6 12:00:00 host app[42]: something failed`, false},
		{"apache error log", `[Wed Oct 11 14:32:52 2000] [error] [client 203.0.113.1] client denied`, false},
		{"redis", `1:M 06 Jul 2026 12:00:00.123 * Background saving started`, false},
		{"nginx without an offset", `203.0.113.7 - - [14/Mar/2026 06:42:27] "GET /healthz HTTP/1.1" 404 13 "" "probe/2.7"`, false},

		// Zoned: the line states its offset, or names an instant outright.
		{"rfc3339", `2026-07-06T12:00:00.5+02:00 ERROR something broke`, true},
		{"rfc3339 space separator", `2026-07-06 12:00:00.123Z INFO started`, true},
		{"offset with a space", `2026-07-06 12:00:00.123 +02:00 [main] ERROR: boom`, true},
		{"syslog rfc5424", `<134>1 2026-07-06T12:00:00.123Z host app 1234 ID47 - An application event`, true},
		{"librdkafka epoch", `%4|1700000000.123|FAIL|rdkafka#producer-1| [thrd:main]: broker connection down`, true},
		{"nginx with an offset", `203.0.113.7 - - [14/Mar/2026:06:42:27 -0700] "POST /api/orders HTTP/1.1" 200 658 "-" "curl/8.5" 650 0.023`, true},
		{"json rfc3339", `{"@t":"2026-07-06T12:00:00Z","@l":"Error","@m":"boom"}`, true},
		{"json epoch", `{"level":50,"time":1751805600000,"msg":"connection refused"}`, true},
		{"logfmt rfc3339", `ts=2026-07-06T12:00:00Z level=info msg=x`, true},
		{"logfmt go string", `t="2026-03-14 06:11:46.397 +0000 UTC" level=info msg=x`, true},
		{"logfmt epoch", `ts=1748239806.3691056 level=info msg=x`, true},

		// A nested line answers for the timestamp it contributed: the Docker
		// envelope carries no time of its own, so the embedded klog stamp —
		// and its wall-clock ambiguity — is what the result holds.
		{"docker json-file wrapping klog", `{"log":"I0711 10:00:00.123456       1 x.go:42] hi\n","stream":"stdout"}`, false},
		{"docker json-file with its own time", `{"log":"I0711 10:00:00.123456       1 x.go:42] hi\n","stream":"stdout","time":"2026-07-06T12:00:00Z"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			require.False(t, enriched.Time.IsZero(), "no timestamp parsed at all")
			assert.Equal(t, tc.want, enriched.TimeHasZone)
		})
	}

	// No timestamp, no zone claim.
	assert.False(t, Parse("a plain line with no metadata whatsoever").TimeHasZone)
	assert.False(t, Parse(`{"msg":"no timestamp here"}`).TimeHasZone)
	assert.False(t, Parse(`level=info msg="no timestamp here"`).TimeHasZone)
}

// TestLogfmtTimestampsAlwaysCarryAZone and TestJSONTimestampsAlwaysCarryAZone
// pin the two dependency facts enrichFromLogFmt and applyJSON assert rather
// than derive: neither logfmt.ParseTime nor lightning's lax time decoder
// accepts a zone-less shape, so a timestamp from either path is an instant. If
// a dependency widens its accepted set, these fail instead of the flag quietly
// starting to lie.
func TestLogfmtTimestampsAlwaysCarryAZone(t *testing.T) {
	for _, zoneless := range []string{
		"2026-07-06 12:00:00", "2026-07-06 12:00:00.123", "2026-07-06T12:00:00",
		"2026/07/06 12:00:00", "0711 10:00:00", "Jul  6 12:00:00",
		"2026-07-06 12:00:00.123 (no zone)",
	} {
		_, ok := logfmt.ParseTime([]byte(zoneless))
		assert.False(t, ok, "logfmt.ParseTime now accepts the zone-less %q", zoneless)
		_, ok = parseGoStringTime([]byte(zoneless))
		assert.False(t, ok, "parseGoStringTime now accepts the zone-less %q", zoneless)
	}
}

func TestJSONTimestampsAlwaysCarryAZone(t *testing.T) {
	for _, zoneless := range []string{
		"2026-07-06 12:00:00", "2026-07-06 12:00:00.123", "2026-07-06T12:00:00",
		"2026-07-06T12:00:00.123", "2026/07/06 12:00:00",
	} {
		var r Result
		ParseInto(`{"ts":"`+zoneless+`","msg":"x"}`, &r)
		assert.True(t, r.Time.IsZero(), "the JSON decoder now accepts the zone-less %q", zoneless)
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

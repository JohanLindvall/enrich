package enrich

import (
	"strings"
	"time"
)

// Per-layout-family timestamp parsers. time.Parse re-tokenizes its layout
// string on every call, which made it ~20% of the logfmt benchmark and ~15%
// of the pattern benchmark; the stdlib only fast-paths the exact RFC3339 and
// RFC3339Nano layout constants, so every other layout in the pattern table
// pays full price. These parsers cover the table's numeric layout families.
//
// The safety contract, and how this differs from the hand-rolled parser the
// CLAUDE.md rejection note shot down: each parser here serves ONE layout
// family, may return !ok freely ("not claimed" — the caller then falls back
// to the time.Parse loop, so a miss can never change behavior), and when it
// does claim an input it must produce exactly what the family's time.Parse
// layout loop produces. timeparse_test.go differential-tests every family
// against its own layouts on generated and mutated inputs, and pins the
// canonical shapes as claimed so the fast paths cannot silently rot into
// always-missing.

// digits2 parses s[i] and s[i+1] as two ASCII digits. Callers check bounds.
func digits2(s string, i int) (int, bool) {
	a, b := s[i]-'0', s[i+1]-'0'
	if a > 9 || b > 9 {
		return 0, false
	}
	return int(a)*10 + int(b), true
}

// daysInMonth mirrors time.Parse's day-of-month validation, including leap
// years.
func daysInMonth(mo, year int) int {
	if mo == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		return 29
	}
	return [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mo]
}

// clockValid mirrors parse's range checks: hour 0-23, minute and second 0-59.
func clockValid(hh, mi, ss int) bool {
	return hh < 24 && mi < 60 && ss < 60
}

// pair reads two ASCII digits at s[i] as a number. The caller has already
// proven they are digits (stampSkeleton does it for all fourteen at once), so
// unlike digits2 this does no validation.
func pair(s string, i int) int {
	return int(s[i]-'0')*10 + int(s[i+1]-'0')
}

// parseStamp19 parses the 19-byte core "YYYY<sep>MM<sep>DD HH:MM:SS" shared by
// every numeric family, validating ranges exactly as time.Parse does. The
// structural check is stampSkeleton — the same one the hand matchers use, which
// decides all fourteen digits and four separators a word at a time instead of a
// branch at a time, and leaves nothing here to re-validate.
func parseStamp19(s string, sep byte) (y, mo, d, hh, mi, ss int, ok bool) {
	if !stampSkeleton(s, sep, ' ') {
		return 0, 0, 0, 0, 0, 0, false
	}
	y = pair(s, 0)*100 + pair(s, 2)
	mo, d = pair(s, 5), pair(s, 8)
	hh, mi, ss = pair(s, 11), pair(s, 14), pair(s, 17)
	if mo < 1 || mo > 12 || d < 1 || d > daysInMonth(mo, y) || !clockValid(hh, mi, ss) {
		return 0, 0, 0, 0, 0, 0, false
	}
	return y, mo, d, hh, mi, ss, true
}

// fracSecond9 parses an optional trailing-".999999999"-style fraction at
// s[i:], mirroring time.Parse's stdFracSecond9: a '.' or ',' followed by at
// least one digit consumes ALL contiguous digits, with only the first nine
// contributing (parseNanoseconds truncates at ten bytes). An absent or
// malformed fraction is simply not consumed (end == i), as the layout treats
// it as omitted.
func fracSecond9(s string, i int) (ns, end int) {
	if i+1 >= len(s) || (s[i] != '.' && s[i] != ',') || s[i+1] < '0' || s[i+1] > '9' {
		return 0, i
	}
	j := i + 1
	for j < len(s) && '0' <= s[j] && s[j] <= '9' {
		j++
	}
	digits := min(j-(i+1), 9)
	for k := i + 1; k < i+1+digits; k++ {
		ns = ns*10 + int(s[k]-'0')
	}
	return ns * pow10[9-digits], j
}

// pow10 scales a fraction of n digits up to nanoseconds in one multiply, where
// the shift-by-one loop it replaces ran up to eight times per timestamp.
var pow10 = [10]int{1, 10, 100, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9}

// fracExactN parses a mandatory ".000"-style fraction of exactly n digits at
// s[i:]. Like stdFracSecond0 it accepts ',' as the separator; unlike atoi it
// claims digits only — a signed fraction falls back to time.Parse.
func fracExactN(s string, i, n int) (ns, end int, ok bool) {
	if i+1+n > len(s) || (s[i] != '.' && s[i] != ',') {
		return 0, 0, false
	}
	for k := i + 1; k <= i+n; k++ {
		c := s[k]
		if c < '0' || c > '9' {
			return 0, 0, false
		}
		ns = ns*10 + int(c-'0')
	}
	return ns * pow10[9-n], i + 1 + n, true
}

// zoneColon parses a "±hh:mm" offset at s[i:], mirroring stdNumColonTZ,
// including its deliberate quirks: hour 24 and minute 60 are in range (the
// stdlib comment: "some people do write offsets of 24 hours or 60 minutes").
// It returns the offset in seconds.
func zoneColon(s string, i int) (offset, end int, ok bool) {
	if i+6 > len(s) || (s[i] != '+' && s[i] != '-') || s[i+3] != ':' {
		return 0, 0, false
	}
	hh, ok1 := digits2(s, i+1)
	mm, ok2 := digits2(s, i+4)
	if !ok1 || !ok2 || hh > 24 || mm > 60 {
		return 0, 0, false
	}
	offset = (hh*60 + mm) * 60
	if s[i] == '-' {
		offset = -offset
	}
	return offset, i + 6, true
}

// daysFromCivil converts a Gregorian date to days since 1970-01-01, by the
// shift-the-year-to-March algorithm: with March as month 0 the leap day lands
// at the end of the year, so the day-of-year is one affine expression and the
// only division work left is the 400/100/4 century rule. time.Date reaches the
// same number through norm() calls and a table lookup; this is the same
// arithmetic with the parts a validated date does not need removed.
func daysFromCivil(y, mo, d int) int64 {
	if mo <= 2 {
		y--
	}
	era := y / 400
	if y < 0 {
		era = (y - 399) / 400
	}
	yoe := y - era*400 // [0, 399]
	mp := mo - 3
	if mo <= 2 {
		mp = mo + 9 // March-based month index
	}
	doy := (153*mp+2)/5 + d - 1            // [0, 365]
	doe := yoe*365 + yoe/4 - yoe/100 + doy // [0, 146096]
	return int64(era)*146097 + int64(doe) - 719468
}

// utcStamp assembles the parsed fields into the time value the layout loop
// would return: the instant of the wall clock minus the zone offset, in UTC —
// which is also what parse's FixedZone tail resolves to once the caller's
// .UTC() discards the fabricated location. The fields are already range-checked
// by the time they get here, so the seconds are computed directly rather than
// through time.Date's normalization and zone lookup; timeparse_test.go pins
// this to time.Date.
func utcStamp(y, mo, d, hh, mi, ss, ns, offset int) time.Time {
	sec := daysFromCivil(y, mo, d)*86400 + int64(hh*3600+mi*60+ss-offset)
	return time.Unix(sec, int64(ns)).UTC()
}

// zoneTokens are the reference-layout elements that put a numeric UTC offset
// in the text: Z0700, Z07:00, Z07, -0700, -07:00, -07 and their
// seconds-bearing variants, all of which start with one of these two prefixes.
//
// The MST token is deliberately NOT here. It matches a zone abbreviation, and
// time.Parse resolves an abbreviation against the *host's* zone database:
// "Wed Aug 26 22:26:14 CEST 2026" parses to 20:26:14Z where TZ=Europe/Stockholm
// and to 22:26:14Z everywhere else, and an abbreviation the host does not know
// silently becomes offset zero. A layout whose only zone element is MST
// therefore does not tell you the offset — which is exactly what
// TestLayoutHasZoneMatchesRoundTrip's oracle reports for it.
var zoneTokens = [...]string{"Z07", "-07"}

// fixedZoneLiterals are zone NAMES a layout may spell as plain text rather
// than through a token. Both name offset zero, and because they are literals
// the layout matches only text carrying that exact name — so unlike the MST
// token above, they pin the value to an offset the host cannot change (the
// probe over TZ=UTC/Europe/Stockholm/Europe/London/America/New_York/Asia/Tokyo/
// Etc/GMT+5/Africa/Abidjan gives offset zero for all of them). This is how the
// date(1) entry states its zone; see the table.
var fixedZoneLiterals = [...]string{" UTC ", " GMT "}

// layoutHasZone reports whether a layout carries a zone element — that is,
// whether the input it parses states its own UTC offset. It is what
// Result.TimeHasZone is derived from: a zone-less layout leaves the wall clock
// unanchored, and every parser here reads such a stamp as UTC because there is
// nothing else it could do, so the resulting Time is only an instant if the
// writer's clock really was UTC.
//
// The substring test is exact for a layout built from the reference date: none
// of its other elements ("2006", "01", "Jan", "02", "Mon", "15", "04", "05",
// ".000") can produce "Z07" or "-07", nor a space-delimited "UTC"/"GMT", and a
// literal in a layout that did would be pathological.
// TestLayoutHasZoneMatchesRoundTrip pins the token layouts against a round-trip
// oracle rather than trusting that argument, and
// TestFixedZoneLiteralLayoutsPinTheOffset covers the literal ones, which that
// oracle cannot reach.
func layoutHasZone(layout string) bool {
	for _, tok := range zoneTokens {
		if strings.Contains(layout, tok) {
			return true
		}
	}
	for _, lit := range fixedZoneLiterals {
		if strings.Contains(layout, lit) {
			return true
		}
	}
	return false
}

// allLayoutsHaveZone reports whether every layout in ts carries a zone. A
// family parser claims shapes from its whole list, so it can only promise a
// zone when they all do; an empty or mixed list answers false, which is the
// safe direction (a caller weighing a parsed stamp against a producer's own
// treats "no zone" as "ambiguous wall clock").
func allLayoutsHaveZone(ts []string) bool {
	if len(ts) == 0 {
		return false
	}
	for _, layout := range ts {
		if !layoutHasZone(layout) {
			return false
		}
	}
	return true
}

// parseYmdSlashTime is the family parser for ymdSlashLayouts
// ("2006/01/02 15:04:05.999999999").
func parseYmdSlashTime(s string) (time.Time, bool) {
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '/')
	if !ok {
		return time.Time{}, false
	}
	ns, end := fracSecond9(s, 19)
	if end != len(s) {
		return time.Time{}, false
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, 0), true
}

// parseYmdSlash6Time is the family parser for the mandatory-6-digit-fraction
// layout "2006/01/02 15:04:05.000000".
func parseYmdSlash6Time(s string) (time.Time, bool) {
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '/')
	if !ok {
		return time.Time{}, false
	}
	ns, end, ok := fracExactN(s, 19, 6)
	if !ok || end != len(s) {
		return time.Time{}, false
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, 0), true
}

// parseMsSpaceTime is the family parser for msSpaceLayouts
// ("2006-01-02 15:04:05.000", "2006-01-02 15:04:05"): the fraction is either
// absent or exactly three digits.
func parseMsSpaceTime(s string) (time.Time, bool) {
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '-')
	if !ok {
		return time.Time{}, false
	}
	ns := 0
	if len(s) != 19 {
		var end int
		ns, end, ok = fracExactN(s, 19, 3)
		if !ok || end != len(s) {
			return time.Time{}, false
		}
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, 0), true
}

// parseMsSpaceTSTime is the family parser for msSpaceTSLayouts
// ("2006-01-02 15:04:05.000 -07:00", "2006-01-02 15:04:05 -07:00").
func parseMsSpaceTSTime(s string) (time.Time, bool) {
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '-')
	if !ok {
		return time.Time{}, false
	}
	i, ns := 19, 0
	if i < len(s) && (s[i] == '.' || s[i] == ',') {
		ns, i, ok = fracExactN(s, i, 3)
		if !ok {
			return time.Time{}, false
		}
	}
	if i >= len(s) || s[i] != ' ' {
		return time.Time{}, false
	}
	offset, end, ok := zoneColon(s, i+1)
	if !ok || end != len(s) {
		return time.Time{}, false
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, offset), true
}

// parseRfc3339SpaceZTime is the family parser for rfc3339NanoSpaceLayout
// ("2006-01-02 15:04:05.999999999Z07:00" — RFC3339Nano with a space
// separator): an any-length fraction, then 'Z' or a colon offset.
func parseRfc3339SpaceZTime(s string) (time.Time, bool) {
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '-')
	if !ok {
		return time.Time{}, false
	}
	ns, i := fracSecond9(s, 19)
	if i < len(s) && s[i] == 'Z' {
		if i+1 != len(s) {
			return time.Time{}, false
		}
		return utcStamp(y, mo, d, hh, mi, ss, ns, 0), true
	}
	offset, end, ok := zoneColon(s, i)
	if !ok || end != len(s) {
		return time.Time{}, false
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, offset), true
}

// parsePlainDateTime is the family parser for the fraction-less
// "2006-01-02 15:04:05" layout: exactly the 19-byte core.
func parsePlainDateTime(s string) (time.Time, bool) {
	if len(s) != 19 {
		return time.Time{}, false
	}
	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '-')
	if !ok {
		return time.Time{}, false
	}
	return utcStamp(y, mo, d, hh, mi, ss, 0, 0), true
}

// inferYear supplies the year a klog or RFC3164 timestamp omits: the clock's,
// stepped across a year boundary when the stamp's month and the clock's sit on
// opposite sides of it. expandKlogTime and expandStampTime deliberately keep
// their own copies of this logic — they are the oracles the differential
// tests hold parseKlogTime and parseStampTime to, so they must not share code
// with the fast paths they check.
func inferYear(mo int, now time.Time) int {
	year := now.Year()
	if now.Month() == time.January && mo == 12 {
		year-- // date probably refers to previous year
	} else if now.Month() == time.December && mo == 1 {
		year++ // date probably refers to next year
	}
	return year
}

// parseKlogTime parses a klog "MMDD hh:mm:ss[.dddddd]" timestamp directly,
// replacing the expandKlogTime year-prefix + time.Parse round trip (which
// allocated the prefixed string) for the canonical shapes. The year inference,
// including the year-boundary adjustment, mirrors expandKlogTime; the
// mandatory-6-digit fraction mirrors timeLayoutsKlog's first layout and the
// bare form its second. Anything else falls back to the old path.
func parseKlogTime(s string, now time.Time) (time.Time, bool) {
	if len(s) != 13 && len(s) != 20 {
		return time.Time{}, false
	}
	if s[4] != ' ' || s[7] != ':' || s[10] != ':' {
		return time.Time{}, false
	}
	mo, ok1 := digits2(s, 0)
	d, ok2 := digits2(s, 2)
	hh, ok3 := digits2(s, 5)
	mi, ok4 := digits2(s, 8)
	ss, ok5 := digits2(s, 11)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return time.Time{}, false
	}
	ns := 0
	if len(s) == 20 {
		var end int
		var ok bool
		ns, end, ok = fracExactN(s, 13, 6)
		if !ok || end != len(s) {
			return time.Time{}, false
		}
	}
	year := inferYear(mo, now)
	if mo < 1 || mo > 12 || d < 1 || d > daysInMonth(mo, year) || !clockValid(hh, mi, ss) {
		return time.Time{}, false
	}
	return utcStamp(year, mo, d, hh, mi, ss, ns, 0), true
}

// monthByName maps an exact-case three-letter month abbreviation to its
// number, or 0. Exact case is all the RFC3164 regex can capture; any other
// casing (which time.Parse's lookup would fold) stays on the slow path.
func monthByName(s string) int {
	switch s {
	case "Jan":
		return 1
	case "Feb":
		return 2
	case "Mar":
		return 3
	case "Apr":
		return 4
	case "May":
		return 5
	case "Jun":
		return 6
	case "Jul":
		return 7
	case "Aug":
		return 8
	case "Sep":
		return 9
	case "Oct":
		return 10
	case "Nov":
		return 11
	case "Dec":
		return 12
	}
	return 0
}

// parseStampTime parses an RFC3164 syslog "Mmm dd hh:mm:ss" timestamp
// directly, replacing the expandStampTime year-prefix round trip (a
// time.Parse("Jan") call plus two allocations) and the "2006 Jan _2 15:04:05"
// layout parse. The day mirrors stdUnderDay: one literal space, then _2's
// optional pad space, then one or two digits. Year inference, including the
// boundary adjustment, mirrors expandStampTime. Anything else — odd casing,
// tabs, extra padding — falls back to the old path.
func parseStampTime(s string, now time.Time) (time.Time, bool) {
	if len(s) < 4 || s[3] != ' ' {
		return time.Time{}, false
	}
	mo := monthByName(s[:3])
	if mo == 0 {
		return time.Time{}, false
	}
	i := 4
	if i < len(s) && s[i] == ' ' {
		i++ // _2's optional pad space
	}
	d := 0
	j := i
	for j < len(s) && j < i+2 && isDigitB(s[j]) {
		d = d*10 + int(s[j]-'0')
		j++
	}
	if j == i || j+9 != len(s) || s[j] != ' ' || s[j+3] != ':' || s[j+6] != ':' {
		return time.Time{}, false
	}
	hh, ok1 := digits2(s, j+1)
	mi, ok2 := digits2(s, j+4)
	ss, ok3 := digits2(s, j+7)
	if !ok1 || !ok2 || !ok3 {
		return time.Time{}, false
	}
	year := inferYear(mo, now)
	if d < 1 || d > daysInMonth(mo, year) || !clockValid(hh, mi, ss) {
		return time.Time{}, false
	}
	return utcStamp(year, mo, d, hh, mi, ss, 0, 0), true
}

// parseGoStringTime is the fast path for the Go time.Time String() format
// "2006-01-02 15:04:05.999 -0700 MST" — what the faro/browser-telemetry
// logfmt lines carry — tried by enrichFromLogFmt before logfmt.ParseTime
// (whose time.Parse call on this layout was ~20% of the whole logfmt-line
// parse). It mirrors ParseTime's trailing-delimiter trim, and claims only
// zone-abbreviation shapes whose parseTimeZone outcome is certain: three
// upper-case letters (a bare "GMT" included — a GMT+8-style suffix would make
// the shape longer and is not claimed), or four or five ending in 'T'. The
// instant comes from the numeric offset alone, exactly as parse's
// FixedZone/local-lookup tail resolves once .UTC() discards the location.
func parseGoStringTime(val []byte) (time.Time, bool) {
	end := len(val)
	for end > 0 {
		switch val[end-1] {
		case '}', ']', ',', ')', '"':
			end--
			continue
		}
		break
	}
	// val aliases the immutable input line (or a constant), like every other
	// value the logfmt callback sees.
	s := unsafeString(val[:end])

	y, mo, d, hh, mi, ss, ok := parseStamp19(s, '-')
	if !ok {
		return time.Time{}, false
	}
	ns, i := fracSecond9(s, 19)
	// " ±hhmm " — stdNumTZ: sign and four digits, no colon.
	if i+7 > len(s) || s[i] != ' ' || (s[i+1] != '+' && s[i+1] != '-') || s[i+6] != ' ' {
		return time.Time{}, false
	}
	zh, ok1 := digits2(s, i+2)
	zm, ok2 := digits2(s, i+4)
	if !ok1 || !ok2 || zh > 24 || zm > 60 {
		return time.Time{}, false
	}
	offset := (zh*60 + zm) * 60
	if s[i+1] == '-' {
		offset = -offset
	}

	zone := s[i+7:]
	if len(zone) < 3 || len(zone) > 5 {
		return time.Time{}, false
	}
	for j := 0; j < len(zone); j++ {
		if zone[j] < 'A' || zone[j] > 'Z' {
			return time.Time{}, false
		}
	}
	if len(zone) > 3 && zone[len(zone)-1] != 'T' {
		return time.Time{}, false
	}
	if len(zone) > 3 && zone[0] == 'G' && zone[1] == 'M' && zone[2] == 'T' {
		// parseTimeZone special-cases a GMT prefix before its letter counting
		// and consumes only the three bytes (plus an optional signed digit
		// offset, which the uppercase filter already excluded); the leftover
		// letters of a "GMTT"-style name make time.Parse fail, so those
		// shapes stay on the slow path. Bare "GMT" is claimed, and unlike
		// UTC its numeric offset does apply.
		return time.Time{}, false
	}
	if zone[0] == 'U' && zone[1] == 'T' && zone[2] == 'C' {
		if len(zone) > 3 {
			// "UTCT" hits parse's UTC prefix case and then fails on the
			// leftover byte; leave such shapes to the slow path.
			return time.Time{}, false
		}
		// A literal "UTC" name short-circuits parse before the numeric offset
		// is consulted: the wall clock is taken as already being UTC. (Real
		// emitters write "+0000 UTC", where the difference is invisible; the
		// differential test's "+0500 UTC" is what forced this branch.)
		offset = 0
	}
	return utcStamp(y, mo, d, hh, mi, ss, ns, offset), true
}

// fastLayoutTime returns the family parser covering exactly the given layout
// list, or nil when no hand-rolled family exists; init attaches the result to
// each compiled table entry, and parseLayoutTime consults it before the
// time.Parse loop.
func fastLayoutTime(ts []string) func(string) (time.Time, bool) {
	switch {
	case len(ts) == 1 && ts[0] == "2006/01/02 15:04:05.999999999":
		return parseYmdSlashTime
	case len(ts) == 1 && ts[0] == "2006/01/02 15:04:05.000000":
		return parseYmdSlash6Time
	case len(ts) == 2 && ts[0] == "2006-01-02 15:04:05.000" && ts[1] == "2006-01-02 15:04:05":
		return parseMsSpaceTime
	case len(ts) == 2 && ts[0] == "2006-01-02 15:04:05.000 -07:00" && ts[1] == "2006-01-02 15:04:05 -07:00":
		return parseMsSpaceTSTime
	case len(ts) == 1 && ts[0] == rfc3339NanoSpaceLayout:
		return parseRfc3339SpaceZTime
	case len(ts) == 1 && ts[0] == "2006-01-02 15:04:05":
		return parsePlainDateTime
	}
	return nil
}

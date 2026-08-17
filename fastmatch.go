package enrich

import "strings"

// Hand-written matchers for the hottest pattern-table entries, the lazy
// byte-presence memo that dedupes the gate scans, and the anchored substring
// scan. Together they remove most regexp executions (and the []int a
// FindStringSubmatchIndex match allocates) from the common plain-text shapes:
// the profile had the bitState backtracker at ~40% of the pattern benchmark,
// and repeated IndexByte gate scans at ~40% of the miss benchmark.

// indexAnchored is strings.Index for a needle whose FIRST byte is a poor
// anchor. strings.Index scans for needle[0] and re-compares at every hit, so
// the cost is set by how often that one byte occurs in the haystack — and the
// needles this package searches for lead with the commonest byte around: the
// 't' of "traceparent" against plain log prose, the '"' of `"level":` against
// a JSON line, where it opens every key and every string value. Anchoring the
// scan on a rare byte of the needle instead runs the same algorithm over a
// fraction of the candidates (~12% of the plain-text benchmark went into the
// 't' scan alone).
//
// needle must be non-empty and anchor an index into it; needle[anchor] should
// be the needle's rarest byte in the text being searched. Every needle here is
// short (at most a dozen bytes), so the missing Rabin-Karp fallback that
// strings.Index keeps for long needles cannot turn into a blow-up on hostile
// input: a failed candidate costs at most len(needle) byte compares.
// micro_test.go pins this to strings.Index.
func indexAnchored(s, needle string, anchor int) int {
	// The last index at which the anchor byte can still be followed by the
	// needle's tail; a match found past it would not fit in s.
	last := len(s) - len(needle) + anchor
	for i := anchor; i <= last; i++ {
		j := strings.IndexByte(s[i:], needle[anchor])
		if j < 0 {
			return -1
		}
		if i += j; i > last {
			return -1
		}
		if start := i - anchor; s[start:start+len(needle)] == needle {
			return start
		}
	}
	return -1
}

// byteMemo lazily records, per line, whether a byte occurs anywhere in it.
// The gates of different table entries keep asking about the same bytes ('='
// for the logfmt gate, the type= needle and the traceparent probe; ':' for
// the panic needle and the traceparent probe; '\n' twice) — each distinct
// byte is now scanned at most once per line. Purely stack-local state, so the
// package keeps zero mutable global state, and memoizing a pure predicate
// over the immutable line cannot change any decision.
type byteMemo struct {
	checked [4]uint64
	present [4]uint64
}

// has reports whether b occurs in s, scanning at most once per (line, byte).
func (m *byteMemo) has(s string, b byte) bool {
	w, bit := b>>6, uint64(1)<<(b&63)
	if m.checked[w]&bit == 0 {
		m.checked[w] |= bit
		if strings.IndexByte(s, b) >= 0 {
			m.present[w] |= bit
		}
	}
	return m.present[w]&bit != 0
}

// A fast matcher decides an entry's regex outcome without running it:
// fastNoMatch/fastMatched are proven verdicts (fastmatch_test.go pins them to
// the regex on generated inputs and the fuzz corpus), fastUndecided falls
// through to the gates and the regex. Matchers are recognized in init by the
// entry's exact pattern string — editing a pattern detaches its matcher
// rather than desynchronizing it.
type fastVerdict int8

const (
	fastUndecided fastVerdict = iota
	fastNoMatch
	fastMatched
)

// fastSpans carries the named-group captures of a fastMatched verdict as
// [start,end) index pairs into the line; an empty span means the group did
// not participate (exactly the cases the regex application loop skips).
type fastSpans struct {
	time  [2]int
	level [2]int
}

// spaceMaskRE is regexp's Perl \s class as a bit per byte value: [\t\n\f\r ] —
// \v is NOT included.
const spaceMaskRE = 1<<'\t' | 1<<'\n' | 1<<'\f' | 1<<'\r' | 1<<' '

// isSpaceRE reports whether c is in that class. The mask test is three
// instructions where the five comparisons it replaces were five compares and
// five branches — worth it because the token walks below run it per byte. A
// byte of 64 or more shifts the mask away entirely, which Go defines as zero,
// so no range test is needed.
func isSpaceRE(c byte) bool {
	return uint64(spaceMaskRE)>>c&1 != 0
}

func isDigitB(c byte) bool { return c-'0' <= 9 }

// isAlphaB mirrors the regexes' [a-zA-Z] class. Setting the case bit folds
// A-Z onto a-z and moves every other byte — digits, punctuation, and the
// lead/continuation bytes of a multi-byte rune, none of which the rune-based
// class accepts either — outside a-z.
func isAlphaB(c byte) bool { return c|0x20-'a' <= 'z'-'a' }

// Lane masks for the 19-byte timestamp skeleton, over the two words that cover
// its first sixteen bytes: separators at s[4], s[7] (dateSep), s[10] (timeSep)
// and s[13] (':'), digits everywhere else. Lane i of word w holds byte i of it,
// as le64 reads them.
const (
	stampSepMask0  = 0xff<<32 | 0xff<<56                                        // s[4], s[7]
	stampSepMask1  = 0xff<<16 | 0xff<<40                                        // s[10], s[13]
	stampDigits0   = 0x80 | 0x80<<8 | 0x80<<16 | 0x80<<24 | 0x80<<40 | 0x80<<48 // s[0..3], s[5..6]
	stampDigits1   = 0x80 | 0x80<<8 | 0x80<<24 | 0x80<<32 | 0x80<<48 | 0x80<<56 // s[8..9], s[11..12], s[14..15]
	stampColonWant = uint64(':') << 40                                          // s[13]
)

// stampSkeleton reports whether s starts with the 19-byte digit skeleton
// "dddd<dateSep>dd<dateSep>dd<timeSep>dd:dd:dd". It replicates the regexes'
// structural test only — value ranges are deliberately not checked, exactly
// like \d{4} isn't.
//
// The first sixteen bytes are decided two words at a time (the per-byte version
// it replaced is kept as its oracle in hex_test.go): the four separators are one
// XOR-and-compare per word, and the twelve digits one laneRange per word. Every
// one of those sixteen positions is checked, so a byte with its high bit set —
// which would make laneRange's masked sums inexact — can only belong to a
// position that fails anyway, and is rejected outright.
func stampSkeleton(s string, dateSep, timeSep byte) bool {
	if len(s) < 19 {
		return false
	}
	w0, w1 := le64(s, 0), le64(s, 8)
	sepWant0 := uint64(dateSep)<<32 | uint64(dateSep)<<56
	sepWant1 := uint64(timeSep)<<16 | stampColonWant
	if (w0^sepWant0)&stampSepMask0 != 0 || (w1^sepWant1)&stampSepMask1 != 0 {
		return false
	}
	if (w0|w1)&swarHigh != 0 {
		return false
	}
	if laneRange(w0, '0', '9')&stampDigits0 != stampDigits0 ||
		laneRange(w1, '0', '9')&stampDigits1 != stampDigits1 {
		return false
	}
	return s[16] == ':' && isDigitB(s[17]) && isDigitB(s[18])
}

// zColonSpaceEnd matches the shared "(Z:)?\s" suffix at msg[i:], returning the
// offset just past it or -1. Maximal munch is exact here: if "Z:" is present
// but the following byte is not \s, matching without consuming "Z:" would put
// \s at 'Z' and fail too.
func zColonSpaceEnd(msg string, i int) int {
	if i+1 < len(msg) && msg[i] == 'Z' && msg[i+1] == ':' {
		i += 2
	}
	if i < len(msg) && isSpaceRE(msg[i]) {
		return i + 1
	}
	return -1
}

// ymdSlashStampEnd returns the offset just past a leading
// `\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?` — the timestamp group the
// Go-log family of entries opens with — or -1. Greedy fraction consumption is
// exact for every tail the table puts after this group ("(Z:)?\s", "\s\["): a
// shorter fraction ends on a digit, which none of 'Z', '.' or \s accepts.
func ymdSlashStampEnd(msg string) int {
	if !stampSkeleton(msg, '/', ' ') {
		return -1
	}
	i := 19
	if i+1 < len(msg) && msg[i] == '.' && isDigitB(msg[i+1]) {
		i += 2
		for i < len(msg) && isDigitB(msg[i]) {
			i++
		}
	}
	return i
}

// matchYmdSlashOptFrac decides `^(?P<time>\d{4}/\d{2}/\d{2}
// \d{2}:\d{2}:\d{2}(\.\d+)?)(Z:)?\s` — the generic Go-log shape, the most
// common plain-text entry.
func matchYmdSlashOptFrac(msg string) (fastSpans, fastVerdict) {
	i := ymdSlashStampEnd(msg)
	if i < 0 || zColonSpaceEnd(msg, i) < 0 {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, i}}, fastMatched
}

// matchYmdSlashBracketLevel decides `^(?P<time>\d{4}/\d{2}/\d{2}
// \d{2}:\d{2}:\d{2}(\.\d+)?)\s\[(?P<level>[a-zA-Z]+)\]` — the bracketed-level
// Go-log shape, which the table tries BEFORE the bare one above. Without a
// matcher its required '[' costs a whole-line scan on every ymd-slash line,
// most of which carry no bracket at all. The greedy level run is exact: a
// shorter one ends on a letter, which ']' does not accept.
func matchYmdSlashBracketLevel(msg string) (fastSpans, fastVerdict) {
	i := ymdSlashStampEnd(msg)
	if i < 0 || i+1 >= len(msg) || !isSpaceRE(msg[i]) || msg[i+1] != '[' {
		return fastSpans{}, fastNoMatch
	}
	spans := fastSpans{time: [2]int{0, i}}
	i += 2
	level := i
	for i < len(msg) && isAlphaB(msg[i]) {
		i++
	}
	if i == level || i >= len(msg) || msg[i] != ']' {
		return fastSpans{}, fastNoMatch
	}
	spans.level = [2]int{level, i}
	return spans, fastMatched
}

// matchMsDashNoFrac decides `^(?P<time>\d{4}-\d{2}-\d{2}
// \d{2}:\d{2}:\d{2})(Z:)?\s` (the fraction-less dash-date entry).
func matchMsDashNoFrac(msg string) (fastSpans, fastVerdict) {
	if !stampSkeleton(msg, '-', ' ') || zColonSpaceEnd(msg, 19) < 0 {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, 19}}, fastMatched
}

// matchYmdSlash6Frac decides `^(?P<time>\d{4}/\d{2}/\d{2}
// \d{2}:\d{2}:\d{2}\.\d{6})(Z:)?\s` (the mandatory-6-digit-fraction entry).
func matchYmdSlash6Frac(msg string) (fastSpans, fastVerdict) {
	if !stampSkeleton(msg, '/', ' ') || len(msg) < 26 || msg[19] != '.' ||
		!isDigitB(msg[20]) || !isDigitB(msg[21]) || !isDigitB(msg[22]) ||
		!isDigitB(msg[23]) || !isDigitB(msg[24]) || !isDigitB(msg[25]) {
		return fastSpans{}, fastNoMatch
	}
	if zColonSpaceEnd(msg, 26) < 0 {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, 26}}, fastMatched
}

// matchNginxPrefix pre-decides the miss side of the nginx access-log entry
// `^[^[\s-]+\s-\s(-|[^\s[]+)\s\[(?P<time>[^]]+)]...`. The entry is anchored but
// starts with a negated class, so firstBytes cannot bucket it and it is tried
// on EVERY line — where its " - " needle used to cost a whole-line '-' scan
// per line, the largest single cost on the no-match path.
//
// The prefix is decided from the first byte the leading class stops at: the
// class is greedy and cannot contain whitespace, so `\s` must match exactly
// there, and '-' and \s must follow it. A line whose prefix does pass falls
// through to the needle and the regex.
func matchNginxPrefix(msg string) (fastSpans, fastVerdict) {
	// The class stops at '[', '-' or whitespace. Every stop byte but '[' is
	// below 64, so one mask covers them and any byte the compare let through
	// shifts it harmlessly away.
	const stopMask = spaceMaskRE | 1<<'-'
	i := 0
	for i < len(msg) && msg[i] != '[' && uint64(stopMask)>>msg[i]&1 == 0 {
		i++
	}
	if i == 0 || i+2 >= len(msg) || !isSpaceRE(msg[i]) || msg[i+1] != '-' || !isSpaceRE(msg[i+2]) {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{}, fastUndecided
}

// matchRedisPrefix pre-decides only the miss side of the redis entry
// `^\d+:[XCSM]\s...`: its ':' required byte appears in ordinary prose
// ("error: connection refused"), which used to send every such digit-first
// line into a doomed backtracker run. The maximal digit run is exact — every
// byte before its end is a digit, so ':' cannot match earlier — and a prefix
// pass returns fastUndecided so the regex still performs the full match.
func matchRedisPrefix(msg string) (fastSpans, fastVerdict) {
	j := 0
	for j < len(msg) && isDigitB(msg[j]) {
		j++
	}
	if j == 0 || j+2 >= len(msg) || msg[j] != ':' ||
		(msg[j+1] != 'X' && msg[j+1] != 'C' && msg[j+1] != 'S' && msg[j+1] != 'M') ||
		!isSpaceRE(msg[j+2]) {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{}, fastUndecided
}

// rfc3339Stamp decides the `"?(?P<time>\d{4}-\d{2}-\d{2}<sep>\d{2}:\d{2}:\d{2}
// (\.\d+)?(Z|(\+|-)\d{2}:\d{2}))"?` prefix that every dash-date entry with a
// hand matcher opens with. It returns the time group's span and the offset just
// past the optional closing quote. sep is the date/time separator ('T' or ' ');
// zSuffixOnly restricts the zone to a literal 'Z' (the space-separated
// variant), otherwise 'Z' or "±dd:dd".
//
// Both optional quotes are forced, not chosen: `\d` cannot match the opening
// one, and leaving the closing one unconsumed puts '"' where the callers' own
// tails need \s or \t. The greedy fraction is exact too — a shorter one ends on
// a digit, which no zone starter accepts.
func rfc3339Stamp(msg string, sep byte, zSuffixOnly bool) (ts [2]int, end int, ok bool) {
	off := 0
	if len(msg) > 0 && msg[0] == '"' {
		off = 1
	}
	s := msg[off:]
	if !stampSkeleton(s, '-', sep) {
		return ts, 0, false
	}
	i := 19
	if i+1 < len(s) && s[i] == '.' && isDigitB(s[i+1]) {
		i += 2
		for i < len(s) && isDigitB(s[i]) {
			i++
		}
	}
	switch {
	case i < len(s) && s[i] == 'Z':
		i++
	case !zSuffixOnly && i+6 <= len(s) && (s[i] == '+' || s[i] == '-') &&
		isDigitB(s[i+1]) && isDigitB(s[i+2]) && s[i+3] == ':' &&
		isDigitB(s[i+4]) && isDigitB(s[i+5]):
		i += 6
	default:
		return ts, 0, false
	}
	end = off + i
	ts = [2]int{off, end}
	if end < len(msg) && msg[end] == '"' {
		end++
	}
	return ts, end, true
}

// matchRFC3339Level is the shared decider for the two generic RFC3339-ish
// entries `^"?(?P<time>...)"?\s+((?P<level>[a-z]+|[A-Z]+)\s)?`: an optionally
// quoted timestamp, at least one \s, then an optional single-case level word
// itself followed by \s.
//
// Every greedy consumption here is exact under backtracking: shortened \s+
// leaves a space where the level must start, and a shortened level run ends on
// its own letter class (not \s). "Info" matches no level at all: [a-z]+ cannot
// start it and [A-Z]+ takes only "I", which 'n' then fails to follow with \s.
func matchRFC3339Level(msg string, sep byte, zSuffixOnly bool) (fastSpans, fastVerdict) {
	ts, j, ok := rfc3339Stamp(msg, sep, zSuffixOnly)
	if !ok {
		return fastSpans{}, fastNoMatch
	}
	spans := fastSpans{time: ts}
	k := j
	for k < len(msg) && isSpaceRE(msg[k]) {
		k++
	}
	if k == j {
		return fastSpans{}, fastNoMatch // \s+ needs at least one
	}
	// Optional level: a maximal run of one letter case, followed by \s.
	e := k
	for e < len(msg) && msg[e]-'a' <= 'z'-'a' {
		e++
	}
	if e == k {
		for e < len(msg) && msg[e]-'A' <= 'Z'-'A' {
			e++
		}
	}
	if e > k && e < len(msg) && isSpaceRE(msg[e]) {
		spans.level = [2]int{k, e}
	}
	return spans, fastMatched
}

func matchRFC3339T(msg string) (fastSpans, fastVerdict) {
	return matchRFC3339Level(msg, 'T', false)
}

func matchRFC3339Space(msg string) (fastSpans, fastVerdict) {
	return matchRFC3339Level(msg, ' ', true)
}

// matchLambda decides the AWS Lambda entry `^"?(?P<time>RFC3339)"?\t
// [0-9a-fA-F-]{36}\t(?P<level>[A-Z]+)\t`. The table tries it before the generic
// RFC3339 entry, so its '\t' needle costs a whole-line scan on every RFC3339
// line; the tab is at a position the timestamp already fixes. The fixed-width
// request ID and the greedy level run (a shorter one ends on A-Z, which '\t'
// does not accept) leave nothing for the regex to decide differently.
func matchLambda(msg string) (fastSpans, fastVerdict) {
	ts, i, ok := rfc3339Stamp(msg, 'T', false)
	if !ok {
		return fastSpans{}, fastNoMatch
	}
	const idLen = 36
	if i+idLen+2 > len(msg) || msg[i] != '\t' || msg[i+idLen+1] != '\t' {
		return fastSpans{}, fastNoMatch
	}
	for j := i + 1; j <= i+idLen; j++ {
		if c := msg[j]; !isHex(c) && c != '-' {
			return fastSpans{}, fastNoMatch
		}
	}
	i += idLen + 2
	level := i
	for i < len(msg) && msg[i]-'A' <= 'Z'-'A' {
		i++
	}
	if i == level || i == len(msg) || msg[i] != '\t' {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: ts, level: [2]int{level, i}}, fastMatched
}

// fastMatcherFor returns the hand matcher for exactly this pattern string, or
// nil. Keying on the whole pattern means an edited entry silently loses its
// matcher (and the differential test's coverage assertion flags a deleted
// shape), never runs a stale one.
func fastMatcherFor(re string) func(string) (fastSpans, fastVerdict) {
	switch re {
	case `^` + ymdSlashExpr + `(Z:)?\s`:
		return matchYmdSlashOptFrac
	case `^` + ymdSlashExpr + `\s\[(?P<level>[a-zA-Z]+)\]`:
		return matchYmdSlashBracketLevel
	case `^` + rfc3339NanoExpr + `\t[0-9a-fA-F-]{36}\t(?P<level>[A-Z]+)\t`:
		return matchLambda
	case `^[^[\s-]+\s-\s(-|[^\s[]+)\s\[(?P<time>[^]]+)]\s+((?P<response_code>\d+)\s+"[^"]+"|"[^"]+"\s(?P<response_code>\d+)|"(([^\s]+\s)){3}(?P<response_code>\d+))\s`:
		return matchNginxPrefix
	case `^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(Z:)?\s`:
		return matchMsDashNoFrac
	case `^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6})(Z:)?\s`:
		return matchYmdSlash6Frac
	case `^\d+:[XCSM]\s(?P<time>\d{1,2}\s[A-Z][a-z]+\s\d{4}\s\d{2}:\d{2}:\d{2}(\.\d+)?)\s(?P<redis_level>[.*#-])\s`:
		return matchRedisPrefix
	case `^` + rfc3339NanoExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`:
		return matchRFC3339T
	case `^` + rfc3339NanoSpaceExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`:
		return matchRFC3339Space
	}
	return nil
}

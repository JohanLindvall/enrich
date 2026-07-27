package enrich

import "strings"

// Hand-written matchers for the hottest pattern-table entries, and the lazy
// byte-presence memo that dedupes the gate scans. Together they remove most
// regexp executions (and the []int a FindStringSubmatchIndex match allocates)
// from the common plain-text shapes: the profile had the bitState backtracker
// at ~40% of the pattern benchmark, and repeated IndexByte gate scans at ~40%
// of the miss benchmark.

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

// isSpaceRE mirrors regexp's Perl \s class: [\t\n\f\r ] — \v is NOT included.
func isSpaceRE(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isDigitB(c byte) bool { return c-'0' <= 9 }

// stampSkeleton19 reports whether msg starts with the 19-byte digit skeleton
// "dddd<sep>dd<sep>dd dd:dd:dd". It replicates the regex's structural test
// only — value ranges are deliberately not checked, exactly like \d{4} isn't.
func stampSkeleton19(msg string, sep byte) bool {
	if len(msg) < 19 {
		return false
	}
	return msg[4] == sep && msg[7] == sep && msg[10] == ' ' && msg[13] == ':' && msg[16] == ':' &&
		isDigitB(msg[0]) && isDigitB(msg[1]) && isDigitB(msg[2]) && isDigitB(msg[3]) &&
		isDigitB(msg[5]) && isDigitB(msg[6]) && isDigitB(msg[8]) && isDigitB(msg[9]) &&
		isDigitB(msg[11]) && isDigitB(msg[12]) && isDigitB(msg[14]) && isDigitB(msg[15]) &&
		isDigitB(msg[17]) && isDigitB(msg[18])
}

// tailZColonSpace matches the shared "(Z:)?\s" suffix at msg[i:], returning
// whether it matched. Maximal munch is exact here: if "Z:" is present but the
// following byte is not \s, matching without consuming "Z:" would put \s at
// 'Z' and fail too.
func tailZColonSpace(msg string, i int) bool {
	if i+1 < len(msg) && msg[i] == 'Z' && msg[i+1] == ':' {
		i += 2
	}
	return i < len(msg) && isSpaceRE(msg[i])
}

// matchYmdSlashOptFrac decides `^(?P<time>\d{4}/\d{2}/\d{2}
// \d{2}:\d{2}:\d{2}(\.\d+)?)(Z:)?\s` — the generic Go-log shape, the most
// common plain-text entry. Greedy fraction consumption is exact: a shorter
// fraction ends on a digit, which neither 'Z' nor \s accepts.
func matchYmdSlashOptFrac(msg string) (fastSpans, fastVerdict) {
	if !stampSkeleton19(msg, '/') {
		return fastSpans{}, fastNoMatch
	}
	i := 19
	if i+1 < len(msg) && msg[i] == '.' && isDigitB(msg[i+1]) {
		i += 2
		for i < len(msg) && isDigitB(msg[i]) {
			i++
		}
	}
	if !tailZColonSpace(msg, i) {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, i}}, fastMatched
}

// matchMsDashNoFrac decides `^(?P<time>\d{4}-\d{2}-\d{2}
// \d{2}:\d{2}:\d{2})(Z:)?\s` (the fraction-less dash-date entry).
func matchMsDashNoFrac(msg string) (fastSpans, fastVerdict) {
	if !stampSkeleton19(msg, '-') {
		return fastSpans{}, fastNoMatch
	}
	if !tailZColonSpace(msg, 19) {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, 19}}, fastMatched
}

// matchYmdSlash6Frac decides `^(?P<time>\d{4}/\d{2}/\d{2}
// \d{2}:\d{2}:\d{2}\.\d{6})(Z:)?\s` (the mandatory-6-digit-fraction entry).
func matchYmdSlash6Frac(msg string) (fastSpans, fastVerdict) {
	if !stampSkeleton19(msg, '/') || len(msg) < 26 || msg[19] != '.' ||
		!isDigitB(msg[20]) || !isDigitB(msg[21]) || !isDigitB(msg[22]) ||
		!isDigitB(msg[23]) || !isDigitB(msg[24]) || !isDigitB(msg[25]) {
		return fastSpans{}, fastNoMatch
	}
	if !tailZColonSpace(msg, 26) {
		return fastSpans{}, fastNoMatch
	}
	return fastSpans{time: [2]int{0, 26}}, fastMatched
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

// matchRFC3339Level is the shared decider for the two generic RFC3339-ish
// entries `^"?(?P<time>...)"?\s+((?P<level>[a-z]+|[A-Z]+)\s)?`: an optionally
// quoted timestamp, at least one \s, then an optional single-case level word
// itself followed by \s. sep is the date/time separator ('T' or ' ');
// zSuffixOnly restricts the zone to a literal 'Z' (the space-separated
// variant), otherwise 'Z' or "±dd:dd".
//
// Every greedy consumption here is exact under backtracking: a shortened
// fraction ends on a digit (not a zone starter), an unconsumed closing quote
// leaves '"' where \s must be, shortened \s+ leaves a space where the level
// must start, and a shortened level run ends on its own letter class (not
// \s). "Info" matches no level at all: [a-z]+ cannot start it and [A-Z]+
// takes only "I", which 'n' then fails to follow with \s.
func matchRFC3339Level(msg string, sep byte, zSuffixOnly bool) (fastSpans, fastVerdict) {
	off := 0
	if len(msg) > 0 && msg[0] == '"' {
		off = 1
	}
	s := msg[off:]
	if !stampSkeletonSep(s, sep) {
		return fastSpans{}, fastNoMatch
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
		return fastSpans{}, fastNoMatch
	}
	spans := fastSpans{time: [2]int{off, off + i}}

	j := off + i
	if j < len(msg) && msg[j] == '"' {
		j++
	}
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

// stampSkeletonSep is stampSkeleton19 with a parameterized date/time
// separator at index 10 (the dash-date skeleton "dddd-dd-dd<sep>dd:dd:dd").
func stampSkeletonSep(s string, sep byte) bool {
	if len(s) < 19 {
		return false
	}
	return s[4] == '-' && s[7] == '-' && s[10] == sep && s[13] == ':' && s[16] == ':' &&
		isDigitB(s[0]) && isDigitB(s[1]) && isDigitB(s[2]) && isDigitB(s[3]) &&
		isDigitB(s[5]) && isDigitB(s[6]) && isDigitB(s[8]) && isDigitB(s[9]) &&
		isDigitB(s[11]) && isDigitB(s[12]) && isDigitB(s[14]) && isDigitB(s[15]) &&
		isDigitB(s[17]) && isDigitB(s[18])
}

func matchRFC3339T(msg string) (fastSpans, fastVerdict) {
	return matchRFC3339Level(msg, 'T', false)
}

func matchRFC3339Space(msg string) (fastSpans, fastVerdict) {
	return matchRFC3339Level(msg, ' ', true)
}

// fastMatcherFor returns the hand matcher for exactly this pattern string, or
// nil. Keying on the whole pattern means an edited entry silently loses its
// matcher (and the differential test's coverage assertion flags a deleted
// shape), never runs a stale one.
func fastMatcherFor(re string) func(string) (fastSpans, fastVerdict) {
	switch re {
	case `^` + ymdSlashExpr + `(Z:)?\s`:
		return matchYmdSlashOptFrac
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

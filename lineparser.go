package enrich

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"
)

type lineParser struct {
	contain string
	re      string
	ts      []string
}

type compiledLineParser struct {
	// The reject path comes first, so that deciding an entry cannot match
	// touches one cache line: the positional gate, the hand matcher, then the
	// byte prefilters.
	gateMask uint64                                // a line passes the gate when its
	gateWant uint64                                // gate window & gateMask == gateWant
	fast     func(string) (fastSpans, fastVerdict) // hand matcher, or nil

	contain     string
	containByte byte // contain when it is a single byte, for the memo
	rare        byte // rarest byte of contain (0: none); gates the substring scan
	req         byte // a byte every regex match must contain (0: none)
	quoted      bool // pattern allows a leading '"', shifting its gate by one

	re          *regexp.Regexp
	names       []string // re.SubexpNames(), hoisted out of the per-line loop
	ts          []tsLayout
	fastTS      func(string) (time.Time, bool) // family parser for ts, or nil
	fastTSZoned bool                           // every layout fastTS covers carries a zone
}

// passes reports whether the line's gate windows satisfy this entry's
// positional gate: the wrong timestamp family is rejected by one masked word
// compare, before the dispatch loop even calls apply. A gate may only reject
// lines the regex rejects, so testing it first cannot change any verdict; an
// entry with no gates has a zero mask, which every line passes.
func (clp *compiledLineParser) passes(plain, quoted uint64) bool {
	w := plain
	if clp.quoted {
		w = quoted
	}
	return w&clp.gateMask == clp.gateWant
}

// The eight-byte window the positional gates are tested in. Every gate the
// table derives comes from an anchored timestamp prefix and names one of the
// date separators or the date/time separator — bytes 4, 7 and 10 — so a single
// word starting at byte 4 covers them all.
const gateWindowStart, gateWindowLen = 4, 8

// lineGates reads that window of the line twice: plain at its usual offset, and
// quoted one byte later, where a `^"?` pattern's gates shift to when the line
// really does open with a quote (a copy of plain when it does not). Deriving
// them once per line turns every entry's positional gate into one AND and one
// compare, where the posGate slice cost a length test, a bounds check and a
// load per gate. They are two values rather than an array because indexing an
// array by the entry's quoted flag made the compiler copy it to the stack on
// every iteration of the dispatch loop.
func lineGates(message string) (plain, quoted uint64) {
	if len(message) < gateWindowStart+gateWindowLen+1 {
		return lineGatesShort(message)
	}
	plain = le64(message, gateWindowStart)
	// Unless the line really opens with a quote, the `"?` of a quoted pattern
	// matched empty and its gates sit where every other pattern's do.
	quoted = plain
	if message[0] == '"' {
		quoted = le64(message, gateWindowStart+1)
	}
	return plain, quoted
}

// lineGatesShort is lineGates for a line too short to load a whole word from,
// zero-padding what is missing. No gate ever wants a NUL, so a padded position
// can only fail the test — which is the right answer, since a line too short to
// hold a gate's byte is too short to match the pattern that wants it.
func lineGatesShort(message string) (plain, quoted uint64) {
	plain = paddedWord(message, gateWindowStart)
	quoted = plain
	if len(message) > 0 && message[0] == '"' {
		quoted = paddedWord(message, gateWindowStart+1)
	}
	return plain, quoted
}

// paddedWord assembles message[off:off+8] a byte at a time, in the byte order
// le64 reads, leaving the bytes past the end zero.
func paddedWord(message string, off int) (w uint64) {
	for i := off; i < len(message) && i-off < gateWindowLen; i++ {
		w |= uint64(message[i]) << (uint(i-off) * 8)
	}
	return w
}

// compileGates folds the derived posGates into the masked-word form apply
// tests. A gate outside the window would silently stop being enforced, hence
// the panic rather than a quiet fallback.
func compileGates(gates []posGate) (mask, want uint64) {
	for _, g := range gates {
		if g.idx < gateWindowStart || g.idx >= gateWindowStart+gateWindowLen {
			panic(fmt.Sprintf("enrich: positional gate at index %d is outside the gate window [%d,%d)",
				g.idx, gateWindowStart, gateWindowStart+gateWindowLen))
		}
		shift := uint(g.idx-gateWindowStart) * 8
		mask |= uint64(0xff) << shift
		want |= uint64(g.want) << shift
	}
	return mask, want
}

// tsLayout is one timestamp layout plus the fact about it that its string does
// not spell out: whether it carries a zone element (see layoutHasZone), i.e.
// whether a value it parses is an instant or an unanchored wall clock. They
// travel together — as one struct rather than two parallel slices — because
// zonedness is a property of the layout that CLAIMED a value, and the nginx
// entry alone offers one of each. The flag is computed once in init: three
// substring scans per parsed timestamp would be real cost on the RFC3339
// entries, which have no fast family parser.
type tsLayout struct {
	layout string
	zoned  bool
}

// posGate is a fixed-position byte requirement derived from a pattern's
// anchored timestamp prefix: a matching line must carry want at idx. Two of
// these distinguish the timestamp families (slash vs dash date, 'T' vs space
// separator) for a few byte compares, sparing the failing patterns their full
// regex run. want is a single byte — an IndexByte call over a one-byte set
// used to cost more than the comparison it performed.
type posGate struct {
	idx  int
	want byte
}

var ymdSlashLayouts = []string{"2006/01/02 15:04:05.999999999"}
var timeLayoutsKlog = []string{"20060102 15:04:05.000000", "20060102 15:04:05"}
var msSpaceLayouts = []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"}
var msSpaceTSLayouts = []string{"2006-01-02 15:04:05.000 -07:00", "2006-01-02 15:04:05 -07:00"}
var rfc3339NanoSpaceLayout = strings.ReplaceAll(time.RFC3339Nano, "T", " ")

var ymdSlashExpr = `(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?)`
var msSpaceExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|,)\d+)?)"?`
var msSpaceTSExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|,)\d+)? (\+|-)\d{2}:\d{2})"?`
var rfc3339NanoExpr = `"?(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|(\+|-)\d{2}:\d{2}))"?`
var rfc3339NanoSpaceExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?Z)"?`

var lineParsers = []lineParser{
	// logfmt lines (level=.. and/or t/ts/time/timestamp=..) are handled before this
	// table by enrichFromLogFmt, including the level-only case.
	{"", `^` + ymdSlashExpr + `\s\[(?P<level>[a-zA-Z]+)\]`, ymdSlashLayouts},
	// AWS Lambda: ts TAB request-id TAB LEVEL TAB message. Must precede the
	// generic RFC3339 entry, which would otherwise take the timestamp and stop.
	{"\t", `^` + rfc3339NanoExpr + `\t[0-9a-fA-F-]{36}\t(?P<level>[A-Z]+)\t`, []string{time.RFC3339Nano}},
	{"", `^` + rfc3339NanoExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`, []string{time.RFC3339Nano}},
	{"", `^` + rfc3339NanoSpaceExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`, []string{rfc3339NanoSpaceLayout}},
	{"", `^\[` + msSpaceExpr + `\](\[\d+\]\[(?P<level>[a-z]+|[A-Z]+)\]|\s+(?P<level>[a-z]+|[A-Z]+)\b)`, msSpaceLayouts},
	// \s+ before the level: Spring Boot right-pads the level, so its default
	// format carries two spaces ("2026-07-06 12:00:00.123  WARN 1 --- [...]").
	{"", `^` + msSpaceExpr + `\s+\[?(?P<level>[a-z]+|[A-Z]+)(\]|\s)`, msSpaceLayouts}, // too generic
	{"", `^\[(?P<time>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) (?P<level>[A-Z]+) [^\s]+ \d+\s*\]`, []string{"02/01/2006 15:04:05"}},
	{"", `^\[([^\s\]]+\s+)?` + rfc3339NanoExpr + `\s+(?P<level>[A-Z]+)\s+[^\s]+\]`, []string{time.RFC3339Nano}},
	{"", `^\[([^\s\]]+\s+)?` + rfc3339NanoSpaceExpr + `\s+(?P<level>[A-Z]+)\s+[^\s]+\]`, []string{rfc3339NanoSpaceLayout}},
	{" - ", `^[^[\s-]+\s-\s(-|[^\s[]+)\s\[(?P<time>[^]]+)]\s+((?P<response_code>\d+)\s+"[^"]+"|"[^"]+"\s(?P<response_code>\d+)|"(([^\s]+\s)){3}(?P<response_code>\d+))\s`, []string{"02/Jan/2006:15:04:05 -0700", "02/Jan/2006 15:04:05"}}, // nginx
	{"", `^` + msSpaceTSExpr + ` \[[^]]+\]\s(?P<level>[A-Z]+):`, msSpaceTSLayouts},
	{"[", `^(([^\s]+)\s){5}\[` + ymdSlashExpr + `\]\s+(([^\s]+)\s){3}"[^"]+"\s+[^\s]+\s+"[^"]+"\s+(?P<response_code>\d+)`, ymdSlashLayouts},                                        // oauth 2 proxy
	{"", `^(?P<level>[IWEF])((?P<ktime>\d{4} \d{2}:\d{2}:\d{2}(\.|,)\d+)?)\s+\d+\s+[^ :]+:\d+\]`, timeLayoutsKlog},                                                                 // klog
	{"", `^` + ymdSlashExpr + `(Z:)?\s([^\s]+\s){2}\"[^"]+\"\s(?P<response_code>\d+)\s`, ymdSlashLayouts},                                                                          // http echo
	{"", `^\d+:[XCSM]\s(?P<time>\d{1,2}\s[A-Z][a-z]+\s\d{4}\s\d{2}:\d{2}:\d{2}(\.\d+)?)\s(?P<redis_level>[.*#-])\s`, []string{"02 Jan 2006 15:04:05.000", "02 Jan 2006 15:04:05"}}, // redis, https://build47.com/redis-log-format-levels/
	{"[", `^\[` + ymdSlashExpr + `\]\s\[[a-z_.]+:\d+\]\s(?P<level>[a-zA-Z]+):\s`, ymdSlashLayouts},                                                                                 // oauth2 proxy
	{"[", `^\[` + ymdSlashExpr + `\]\s\[\s*(?P<level>[a-zA-Z]+)\]\s\[`, ymdSlashLayouts},                                                                                           // fluent bit

	// Apache httpd error log, 2.4 ([Thu Jun 27 11:55:44.569531 2024] [core:error] [pid 42] ...)
	// and 2.2 ([Wed Oct 11 14:32:52 2000] [error] [client ...] ...)
	{"[", `^\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}(\.\d+)? \d{4})\] \[([a-z_0-9]+:)?(?P<level>[a-zA-Z]+)\]`, []string{"Mon Jan _2 15:04:05.999999 2006", "Mon Jan _2 15:04:05 2006"}},

	// Python logging default format: "asctime - name - LEVEL - message"
	{" - ", `^` + msSpaceExpr + `\s+-\s+[\w.]+\s+-\s+(?P<level>[a-zA-Z]+)\s+-\s`, msSpaceLayouts},

	// Syslog RFC5424: <PRI>VERSION RFC3339-timestamp HOSTNAME APP ...
	{"<", `^<(?P<syslogpri>\d{1,3})>\d\s+(?P<time>\d{4}-\d{2}-\d{2}T[^\s]+)\s`, []string{time.RFC3339Nano}},
	// Syslog RFC3164: <PRI>Mmm dd hh:mm:ss host app[pid]: ... (the year is
	// inferred from the clock, like klog).
	{"<", `^<(?P<syslogpri>\d{1,3})>\s*((?P<stamptime>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s)?`, []string{"2006 Jan _2 15:04:05"}},

	// Entries without timestamp
	{"", `^\[(?P<level>[A-Z]+)\]`, nil},
	{"", `^(?P<level>INFO|WARN|ERROR|DEBUG|TRACE|FATAL):`, nil},
	{"type=", `\btype=(?P<level>[A-Z][a-z]+)\b`, nil},

	// librdkafka
	{"|", `^%(?P<sysloglevel>[0-7])\|(?P<syslogtime>\d+(\.\d+)?)\|`, []string{}},

	// Entries without level
	{"", `^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(Z:)?\s`, []string{"2006-01-02 15:04:05"}},
	{"", `^` + ymdSlashExpr + `(Z:)?\s`, ymdSlashLayouts},
	{"", `^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6})(Z:)?\s`, []string{"2006/01/02 15:04:05.000000"}},

	// Go panic
	{"panic: runtime error: invalid memory address or nil pointer dereference", `(?P<logaserror>.+)`, []string{}},

	// .Net unhandled exception
	{"Unhandled exception. ", `(?s)^Unhandled exception\. (?P<unhandled>[A-ZA-z0-9._]+Exception.*)`, []string{}},

	// Python traceback
	{"Traceback (most recent call last):\n", `(?P<logaserror>.+)`, []string{}},

	// Java exception
	{"\n", `.(?P<logaserror>(Exception|Error|Throwable|V8 errors stack trace)):`, []string{}},
}

var compiledLineParsers []*compiledLineParser

// parsersByFirstByte buckets the table by the line's first byte. Testing each
// parser's `first` set per line meant 32 IndexByte calls just to decide what
// *not* to run — 11% of Parse's time. The bucket for a byte holds, in table
// order, exactly the parsers that byte can start (a parser with no first-byte
// gate, e.g. an unanchored one, appears in every bucket), so dispatch is one
// index and the priority order is preserved.
var parsersByFirstByte [256][]*compiledLineParser

func init() {
	for _, p := range lineParsers {
		quoted, gates := posGates(p.re)
		re := regexp.MustCompile(nonCapturing(p.re))
		req := requiredByte(p.re)
		for _, g := range gates {
			if g.want == req {
				// A passing gate already proves this byte is present; the
				// req scan would re-derive it with a full IndexByte.
				req = 0
				break
			}
		}
		var containByte byte
		if len(p.contain) == 1 {
			containByte = p.contain[0]
		}
		ts := make([]tsLayout, len(p.ts))
		for i, layout := range p.ts {
			ts[i] = tsLayout{layout: layout, zoned: layoutHasZone(layout)}
		}
		gateMask, gateWant := compileGates(gates)
		clp := &compiledLineParser{
			gateMask:    gateMask,
			gateWant:    gateWant,
			fast:        fastMatcherFor(p.re),
			contain:     p.contain,
			containByte: containByte,
			rare:        rareByte(p.contain),
			req:         req,
			quoted:      quoted,
			re:          re,
			names:       re.SubexpNames(),
			ts:          ts,
			fastTS:      fastLayoutTime(p.ts),
			fastTSZoned: allLayoutsHaveZone(p.ts),
		}
		compiledLineParsers = append(compiledLineParsers, clp)
		// The first-byte set is a dispatch input only, so it stays out of the
		// parser and is inverted into the bucket table right here.
		first := firstBytes(p.re)
		for b := 0; b < 256; b++ {
			if first == "" || strings.IndexByte(first, byte(b)) >= 0 {
				parsersByFirstByte[b] = append(parsersByFirstByte[b], clp)
			}
		}
	}
}

// nonCapturing rewrites every unnamed capturing group "(" into a
// non-capturing "(?:". The table uses parentheses mostly for grouping and
// alternation, and only named groups are ever read (via names/loc), so the
// unnamed capture slots are pure overhead: each one widens the []int that
// FindStringSubmatchIndex allocates and adds backtracking bookkeeping.
// Escapes and character classes are skipped so "\(" and "[(]" stay literal.
func nonCapturing(re string) string {
	var b strings.Builder
	b.Grow(len(re) + 16)
	inClass := false
	for i := 0; i < len(re); i++ {
		c := re[i]
		switch {
		case c == '\\' && i+1 < len(re):
			b.WriteByte(c)
			i++
			b.WriteByte(re[i])
			continue
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			// "(?" already carries its own flags (?:, ?P<name>, ?s ...).
			if i+1 < len(re) && re[i+1] == '?' {
				break
			}
			b.WriteString("(?:")
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// posGates derives fixed-position byte requirements from a pattern's anchored
// timestamp prefix. Like firstBytes it recognizes the shapes used in the
// table and returns nothing for the rest; extend it alongside new entries.
// quoted reports a `^"?` prefix, which shifts every gate by one on lines that
// do start with a quote.
func posGates(re string) (quoted bool, gates []posGate) {
	re = strings.TrimPrefix(re, `(?s)`)
	if strings.HasPrefix(re, `^"?`) {
		quoted = true
		re = `^` + re[len(`^"?`):]
	}
	switch {
	case strings.HasPrefix(re, `^(?P<time>\d{4}/\d{2}/\d{2} `):
		return quoted, []posGate{{4, '/'}, {10, ' '}}
	case strings.HasPrefix(re, `^(?P<time>\d{4}-\d{2}-\d{2}T`):
		return quoted, []posGate{{4, '-'}, {10, 'T'}}
	case strings.HasPrefix(re, `^(?P<time>\d{4}-\d{2}-\d{2} `):
		return quoted, []posGate{{4, '-'}, {10, ' '}}
	}
	return false, nil
}

// byteScore ranks how unlikely a byte is in log text (lower = rarer): control
// chars, then punctuation, then digits, then letters. Both gate derivations
// pick their cheapest-to-test byte with it.
func byteScore(c byte) int {
	switch {
	case c < 0x20 || c == 0x7f: // control (\t, \n)
		return 0
	case c == '|' || c == '=' || c == '<' || c == '>' || c == '%':
		return 1
	case strings.IndexByte("()[]{}#$&*+^~\"'`@\\", c) >= 0:
		return 2
	case c == ':' || c == ';' || c == '_' || c == '-' || c == '/':
		return 3
	case c >= '0' && c <= '9':
		return 4
	case c >= 'A' && c <= 'Z':
		return 5
	default: // lowercase, space, '.', ','
		return 6
	}
}

// rareByte picks the byte of a multi-byte contain needle least likely to occur
// in log text, so apply can reject most lines with one SIMD byte scan instead
// of a substring search. A needle containing its rare byte is implied by the
// needle being present, so the gate never changes the outcome. Returns 0 (no
// gate) for needles of one byte, where Contains is already a single byte scan.
func rareByte(contain string) byte {
	if len(contain) < 2 {
		return 0
	}
	rare := contain[0]
	for i := 1; i < len(contain); i++ {
		if byteScore(contain[i]) < byteScore(rare) {
			rare = contain[i]
		}
	}
	return rare
}

// requiredByte returns the rarest ASCII byte that every match of the pattern
// must contain, or 0 when none can be proven. It walks the parsed syntax tree
// collecting literal bytes in mandatory positions — concatenations, captures
// and min>=1 repeats; alternations and optional groups prove nothing. The
// payoff is on patterns that fail late (e.g. a timestamp matches but a later
// literal is absent): one byte scan replaces the whole backtracking run.
func requiredByte(pattern string) byte {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0
	}
	var req []byte
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			if r.Flags&syntax.FoldCase != 0 {
				return // case-folded literals match multiple bytes
			}
			for _, ru := range r.Rune {
				if ru < 128 {
					req = append(req, byte(ru))
				}
			}
		case syntax.OpConcat, syntax.OpCapture, syntax.OpPlus:
			for _, sub := range r.Sub {
				walk(sub)
			}
		case syntax.OpRepeat:
			if r.Min >= 1 {
				for _, sub := range r.Sub {
					walk(sub)
				}
			}
		}
	}
	walk(parsed)
	if len(req) == 0 {
		return 0
	}
	rare := req[0]
	for _, c := range req[1:] {
		if byteScore(c) < byteScore(rare) {
			rare = c
		}
	}
	return rare
}

// firstBytes derives, from the anchored prefix of a pattern, the set of bytes
// a line must start with for the pattern to possibly match. This lets apply
// skip most of the table with a single byte comparison per parser. It returns
// "" (no cheap test) for prefixes it does not recognize; when adding a table
// entry with a new anchored shape, extend this classifier.
func firstBytes(re string) string {
	re = strings.TrimPrefix(re, `(?s)`) // flags don't change the first byte
	switch {
	case strings.HasPrefix(re, `^"?(?P<time>\d{4}`): // quoted or bare timestamp
		return `"0123456789`
	case strings.HasPrefix(re, `^(?P<time>\d`), strings.HasPrefix(re, `^\d`):
		return "0123456789"
	case strings.HasPrefix(re, `^\[`):
		return "["
	case strings.HasPrefix(re, `^<`):
		return "<"
	case strings.HasPrefix(re, `^%`):
		return "%"
	case strings.HasPrefix(re, `^(?P<level>[IWEF])`): // klog
		return "IWEF"
	case strings.HasPrefix(re, `^(?P<level>INFO|WARN|ERROR|DEBUG|TRACE|FATAL):`):
		return "IWEDTF"
	case strings.HasPrefix(re, `^Unhandled`):
		return "U"
	}
	return ""
}

// apply matches the parser against message and, on a match, fills result from
// the named submatches. It reports whether the parser matched; the caller has
// already cleared the positional gate (see passes). memo dedupes whole-line
// byte scans across entries (and the traceparent gate).
func (clp *compiledLineParser) apply(result *Result, message string, memo *byteMemo) bool {
	if clp.fast != nil {
		switch spans, v := clp.fast(message); v {
		case fastNoMatch:
			return false
		case fastMatched:
			// The matcher proves the regex outcome for these entries: apply
			// the captures in group order (time before level, as the regexes
			// declare them) and skip contain, req and the regex itself.
			if spans.time[1] > spans.time[0] {
				clp.applySubmatch(result, "time", message[spans.time[0]:spans.time[1]])
			}
			if spans.level[1] > spans.level[0] {
				clp.applySubmatch(result, "level", message[spans.level[0]:spans.level[1]])
			}
			return true
		}
	}
	if clp.containByte != 0 {
		if !memo.has(message, clp.containByte) {
			return false
		}
	} else if clp.contain != "" {
		if clp.rare != 0 && !memo.has(message, clp.rare) {
			return false
		}
		if !strings.Contains(message, clp.contain) {
			return false
		}
	}

	if clp.req != 0 && !memo.has(message, clp.req) {
		return false
	}

	// The index form allocates one []int instead of a []string plus a string
	// header per group; every captured value is a slice of message, so it
	// aliases the input like the rest of the result.
	loc := clp.re.FindStringSubmatchIndex(message)
	if loc == nil {
		return false
	}

	for i, name := range clp.names {
		if name == "" {
			continue
		}
		start, end := loc[2*i], loc[2*i+1]
		if start < 0 || start == end {
			continue // group did not participate, or matched empty
		}
		clp.applySubmatch(result, name, message[start:end])
	}
	return true
}

// applySubmatch fills the result field selected by the submatch name.
func (clp *compiledLineParser) applySubmatch(result *Result, name, value string) {
	switch name {
	case "level":
		result.Severity = value
	case "syslogtime":
		if ts, ok := parseSyslogTime(value); ok {
			// An epoch names an instant outright: there is no wall clock and
			// no zone to be missing, so it is reported as zoned.
			result.setTime(ts, true)
		}
	case "time", "ktime", "stamptime":
		if len(clp.ts) == 0 {
			return
		}
		switch name {
		case "ktime":
			// The direct parse skips expandKlogTime's year-prefix allocation
			// and the layout loop; unclaimed shapes take the old path below.
			// klog writes a bare local wall clock, hence never a zone.
			if ts, ok := parseKlogTime(value, time.Now().UTC()); ok {
				result.setTime(ts, false)
				return
			}
			value = expandKlogTime(value, time.Now().UTC())
		case "stamptime":
			// As for klog: parse directly, fall back to the year-prefix path
			// for unclaimed shapes. RFC3164 carries no zone either.
			if ts, ok := parseStampTime(value, time.Now().UTC()); ok {
				result.setTime(ts, false)
				return
			}
			value = expandStampTime(value, time.Now().UTC())
		}
		// A layout that does not parse simply leaves Time zero; the caller
		// sees that (and Result.Format) rather than the package writing to a
		// global logger.
		if ts, zoned, ok := clp.parseLayoutTime(value); ok {
			result.setTime(ts, zoned)
		}
	case "response_code":
		// An access log observes the code rather than reporting a failure, so
		// a 4xx grades to warn; the code itself is kept either way.
		if code, err := strconv.ParseInt(value, 10, 64); err == nil {
			setHTTPResponseCode(result, code, StatusObserved)
		}
	case "sysloglevel":
		result.Severity, result.SeverityNumber = syslogSeverity(int(value[0] - '0'))
	case "syslogpri":
		// <PRI> encodes facility*8+severity; values above 191 are invalid.
		if pri, err := strconv.Atoi(value); err == nil && pri < 192 {
			result.Severity, result.SeverityNumber = syslogSeverity(pri & 7)
		}
	case "redis_level":
		result.Severity = redisSeverity(value)
	case "logaserror", "unhandled":
		if result.Severity == "" {
			result.Severity = ErrorLevel
		}
		if name == "unhandled" {
			result.parseException(value)
		}
	}
}

// parseLayoutTime tries the parser's layouts in order and returns the first
// successfully parsed timestamp, in UTC, along with whether the layout that
// claimed it carries a zone (see layoutHasZone). The hand-rolled family
// parser, when one covers this layout list, decides the canonical shapes
// without re-tokenizing a layout; a shape it does not claim falls through to
// the loop, so the fast path can only ever change speed, not outcome
// (timeparse_test.go holds it to that, zonedness included).
func (clp *compiledLineParser) parseLayoutTime(ts string) (time.Time, bool, bool) {
	if clp.fastTS != nil {
		if t, ok := clp.fastTS(ts); ok {
			return t, clp.fastTSZoned, true
		}
	}
	for _, l := range clp.ts {
		// Skip a layout that cannot match: only RFC3339Nano carries a
		// 'T' date/time separator at index 10, so a 'T'-vs-space
		// disagreement there means time.Parse would fail (and allocate
		// a parse error) for nothing.
		if len(ts) > 10 && len(l.layout) > 10 && (l.layout[10] == 'T') != (ts[10] == 'T') {
			continue
		}
		if t, err := time.Parse(l.layout, ts); err == nil {
			return t.UTC(), l.zoned, true
		}
	}
	return time.Time{}, false, false
}

// expandKlogTime prefixes a year onto a klog "MMDD hh:mm:ss..." timestamp,
// adjusting across a year boundary when the month disagrees with the clock.
func expandKlogTime(ts string, now time.Time) string {
	year := now.Year()
	month := now.Month()
	if month == 1 && ts[:2] == "12" {
		year-- // date probably refers to previous year
	} else if month == 12 && ts[:2] == "01" {
		year++ // date probably refers to next year
	}
	return strconv.Itoa(year) + ts
}

// expandStampTime prefixes a year onto an RFC3164 "Mmm dd hh:mm:ss" syslog
// timestamp, adjusting across a year boundary when the month disagrees with
// the clock.
func expandStampTime(ts string, now time.Time) string {
	year := now.Year()
	if m, err := time.Parse("Jan", ts[:3]); err == nil {
		if now.Month() == time.January && m.Month() == time.December {
			year-- // date probably refers to previous year
		} else if now.Month() == time.December && m.Month() == time.January {
			year++ // date probably refers to next year
		}
	}
	return strconv.Itoa(year) + " " + ts
}

func parseSyslogTime(t string) (time.Time, bool) {
	if tsFloat, err := strconv.ParseFloat(t, 64); err == nil {
		secs := int64(tsFloat)
		nanos := int64((tsFloat - float64(secs)) * 1e9)
		return time.Unix(secs, nanos).UTC(), true
	}

	return time.Time{}, false
}

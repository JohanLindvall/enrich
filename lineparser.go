package enrich

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type lineParser struct {
	contain string
	re      string
	ts      []string
}

type compiledLineParser struct {
	contain string
	first   string // bytes the line must start with; empty means no cheap test
	rare    byte   // rarest byte of contain (0: none); gates the substring scan
	re      *regexp.Regexp
	ts      []string
	lastWrn atomic.Int64 // unix nanos of the last parse-failure warning
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

func init() {
	for _, p := range lineParsers {
		compiledLineParsers = append(compiledLineParsers, &compiledLineParser{
			contain: p.contain,
			first:   firstBytes(p.re),
			rare:    rareByte(p.contain),
			re:      regexp.MustCompile(p.re),
			ts:      p.ts,
		})
	}
}

// rareByte picks the byte of a multi-byte contain needle least likely to occur
// in log text (control chars, then punctuation, then digits, then letters), so
// apply can reject most lines with one SIMD byte scan instead of a substring
// search. A needle containing its rare byte is implied by the needle being
// present, so the gate never changes the outcome. Returns 0 (no gate) for
// needles of one byte, where Contains is already a single byte scan.
func rareByte(contain string) byte {
	if len(contain) < 2 {
		return 0
	}
	score := func(c byte) int {
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
	rare := contain[0]
	for i := 1; i < len(contain); i++ {
		if score(contain[i]) < score(rare) {
			rare = contain[i]
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

// warnParseFailure logs a failed timestamp parse for this parser, rate-limited
// to one warning per ten minutes. The stamp is a lock-free atomic so parsers
// shared by concurrent pipelines never serialize on it.
func (clp *compiledLineParser) warnParseFailure(msg string) {
	now := time.Now().UnixNano()
	last := clp.lastWrn.Load()
	if now-last > (10*time.Minute).Nanoseconds() && clp.lastWrn.CompareAndSwap(last, now) {
		slog.Warn("Failed to parse time", "regexp", clp.re.String(), "line", msg)
	}
}

// apply matches the parser against message and, on a match, fills result from
// the named submatches. It reports whether the parser matched.
func (clp *compiledLineParser) apply(result *Result, message string) bool {
	if clp.first != "" && (message == "" || strings.IndexByte(clp.first, message[0]) < 0) {
		return false
	}
	if clp.contain != "" {
		if clp.rare != 0 && strings.IndexByte(message, clp.rare) < 0 {
			return false
		}
		if !strings.Contains(message, clp.contain) {
			return false
		}
	}

	match := clp.re.FindStringSubmatch(message)
	if match == nil {
		return false
	}

	for i, name := range clp.re.SubexpNames() {
		if match[i] == "" || name == "" {
			continue
		}
		clp.applySubmatch(result, name, match[i], message)
	}
	return true
}

// applySubmatch fills the result field selected by the submatch name.
func (clp *compiledLineParser) applySubmatch(result *Result, name, value, message string) {
	switch name {
	case "level":
		result.Severity = value
	case "syslogtime":
		if ts, ok := parseSyslogTime(value); ok {
			result.Time = ts
		}
	case "time", "ktime", "stamptime":
		if len(clp.ts) == 0 {
			return
		}
		switch name {
		case "ktime":
			value = expandKlogTime(value, time.Now().UTC())
		case "stamptime":
			value = expandStampTime(value, time.Now().UTC())
		}
		if ts, ok := clp.parseLayoutTime(value); ok {
			result.Time = ts
		} else {
			clp.warnParseFailure(message)
		}
	case "response_code":
		if httpSev := parseHTTPResponseSeverity(value, false); httpSev != "" {
			result.Severity = httpSev
		}
	case "sysloglevel":
		result.Severity, result.SeverityNumber = syslogSeverity(int(value[0] - '0'))
	case "syslogpri":
		// <PRI> encodes facility*8+severity; values above 191 are invalid.
		if pri, err := strconv.Atoi(value); err == nil && pri < 192 {
			result.Severity, result.SeverityNumber = syslogSeverity(pri & 7)
		}
	case "redis_level":
		result.Severity = getRedisSeverityText(value)
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
// successfully parsed timestamp, in UTC.
func (clp *compiledLineParser) parseLayoutTime(ts string) (time.Time, bool) {
	for _, layout := range clp.ts {
		// Skip a layout that cannot match: only RFC3339Nano carries a
		// 'T' date/time separator at index 10, so a 'T'-vs-space
		// disagreement there means time.Parse would fail (and allocate
		// a parse error) for nothing.
		if len(ts) > 10 && len(layout) > 10 && (layout[10] == 'T') != (ts[10] == 'T') {
			continue
		}
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
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

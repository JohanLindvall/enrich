package enrich

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type lineParser struct {
	contain string
	re      string
	ts      []string
}

type compiledLineParser struct {
	contain string
	re      *regexp.Regexp
	ts      []string
	mtx     sync.Mutex
	lastWrn time.Time
	index   int
}

var ymdSlashLayouts = []string{"2006/01/02 15:04:05.999999999"}
var timeLayoutsKlog = []string{"20060102 15:04:05.000000", "20060102 15:04:05"}
var msSpaceLayouts = []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"}
var msSpaceTSLayouts = []string{"2006-01-02 15:04:05.000 -07:00", "2006-01-02 15:04:05 -07:00"}
var rfc3339NanoSpaceLayout = strings.ReplaceAll(time.RFC3339Nano, "T", " ")

var ymdSlashExpr = `(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?)`
var msSpaceExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|,)\d+)?)"?`
var msSpaceTSExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|,)\d+)? (\+|-)\d{2}:\d{2})"?`
var rfc3339NanoExpr = `"?(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z)"?`
var rfc3339NanoSpaceExpr = `"?(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?Z)"?`

var lineParsers = []lineParser{
	// logfmt lines (level=.. and/or t/ts/time/timestamp=..) are handled before this
	// table by parseLogFmt, including the level-only case.
	{"", `^` + ymdSlashExpr + `\s\[(?P<level>[a-zA-Z]+)\]`, ymdSlashLayouts},
	{"", `^` + rfc3339NanoExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`, []string{time.RFC3339Nano}},
	{"", `^` + rfc3339NanoSpaceExpr + `\s+((?P<level>[a-z]+|[A-Z]+)\s)?`, []string{rfc3339NanoSpaceLayout}},
	{"", `^\[` + msSpaceExpr + `\](\[\d+\]\[(?P<level>[a-z]+|[A-Z]+)\]|\s+(?P<level>[a-z]+|[A-Z]+)\b)`, msSpaceLayouts},
	{"", `^` + msSpaceExpr + ` \[?(?P<level>[a-z]+|[A-Z]+)(\]|\s)`, msSpaceLayouts}, // too generic
	{"", `^\[(?P<time>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) (?P<level>[A-Z]+) [^\s]+ \d+\s*\]`, []string{"02/01/2006 15:04:05"}},
	{"", `^\[([^\s\]]+\s+)?` + rfc3339NanoExpr + `\s+(?P<level>[A-Z]+)\s+[^\s]+\]`, []string{time.RFC3339Nano}},
	{"", `^\[([^\s\]]+\s+)?` + rfc3339NanoSpaceExpr + `\s+(?P<level>[A-Z]+)\s+[^\s]+\]`, []string{rfc3339NanoSpaceLayout}},
	{"", `^[^[\s-]+\s-\s(-|[^\s[]+)\s\[(?P<time>[^]]+)]\s+((?P<response_code>\d+)\s+"[^"]+"|"[^"]+"\s(?P<response_code>\d+)|"(([^\s]+\s)){3}(?P<response_code>\d+))\s`, []string{"02/Jan/2006:15:04:05 -0700", "02/Jan/2006 15:04:05"}}, // nginx
	{"", `^` + msSpaceTSExpr + ` \[[^]]+\]\s(?P<level>[A-Z]+):`, msSpaceTSLayouts},
	{"", `^(([^\s]+)\s){5}\[` + ymdSlashExpr + `\]\s+(([^\s]+)\s){3}"[^"]+"\s+[^\s]+\s+"[^"]+"\s+(?P<response_code>\d+)`, ymdSlashLayouts},                                        // oauth 2 proxy
	{"", `^(?P<level>[IWEF])((?P<ktime>\d{4} \d{2}:\d{2}:\d{2}(\.|,)\d+)?)\s+\d+\s+[^ :]+:\d+\]`, timeLayoutsKlog},                                                                // klog
	{"", `^` + ymdSlashExpr + `(Z:)?\s([^\s]+\s){2}\"[^"]+\"\s(?P<response_code>\d+)\s`, ymdSlashLayouts},                                                                         // http echo
	{"", `\d+:[XCSM]\s(?P<time>\d{1,2}\s[A-Z][a-z]+\s\d{4}\s\d{2}:\d{2}:\d{2}(\.\d+)?)\s(?P<redis_level>[.*#-])\s`, []string{"02 Jan 2006 15:04:05.000", "02 Jan 2006 15:04:05"}}, // redis, https://build47.com/redis-log-format-levels/
	{"[", `^\[` + ymdSlashExpr + `\]\s\[[a-z_.]+:\d+\]\s(?P<level>[a-zA-Z]+):\s`, ymdSlashLayouts},                                                                                // oauth2 proxy
	{"[", `^\[` + ymdSlashExpr + `\]\s\[\s*(?P<level>[a-zA-Z]+)\]\s\[`, ymdSlashLayouts},                                                                                          // fluent bit

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
	for i, p := range lineParsers {
		compiledLineParsers = append(compiledLineParsers, &compiledLineParser{p.contain, regexp.MustCompile(p.re), p.ts, sync.Mutex{}, time.Time{}, i})
	}
}

// warnParseFailure logs a failed timestamp parse for this parser, rate-limited
// to one warning per ten minutes.
func (clp *compiledLineParser) warnParseFailure(msg string) {
	now := time.Now()
	clp.mtx.Lock()
	warn := false
	if now.Sub(clp.lastWrn) > 10*time.Minute {
		clp.lastWrn = now
		warn = true
	}
	clp.mtx.Unlock()
	if warn {
		slog.Warn("Failed to parse time", "regexp", clp.re.String(), "line", msg)
	}
}

// apply matches the parser against message and, on a match, fills result from
// the named submatches. It reports whether the parser matched.
func (clp *compiledLineParser) apply(result *Result, message string) bool {
	if clp.contain != "" && !strings.Contains(message, clp.contain) {
		return false
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
	case "time", "ktime":
		if len(clp.ts) == 0 {
			return
		}
		if name == "ktime" {
			value = expandKlogTime(value, time.Now().UTC())
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
		result.Severity = getSyslogSeverityText(value)
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

func parseSyslogTime(t string) (time.Time, bool) {
	if tsFloat, err := strconv.ParseFloat(t, 64); err == nil {
		secs := int64(tsFloat)
		nanos := int64((tsFloat - float64(secs)) * 1e9)
		return time.Unix(secs, nanos).UTC(), true
	}

	return time.Time{}, false
}

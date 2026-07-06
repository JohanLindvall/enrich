package enrich

import (
	"regexp"
	"strconv"
)

// The normalized severity levels and their numeric equivalents. The numbers
// follow the OpenTelemetry log SeverityNumber convention, where each level
// starts a range of four (trace=1, debug=5, info=9, warn=13, error=17,
// fatal=21); SeverityText maps any number in a range back to its level.
const (
	TraceLevel   = "trace"
	DebugLevel   = "debug"
	InfoLevel    = "info"
	WarnLevel    = "warn"
	ErrorLevel   = "error"
	FatalLevel   = "fatal"
	TraceLevelNo = 1
	DebugLevelNo = 5
	InfoLevelNo  = 9
	WarnLevelNo  = 13
	ErrorLevelNo = 17
	FatalLevelNo = 21
)

var normalizeReg = []struct {
	regexp  *regexp.Regexp
	replace string
	number  int
}{
	{regexp.MustCompile(`^(?i)(trace?|trc)\d*$`), TraceLevel, TraceLevelNo},
	{regexp.MustCompile(`^(?i)(d|debug?|dbg)\d*$`), DebugLevel, DebugLevelNo},
	{regexp.MustCompile(`^(?i)(i(nfo?(rmation(al)?)?)?)$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)normal$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)log$`), InfoLevel, InfoLevelNo},
	{regexp.MustCompile(`^(?i)(w(a?rn(ing)?)?)$`), WarnLevel, WarnLevelNo},
	{regexp.MustCompile(`^(?i)(e(rr(or)?)?)$`), ErrorLevel, ErrorLevelNo},
	{regexp.MustCompile(`^(?i)(fatal|f(tl)?|crit(ical)?|panic|pnc)$`), FatalLevel, FatalLevelNo},
}

// NormalizeSeverity normalizes log severity to a set of predefined values
func NormalizeSeverity(input string) (string, int) {
	if input != "" {
		for _, reg := range normalizeReg {
			if reg.regexp.MatchString(input) {
				return reg.replace, reg.number
			}
		}
	}

	return "", 0
}

// SeverityText Gets the severity text for a given severity number
func SeverityText(severity int) string {
	if severity < 1 {
		return ""
	}
	if severity < 5 {
		return TraceLevel
	}
	if severity < 9 {
		return DebugLevel
	}
	if severity < 13 {
		return InfoLevel
	}
	if severity < 17 {
		return WarnLevel
	}
	if severity < 21 {
		return ErrorLevel
	}
	if severity < 25 {
		return FatalLevel
	}

	return ""
}

func getSyslogSeverityText(severity string) string {
	switch severity {
	case "0", "1", "2":
		return FatalLevel
	case "3":
		return ErrorLevel
	case "4":
		return WarnLevel
	case "5", "6":
		return InfoLevel
	case "7":
		return DebugLevel
	}
	return ""
}

func getRedisSeverityText(severity string) string {
	switch severity {
	case ".": // debug
		return DebugLevel
	case "-": // verbose
		return DebugLevel
	case "*":
		return InfoLevel
	case "#":
		return WarnLevel
	}
	return ""
}

func parseHTTPResponseSeverity(value string, fail bool) string {
	if code, err := strconv.ParseInt(value, 10, 64); err == nil && code >= 0 && code <= 599 {
		return HTTPStatusSeverity(code, fail)
	}

	return ""
}

// HTTPStatusSeverity parses severity from the HTTP response code.
func HTTPStatusSeverity(code int64, fail bool) string {
	if code >= 0 && code <= 599 {
		if code == 0 {
			return ErrorLevel
		}

		if fail && code >= 400 && code < 500 {
			return ErrorLevel
		}

		if code >= 100 && code < 400 {
			return InfoLevel
		}

		return WarnLevel
	}

	return ""
}

func setHTTPResponseCode(result *Result, code int64, fail bool) {
	if fail || result.Severity == "" || result.Severity == "info" {
		if httpSev := HTTPStatusSeverity(code, fail); httpSev != "" {
			result.Severity = httpSev
		}
	}
}

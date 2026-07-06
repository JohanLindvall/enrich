package enrich

import (
	"regexp"
	"strconv"
)

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

// GetSeverityText Gets the severity text for a given severity number
func GetSeverityText(severity int) string {
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
		return ParseHTTPResponseSeverity(code, fail)
	}

	return ""
}

// ParseHTTPResponseSeverity parses severity from the HTTP response code.
func ParseHTTPResponseSeverity(code int64, fail bool) string {
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

func setHTTPResponseCode(result *Enriched, code int64, fail bool) {
	if fail || result.Severity == "" || result.Severity == "info" {
		if httpSev := ParseHTTPResponseSeverity(code, fail); httpSev != "" {
			result.Severity = httpSev
		}
	}
}

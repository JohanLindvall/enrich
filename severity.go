package enrich

import (
	"strconv"
	"strings"
)

// The six normalized severity levels. Parse reports one of these in
// Result.Severity, and they are the only values SeverityFromText returns.
const (
	TraceLevel = "trace"
	DebugLevel = "debug"
	InfoLevel  = "info"
	WarnLevel  = "warn"
	ErrorLevel = "error"
	FatalLevel = "fatal"
)

// The OpenTelemetry log SeverityNumber values, reported in
// Result.SeverityNumber. Each level owns a range of four, so a producer can
// grade within a level: syslog's "notice", for instance, is an info that
// outranks a plain one, and is reported as Info2LevelNo. SeverityFromNumber
// maps any number in a range back to that range's level.
const (
	TraceLevelNo = iota + 1 // 1
	Trace2LevelNo
	Trace3LevelNo
	Trace4LevelNo
	DebugLevelNo // 5
	Debug2LevelNo
	Debug3LevelNo
	Debug4LevelNo
	InfoLevelNo // 9
	Info2LevelNo
	Info3LevelNo
	Info4LevelNo
	WarnLevelNo // 13
	Warn2LevelNo
	Warn3LevelNo
	Warn4LevelNo
	ErrorLevelNo // 17
	Error2LevelNo
	Error3LevelNo
	Error4LevelNo
	FatalLevelNo // 21
	Fatal2LevelNo
	Fatal3LevelNo
	Fatal4LevelNo
)

// severityLUT enumerates every spelling a level can have, keyed lowercase
// (the recognized spellings are ASCII, so folding is a plain case flip).
//
// It is the whole implementation, not a cache in front of one: the set of
// level spellings is finite, so a lookup table decides every input in O(1) —
// including the ones that name no level, which a regex walk used to spend
// ~330 ns rejecting. severity_test.go keeps the original regexes as an oracle
// and differential-tests this table against them.
//
// The odd-looking "infrmation"/"wrning" entries are not typos: the original
// patterns (i(nfo?(rmation(al)?)?)? and w(a?rn(ing)?)?) accept them, and this
// table reproduces that language exactly.
var severityLUT = map[string]struct {
	text string
	no   int
}{}

const maxSeverityKey = len("informational")

func init() {
	add := func(text string, no int, forms ...string) {
		for _, f := range forms {
			severityLUT[f] = struct {
				text string
				no   int
			}{text, no}
		}
	}
	add(TraceLevel, TraceLevelNo, "trac", "trace", "trc")
	add(DebugLevel, DebugLevelNo, "d", "debu", "debug", "dbg")
	add(InfoLevel, InfoLevelNo, "i", "inf", "info", "infrmation", "infrmational",
		"information", "informational", "normal", "log")
	add(WarnLevel, WarnLevelNo, "w", "wrn", "warn", "wrning", "warning")
	add(ErrorLevel, ErrorLevelNo, "e", "err", "error")
	add(FatalLevel, FatalLevelNo, "fatal", "f", "ftl", "crit", "critical", "panic", "pnc")
}

// severityInitials are the first letters of every entry in severityLUT. A
// single byte test rejects the overwhelming majority of non-levels (any word
// the pattern table happened to capture as a level) before hashing anything.
const severityInitials = "tdinlwefcp"

// lookupSeverity does the case-insensitive LUT lookup without allocating: the
// lowercased key is built on the stack.
func lookupSeverity(s string) (string, int, bool) {
	if len(s) == 0 || len(s) > maxSeverityKey {
		return "", 0, false
	}
	var buf [maxSeverityKey]byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	v, ok := severityLUT[string(buf[:len(s)])]
	return v.text, v.no, ok
}

// SeverityFromText normalizes any of the level spellings that appear in the
// wild ("WRN", "Warning", "w", "Information", ...) to one of the canonical
// levels and its OpenTelemetry severity number. It returns "", 0 for a string
// that names no level. It is the inverse of SeverityFromNumber.
func SeverityFromText(input string) (string, int) {
	if input == "" {
		return "", 0
	}
	// No level begins with any other letter, so one byte test rejects most
	// non-levels outright. (|0x20 lowercases ASCII letters; every other byte,
	// including the lead byte of a multi-byte rune, maps outside the set.)
	if strings.IndexByte(severityInitials, input[0]|0x20) < 0 {
		return "", 0
	}

	if text, no, ok := lookupSeverity(input); ok {
		return text, no
	}

	// Only the trace and debug spellings take a numeric suffix ("trace2",
	// MongoDB's "D1".."D5"); an "info2" is deliberately not info.
	if trimmed := strings.TrimRight(input, "0123456789"); len(trimmed) < len(input) {
		if text, no, ok := lookupSeverity(trimmed); ok && (text == TraceLevel || text == DebugLevel) {
			return text, no
		}
	}
	return "", 0
}

// SeverityFromNumber maps an OpenTelemetry severity number to its canonical
// level, so any number within a level's range of four resolves to that level
// (e.g. both 9 and the syslog-notice 10 are info). It returns "" for a number
// outside 1-24. It is the inverse of SeverityFromText.
func SeverityFromNumber(severity int) string {
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

// syslogSeverity maps a syslog severity (0-7, the low three bits of the
// priority) to a normalized level and OTLP severity number. Notice (5) maps
// to info with the finer-grained INFO2 number.
func syslogSeverity(level int) (string, int) {
	switch level {
	case 0, 1, 2: // emergency, alert, critical
		return FatalLevel, FatalLevelNo
	case 3:
		return ErrorLevel, ErrorLevelNo
	case 4:
		return WarnLevel, WarnLevelNo
	case 5: // notice
		return InfoLevel, Info2LevelNo
	case 6:
		return InfoLevel, InfoLevelNo
	case 7:
		return DebugLevel, DebugLevelNo
	}
	return "", 0
}

// pinoSeverity maps the numeric levels of Pino/Bunyan (Node.js loggers) to
// severities: 10=trace, 20=debug, 30=info, 40=warn, 50=error, 60=fatal.
// The lax JSON decoder skips the numeric "level" value (the same key commonly
// carries a string), so the number is fished out of the raw line when no
// textual severity was found. An escaped quote cannot produce a false match:
// the bytes of \"level\": contain a backslash before the colon.
func pinoSeverity(message string) string {
	const key = `"level":`
	i := strings.Index(message, key)
	if i < 0 {
		return ""
	}
	rest := message[i+len(key):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 || j > 2 {
		return ""
	}
	n, _ := strconv.Atoi(rest[:j])
	switch n / 10 {
	case 1:
		return TraceLevel
	case 2:
		return DebugLevel
	case 3:
		return InfoLevel
	case 4:
		return WarnLevel
	case 5:
		return ErrorLevel
	case 6:
		return FatalLevel
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

func parseHTTPResponseSeverity(value string, kind StatusKind) string {
	if code, err := strconv.ParseInt(value, 10, 64); err == nil && code >= 0 && code <= 599 {
		return HTTPStatusSeverity(code, kind)
	}

	return ""
}

// StatusKind says how a line reports an HTTP status code, which decides how a
// 4xx is graded: an access log merely observes the code (the client asked for
// something that was not there — a warning), whereas a line whose subject is a
// failed call reports it as the failure itself (an error).
type StatusKind int

const (
	// StatusObserved is an access-log style status: 4xx grades to warn.
	StatusObserved StatusKind = iota
	// StatusFailure is a status reported as the failure of the operation the
	// line is about: 4xx grades to error.
	StatusFailure
)

// HTTPStatusSeverity grades an HTTP response code into a severity: 1xx-3xx is
// info, 5xx (and a 0, meaning no response at all) is an error-ish warn, and
// 4xx depends on kind (see StatusKind). It returns "" for a code outside
// 0-599.
func HTTPStatusSeverity(code int64, kind StatusKind) string {
	if code >= 0 && code <= 599 {
		if code == 0 {
			return ErrorLevel
		}

		if kind == StatusFailure && code >= 400 && code < 500 {
			return ErrorLevel
		}

		if code >= 100 && code < 400 {
			return InfoLevel
		}

		return WarnLevel
	}

	return ""
}

func setHTTPResponseCode(result *Result, code int64, kind StatusKind) {
	if kind == StatusFailure || result.Severity == "" || result.Severity == "info" {
		if httpSev := HTTPStatusSeverity(code, kind); httpSev != "" {
			result.Severity = httpSev
		}
	}
}

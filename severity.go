package enrich

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
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

// sevTable is severityLUT rebuilt as a perfect-hash array: sevHash is injective
// over the LUT's keys (init verifies that and panics with replacement constants
// if a new spelling ever collides), so a lookup is one multiply-mix, one slot
// load and one string compare — no map hashing. On the Azure benchmark the
// map's aeshash+access was ~8% of the whole parse; this is the same lookup for
// a fraction of that. The map stays as the authoritative registry (init and the
// severity tests iterate it); only the lookup bypasses it.
type sevSlot struct {
	key  string
	text string
	no   int
}

const (
	sevHashLen   = 3
	sevHashFirst = 43
	sevHashLast  = 5
	sevTableSize = 128 // power of two; 42 keys leave plenty of slack
)

var sevTable [sevTableSize]sevSlot

// sevHash mixes the three bytes that distinguish every LUT key: length, first
// and last byte. s must be non-empty and lowercased.
func sevHash(s string) uint32 {
	return (uint32(len(s))*sevHashLen + uint32(s[0])*sevHashFirst + uint32(s[len(s)-1])*sevHashLast) % sevTableSize
}

// buildSevTable fills sevTable from severityLUT, panicking on a hash collision.
// The panic message includes freshly searched constants that do work, so a
// maintainer adding a colliding spelling just copies them in.
func buildSevTable() {
	for key, v := range severityLUT {
		slot := &sevTable[sevHash(key)]
		if slot.key != "" {
			panic(fmt.Sprintf("enrich: severity spellings %q and %q collide in sevTable; use %s",
				slot.key, key, searchSevHash()))
		}
		*slot = sevSlot{key: key, text: v.text, no: v.no}
	}
}

// searchSevHash looks for mixer constants that are injective over the current
// severityLUT keys, for buildSevTable's collision panic. It only ever runs on
// that panic path.
func searchSevHash() string {
	for _, size := range []uint32{64, 128, 256} {
		for a := uint32(1); a < 64; a++ {
			for b := uint32(1); b < 64; b++ {
			next:
				for c := uint32(1); c < 8; c++ {
					seen := make(map[uint32]bool, len(severityLUT))
					for k := range severityLUT {
						h := (uint32(len(k))*a + uint32(k[0])*b + uint32(k[len(k)-1])*c) % size
						if seen[h] {
							continue next
						}
						seen[h] = true
					}
					return fmt.Sprintf("sevHashLen=%d sevHashFirst=%d sevHashLast=%d sevTableSize=%d", a, b, c, size)
				}
			}
		}
	}
	return "no constants found; widen the search in searchSevHash"
}

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

	// Spellings from level vocabularies the six canonical names do not cover.
	// Where a source grades within a level, the OTLP number records the
	// grading that the canonical text flattens away — syslog's notice is an
	// info that outranks a plain one, its alert a fatal that outranks a
	// critical (the same mapping syslogSeverity applies to the numeric form).
	add(InfoLevel, Info2LevelNo, "notice", "ntc") // syslog, Apache, nginx
	add(FatalLevel, Fatal2LevelNo, "alert")
	add(FatalLevel, Fatal3LevelNo, "emerg", "emergency")
	add(TraceLevel, TraceLevelNo, "verbose", "vrb") // Serilog's lowest level
	add(ErrorLevel, ErrorLevelNo, "severe")         // java.util.logging
	add(DebugLevel, DebugLevelNo, "fine")
	add(TraceLevel, TraceLevelNo, "finer", "finest")

	// The three abbreviations Microsoft.Extensions.Logging's console formatter
	// uses that no other vocabulary spells this way (its "info", "warn" and
	// "crit" are already above). "fail" is that formatter's word for Error.
	add(TraceLevel, TraceLevelNo, "trce")
	add(DebugLevel, DebugLevelNo, "dbug")
	add(ErrorLevel, ErrorLevelNo, "fail")

	buildSevTable()
}

// severityInitials are the first letters of every entry in severityLUT. A
// single byte test rejects the overwhelming majority of non-levels (any word
// the pattern table happened to capture as a level) before hashing anything.
// The lookup tests severityInitialMask, its bitmask form — one shift-and-mask
// instead of an IndexByte call.
const severityInitials = "tdinlwefcpavs"

var severityInitialMask uint32

func init() {
	for i := 0; i < len(severityInitials); i++ {
		severityInitialMask |= 1 << (severityInitials[i] - 'a')
	}
}

// lookupSeverity does the case-insensitive LUT lookup without allocating: the
// lowercased key is built on the stack and probed against the perfect-hash
// sevTable (see buildSevTable).
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
	// buf is stack memory that outlives the view, and the view never escapes.
	key := unsafe.String(&buf[0], len(s))
	slot := &sevTable[sevHash(key)]
	if slot.key != key {
		return "", 0, false
	}
	return slot.text, slot.no, true
}

// SeverityFromText normalizes any of the level spellings that appear in the
// wild ("WRN", "Warning", "w", "Information", ...) to one of the canonical
// levels and its OpenTelemetry severity number. It returns "", 0 for a string
// that names no level. It is the inverse of SeverityFromNumber.
func SeverityFromText(input string) (string, int) {
	// The canonical spellings dominate at runtime: ParseInto's final
	// normalization mostly re-normalizes text a parser already canonicalized.
	// The switch compiles to a length dispatch plus a couple of wide
	// compares — no lowercase pass, no hash. Each case returns exactly what
	// the LUT holds for that key, which the differential sweep pins.
	switch input {
	case "":
		return "", 0
	case TraceLevel:
		return TraceLevel, TraceLevelNo
	case DebugLevel:
		return DebugLevel, DebugLevelNo
	case InfoLevel:
		return InfoLevel, InfoLevelNo
	case WarnLevel:
		return WarnLevel, WarnLevelNo
	case ErrorLevel:
		return ErrorLevel, ErrorLevelNo
	case FatalLevel:
		return FatalLevel, FatalLevelNo
	}
	// No level begins with any other letter, so one bit test rejects most
	// non-levels outright. (|0x20 lowercases ASCII letters; every other byte,
	// including the lead byte of a multi-byte rune, maps outside a-z and
	// fails the range check.)
	if c := input[0] | 0x20; c-'a' > 'z'-'a' || severityInitialMask&(1<<(c-'a')) == 0 {
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
// priority) to a normalized level and OTLP severity number, following the
// mapping in the OpenTelemetry logs data model. Three syslog severities are
// fatal and three are info-or-below, so the OTLP numbers keep the grading the
// six canonical levels flatten away: notice is INFO2, alert FATAL2, emergency
// FATAL3.
func syslogSeverity(level int) (string, int) {
	switch level {
	case 0: // emergency
		return FatalLevel, Fatal3LevelNo
	case 1: // alert
		return FatalLevel, Fatal2LevelNo
	case 2: // critical
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
	// The scan anchors on the 'v', not on the leading quote: a quote opens
	// every key and every string value of a JSON line, so strings.Index would
	// restart at dozens of candidates per line to find one key.
	const key, anchor = `"level":`, 3
	i := indexAnchored(message, key, anchor)
	if i < 0 {
		return ""
	}
	rest := message[i+len(key):]
	// An encoder that pretty-prints puts whitespace after the colon.
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r') {
		rest = rest[1:]
	}
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

// redisSeverity maps a redis log-level mark (the single character between the
// timestamp and the message) to a severity.
func redisSeverity(severity string) string {
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
func HTTPStatusSeverity(code int, kind StatusKind) string {
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

// setHTTPResponseCode records an HTTP status code on the result and grades it
// into a severity. The code is kept whatever the severity ends up being: it is
// metadata in its own right, and a caller that wants to route on the number
// should not have to re-parse the line. A code outside 100-599 is not an HTTP
// status (Envoy writes 0 for "no response at all") and is not recorded.
// It takes int64 because every caller holds a freshly parsed JSON number; the
// early return also keeps the int conversion exact on 32-bit ints.
func setHTTPResponseCode(result *Result, code int64, kind StatusKind) {
	if code < 0 || code > 599 {
		return
	}
	c := int(code)
	if c >= 100 {
		result.HTTPStatusCode = c
	}
	if kind == StatusFailure || result.Severity == "" || result.Severity == "info" {
		if httpSev := HTTPStatusSeverity(c, kind); httpSev != "" {
			result.Severity = httpSev
		}
	}
}

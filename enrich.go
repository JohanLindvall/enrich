package enrich

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/JohanLindvall/logfmt"
)

// isHex reports whether c is an ASCII hex digit.
func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// validTraceID reports whether s is a whole trace ID: 32 hex digits, dashes
// permitted between them (Envoy emits its request_id as a UUID). The check is
// anchored — a field that merely *contains* 32 hex digits somewhere in a
// larger sentence is not a trace ID, and validating it as one used to store
// the entire sentence in Result.TraceID.
//
// An all-zero ID is rejected: W3C trace-context defines it as the invalid
// value, and that is exactly what OpenTelemetry SDKs emit for a log record
// with no active span. Storing it would correlate every untraced line in a
// fleet under one trace.
func validTraceID(s string) bool {
	if len(s) < 32 || len(s) > 36 {
		return false
	}
	if len(s) == 32 {
		// The dominant shape: 32 bare hex digits, decided a word at a time. A
		// dash would make the digit count fall short, so hex-and-not-all-zero
		// is the whole predicate here.
		isHex, isZero := hexRun(s, 0, 32)
		return isHex && !isZero
	}
	hex, zeros := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isHex(c):
			hex++
			if c == '0' {
				zeros++
			}
		case c != '-':
			return false
		}
	}
	return hex == 32 && zeros != 32
}

// validSpanID reports whether s is a whole span ID: exactly 16 hex digits, not
// all zero (see validTraceID).
func validSpanID(s string) bool {
	if len(s) != 16 {
		return false
	}
	isHex, isZero := hexRun(s, 0, 16)
	return isHex && !isZero
}

// lowHex reports whether c is a lowercase ASCII hex digit — the alphabet the
// W3C traceparent grammar (and the regex scanTraceparent replaced) allows.
func lowHex(c byte) bool {
	return c-'0' <= 9 || c-'a' <= 5
}

// scanTraceparent extracts the trace/span IDs from rest, the text following a
// "traceparent" occurrence: "[:=]", optional regexp-\s whitespace, an optional
// opening quote, then the 55-byte version-traceid-spanid-flags value in
// lowercase hex. It is the hand-scan replacement for the anchored regex this
// package used here (kept as the oracle in enrich_test.go, the same pattern
// as resourceGroupID): the regex allocated its submatch slice on every hit, per
// line on fleets that propagate W3C trace context. parseTraceparent supplies
// the structural offsets and the all-zero rejection; the lowercase check is
// what the regex's [0-9a-f] added on top of it.
func scanTraceparent(rest string) (traceID, spanID string) {
	if len(rest) == 0 || (rest[0] != ':' && rest[0] != '=') {
		return "", ""
	}
	i := 1
	for i < len(rest) && isSpaceRE(rest[i]) {
		i++
	}
	if i < len(rest) && rest[i] == '"' {
		i++
	}
	if i+traceparentValueLen > len(rest) {
		return "", ""
	}
	v := rest[i : i+traceparentValueLen]
	for j := 0; j < traceparentValueLen; j++ {
		switch j {
		case 2, 35, 52:
			if v[j] != '-' {
				return "", ""
			}
		default:
			if !lowHex(v[j]) {
				return "", ""
			}
		}
	}
	return parseTraceparent(v)
}

// resourceGroupID extracts the "/subscriptions/<guid>/resourcegroups/<name>"
// prefix of an Azure resource ID — the group's own ARM resource ID, the scope
// a caller groups by — and returns "" when id carries no such prefix. id must
// already be lowercased.
//
// This was a regexp; the equivalent scan is here because every match form the
// regexp package offers (FindStringIndex included) allocates its result slice,
// which put an allocation on every Azure diagnostic line. enrich_test.go keeps
// the original pattern as an oracle and differential-tests this against it.
func resourceGroupID(id string) string {
	const subscriptions = "/subscriptions/"
	const resourceGroups = "/resourcegroups/"
	const guidLen = len("00000000-0000-0000-0000-000000000000")

	// The pattern is unanchored: a resource ID sometimes appears inside a
	// longer path, so scan for each occurrence of the prefix.
	for off := 0; ; {
		i := strings.Index(id[off:], subscriptions)
		if i < 0 {
			return ""
		}
		i += off
		off = i + len(subscriptions)
		rest := id[off:]
		if len(rest) < guidLen || !validGUID(rest[:guidLen]) {
			continue
		}
		rest = rest[guidLen:]
		if !strings.HasPrefix(rest, resourceGroups) {
			continue
		}
		name := rest[len(resourceGroups):]
		if end := strings.IndexByte(name, '/'); end >= 0 {
			name = name[:end]
		}
		if name == "" { // "[^/]+": the group name must be non-empty
			continue
		}
		return id[i : off+guidLen+len(resourceGroups)+len(name)]
	}
}

// validGUID reports whether s is a dashed GUID: 8-4-4-4-12 hex digits. The
// 36-byte shape (the only one resourceGroupID asks about) is decided a word at
// a time: the dashes are checked directly, then XORed onto '0' ('-'^0x1d)
// so the whole word can take the one hex8 test.
func validGUID(s string) bool {
	if len(s) == 36 {
		const dash0and5 = uint64(0x1d) | uint64(0x1d)<<40     // bytes 8 and 13
		const dash2and7 = uint64(0x1d)<<16 | uint64(0x1d)<<56 // bytes 18 and 23
		return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' &&
			hex8(le64(s, 0)) &&
			hex8(le64(s, 8)^dash0and5) &&
			hex8(le64(s, 16)^dash2and7) &&
			hex8(le64(s, 24)) &&
			hex8(le64(s, 28))
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

// The parsing strategy that matched a line, reported in Result.Format.
const (
	FormatJSON    = "json"
	FormatLogfmt  = "logfmt"
	FormatPattern = "pattern"
	FormatNone    = ""
)

// Result holds the metadata extracted from a log line.
type Result struct {
	// Body is the original input line, unmodified.
	Body string

	// Format identifies the parsing strategy that matched: FormatJSON,
	// FormatLogfmt, FormatPattern, or FormatNone when nothing did. Exposing
	// this lets callers count enrichment hit rates and debug unparsed lines.
	Format string

	// Time is the timestamp parsed from the line; zero when none was found.
	Time time.Time

	// TimeHasZone reports whether the shape Time was parsed from stated its own
	// UTC offset — an RFC3339 stamp (or any other layout carrying a zone), a
	// numeric epoch, a JSON or logfmt timestamp. It is false for the layouts
	// that carry only a wall clock (klog's "MMDD hh:mm:ss", syslog RFC3164's
	// "Mmm dd hh:mm:ss", "2006-01-02 15:04:05", the slash-date forms, ...),
	// which this package must read as UTC because nothing in the line says
	// otherwise: a process running with TZ set to anything else then produces a
	// Time displaced by exactly that zone's offset, and the line cannot tell
	// you so.
	//
	// It exists for callers that hold a second, unambiguous timestamp — a
	// container runtime's or a journal's ingest time — and must decide whether
	// the line's own is the better datum. A zoned Time is an instant and may be
	// trusted however far it is from theirs; a zone-less one is a wall clock in
	// an unknown zone. It says nothing when Time is zero — no timestamp was
	// parsed, so there is none to have carried a zone.
	TimeHasZone bool

	// Severity is the normalized level (trace/debug/info/warn/error/fatal, see
	// SeverityFromText) and SeverityNumber its numeric equivalent.
	Severity       string
	SeverityNumber int

	// Message is the log message itself, without the envelope the line carries
	// it in: the "msg"/"message"/"@m" value of a JSON or logfmt line, or the
	// embedded line of a Docker json-file record. It is empty for a plain-text
	// line, whose message is not separable from Body.
	Message string

	// HTTPStatusCode is the HTTP response code the line reports (Envoy's
	// response_code, an Azure httpStatusCode or resultDescription, an access
	// log's status field, ...), or 0 when the line reports none. It is the
	// number behind the severity that HTTPStatusSeverity derives.
	HTTPStatusCode int

	// Trace correlation identifiers.
	TraceID string
	SpanID  string

	// Structured-log (Serilog-style) fields. Service and Product are
	// normalized to lowercase.
	Template      string
	TemplateHash  string
	SourceContext string
	Service       string
	Version       string
	Product       string

	// Azure resource metadata. ResourceGroupID is the resource group's own
	// full ARM resource ID ("/subscriptions/<guid>/resourcegroups/<name>"),
	// not the bare group name.
	ResourceID      string
	ResourceGroupID string
	EventCategory   string

	// Exception details parsed from .NET-style exception payloads.
	ExceptionType       string
	ExceptionMessage    string
	ExceptionStackTrace string
}

// setTime records a parsed timestamp together with whether the shape it came
// from stated its own UTC offset. Every assignment to Time goes through this,
// so a later timestamp can never silently inherit an earlier one's zone answer
// (a Docker json-file record whose embedded klog line parsed first, say).
func (result *Result) setTime(t time.Time, hasZone bool) {
	result.Time = t
	result.TimeHasZone = hasZone
}

// ansiEscape opens every ANSI escape sequence (https://tforgione.fr/posts/ansi-escape-codes/).
const ansiEscape = 0x1b

// ansiSeqLen returns the length of the SGR escape sequence at the start of s —
// ESC '[' then digit groups separated by ';' then 'm' — or 0 when there is
// none. Maximal munch is exact: a shortened digit run ends on a digit, which
// neither ';' nor 'm' accepts.
func ansiSeqLen(s string) int {
	if len(s) < 2 || s[0] != ansiEscape || s[1] != '[' {
		return 0
	}
	for i := 2; ; {
		start := i
		for i < len(s) && isDigitB(s[i]) {
			i++
		}
		if i == start || i == len(s) {
			return 0 // \d+ needs a digit, and 'm' still has to arrive
		}
		switch s[i] {
		case ';':
			i++
		case 'm':
			return i + 1
		default:
			return 0
		}
	}
}

// removeANSICodes strips the SGR colour sequences a console-formatting logger
// writes (zerolog's and logrus's text output colour the level, and the pattern
// table has to see the line without them).
//
// This was `ansiRe.ReplaceAllString` behind a ContainsRune guard. The guard is
// what matters for uncoloured lines and is still here; the hand scan is for the
// coloured ones, where handing a whole line to the regexp engine cost more than
// the rest of Parse put together. enrich_test.go keeps the pattern as the
// oracle, as it does for resourceGroupID and the severity table.
func removeANSICodes(input string) string {
	i := strings.IndexByte(input, ansiEscape)
	if i < 0 {
		return input // no escape at all: the overwhelmingly common case
	}
	b := make([]byte, 0, len(input))
	last := 0
	for i >= 0 {
		if n := ansiSeqLen(input[i:]); n > 0 {
			b = append(b, input[last:i]...)
			i += n
			last = i
		} else {
			i++ // a lone ESC, or a sequence the pattern does not match
		}
		if i >= len(input) {
			break
		}
		next := strings.IndexByte(input[i:], ansiEscape)
		if next < 0 {
			break
		}
		i += next
	}
	if last == 0 {
		return input // an ESC, but no complete sequence: nothing to copy
	}
	// b is freshly heap-allocated and never written again, so the view is as
	// immutable as any string (the same pattern as lower and removeDashesASCII).
	b = append(b, input[last:]...)
	return unsafeString(b)
}

func removeDashesASCII(s string) string {
	if strings.IndexByte(s, '-') < 0 {
		return s // no dashes: avoid the copy (common for 32-hex trace ids)
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			b = append(b, s[i])
		}
	}
	// The buffer is built here and never mutated again, so hand out a view of
	// it instead of paying string(b)'s second copy (dashed UUID request_ids —
	// the common Envoy shape — otherwise cost 2 allocs per line). Same pattern
	// as lower().
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// logfmtKeys are the keys enrichFromLogFmt's switch inspects (t/ts/time/
// timestamp, level, msg/message, the trace/span/traceparent spellings, both
// cases). The list mirrors the switch's case clauses by hand — a new case
// whose spelling is missing here is silently never matched, so extend both
// together; TestLogfmtKeyGate pins the two against each other, and the
// per-spelling tests (TestParse_TraceIDSpellings,
// TestParse_Logfmt_TimestampKeys, TestParse_Logfmt_Message) catch a miss end
// to end.
var logfmtKeys = []string{
	"t", "ts", "time", "timestamp", "level", "msg", "message",
	"traceid", "traceId", "traceID", "TraceId", "TraceID", "trace_id", "trace.id",
	"spanid", "spanId", "spanID", "SpanId", "SpanID", "span_id", "span.id",
	"traceparent",
}

// logfmtKeyGate holds, per first byte, the lengths those keys come in: bit L is
// set when some key starts with that byte and is L bytes long. One load, one
// shift and one mask reject a key on either count, which matters because the
// first byte alone is a weak filter — a browser-telemetry line carries a dozen
// session_attr_* keys, every one of which shares its 's' with the span-ID
// spellings and only differs in length. A length of 32 or more shifts the bit
// out of the word entirely, which Go defines as zero.
var logfmtKeyGate [256]uint32

func init() {
	for _, k := range logfmtKeys {
		logfmtKeyGate[k[0]] |= 1 << len(k)
	}
}

// parseTraceparent splits a W3C traceparent value
// (version-traceid-spanid-flags, e.g. "00-4bf9...4736-00f0...02b7-01") into
// its trace and span IDs, returning empty strings if the value is malformed.
func parseTraceparent(v string) (traceID, spanID string) {
	// version(2)-traceid(32)-spanid(16)-flags(2), all hex: fixed offsets, so
	// slice it directly instead of allocating a split.
	if len(v) != traceparentValueLen || v[2] != '-' || v[35] != '-' || v[52] != '-' {
		return "", ""
	}
	traceID, spanID = v[3:35], v[36:52]
	if !validTraceID(traceID) || !validSpanID(spanID) {
		return "", ""
	}
	return traceID, spanID
}

// enrichFromLogFmt scans a logfmt line for a timestamp (key t/ts/time/
// timestamp), a severity (key level), and trace correlation IDs (trace_id/
// span_id spellings and W3C traceparent), using the logfmt key/value reader
// instead of a regex. It reports whether the line is a logfmt line worth
// using — true when a timestamp parsed, a non-empty level was seen, or a
// trace ID was found. The time is zero for a level-only line.
//
// The first parseable timestamp wins, as does the first valid trace/span ID.
// For the level, a value that normalizes to a known severity wins over an
// earlier non-normalizing one (e.g. the inner "level=a@1 level=info" keeps
// "info"). Explicit trace_id/span_id keys win over a traceparent wherever
// either appears — the same precedence applyMetadata gives the JSON fields.
func (result *Result) enrichFromLogFmt(message string, memo *byteMemo) bool {
	if !memo.has(message, '=') {
		return false
	}

	var ts time.Time
	var tsFound, levelGood bool
	var levelNo int
	var level, msg, traceID, spanID, tpTraceID, tpSpanID string

	// message is immutable; alias its bytes rather than copying.
	buf := unsafe.Slice(unsafe.StringData(message), len(message))
	_ = logfmt.Iterate(buf, func(key, val []byte) bool {
		// Every key the switch below knows starts with one of t/l/m/s (either
		// case) and is at most eleven bytes; one table probe rejects the rest
		// before the length-dispatched switch runs. A browser-telemetry line
		// carries dozens of event_data_* keys per interesting one.
		if len(key) == 0 || logfmtKeyGate[key[0]]&(uint32(1)<<uint(len(key))) == 0 {
			return true
		}
		// val aliases message (or, for a bare key, a constant): both are
		// immutable, so a string view costs nothing and copies nothing.
		// Anything kept in the result therefore aliases the input, exactly
		// like the nocopy JSON fields.
		sval := unsafe.String(unsafe.SliceData(val), len(val))
		switch string(key) {
		case "t", "ts", "time", "timestamp":
			if !tsFound {
				// The Go time.Time String() shape first — the common browser-
				// telemetry timestamp, which logfmt.ParseTime can only reach
				// through a full time.Parse. A shape the fast path does not
				// claim (epoch, RFC3339, exotic zone names) goes to ParseTime
				// as before.
				if t, ok := parseGoStringTime(val); ok {
					ts, tsFound = t, true
				} else if t, ok := logfmt.ParseTime(val); ok {
					ts, tsFound = t, true
				}
			}
		case "level":
			if !levelGood {
				// Normalize here rather than leaving it to ParseInto's final
				// pass: the canonical text turns that pass into a
				// constant-switch hit instead of a second LUT probe, and the
				// number keeps the grading ("notice" is an info with the INFO2
				// number) exactly as re-normalizing the raw text would.
				if sev, no := SeverityFromText(sval); sev != "" {
					level, levelNo, levelGood = sev, no, true
				} else if level == "" {
					level = sval
				}
			}
		case "msg", "message":
			if msg == "" {
				msg = sval
			}
		case "traceid", "traceId", "traceID", "TraceId", "TraceID", "trace_id", "trace.id":
			if traceID == "" && validTraceID(sval) {
				traceID = sval
			}
		case "spanid", "spanId", "spanID", "SpanId", "SpanID", "span_id", "span.id":
			if spanID == "" && validSpanID(sval) {
				spanID = sval
			}
		case "traceparent":
			if tpTraceID == "" {
				if t, s := parseTraceparent(sval); t != "" {
					tpTraceID, tpSpanID = t, s
				}
			}
		}
		// Keep scanning while any signal is still missing. A found traceparent
		// does not stop the scan: an explicit trace_id/span_id later in the
		// line would still win over it.
		return !levelGood || !tsFound || msg == "" || traceID == "" || spanID == ""
	})

	// Explicit keys name the record's own IDs and win; a propagated
	// traceparent fills whichever side they left empty (the same rule as
	// applyMetadata on the JSON path).
	if traceID == "" {
		traceID = tpTraceID
	}
	if spanID == "" {
		spanID = tpSpanID
	}
	if traceID != "" {
		result.TraceID = removeDashesASCII(traceID)
	}
	if spanID != "" {
		result.SpanID = spanID
	}
	// Every shape reaching a timestamp here carries a zone: parseGoStringTime
	// claims only values with a numeric offset, and logfmt.ParseTime accepts
	// RFC3339Nano, the "-0700 MST" form, and a unix epoch — nothing zone-less.
	// TestLogfmtTimestampsAlwaysCarryAZone pins that dependency.
	result.setTime(ts, tsFound)
	result.Severity = level
	if levelGood {
		result.SeverityNumber = levelNo
	}
	// The message is kept even when the line is not claimed as logfmt: a
	// key=value line the pattern table resolves instead (a Kubernetes event,
	// say) still carries its msg= in the same place.
	result.Message = msg
	return tsFound || level != "" || result.TraceID != ""
}

// Parse extracts metadata from a log message.
//
// The result shares memory with input: Body is input itself, and the string
// fields populated from a JSON line (TraceID, SourceContext, Template, ...) alias
// input's backing array rather than copying it. Go strings are immutable, so this
// is safe, but it means input is kept alive for as long as the returned *Result
// (or any string copied out of it) is reachable. Callers holding many results
// therefore retain the corresponding input strings; copy the fields you need if
// you want the large input buffers to be collected sooner.
func Parse(input string) *Result {
	// The allocation already yields zeroed memory, so the reset ParseInto opens
	// with would be pure waste here — and not cheap waste: overwriting the
	// Result's eighteen string headers takes a bulk write barrier whenever the
	// collector is marking, which on a per-line allocator is most of the time.
	result := &Result{Body: input}
	fillResult(result)
	return result
}

// ParseBytes is ParseInto for a byte slice, avoiding the copy that
// Parse(string(line)) makes of every line.
//
// It reports whether any parsing strategy matched.
//
// The result aliases input: Body and the extracted string fields point into
// input's backing array rather than copying it. input must therefore not be
// modified or reused while the result (or any string taken from it) is still
// in use. This matters most with bufio.Scanner, whose Bytes method returns a
// buffer that the next Scan overwrites — either consume the result before
// scanning again:
//
//	var r enrich.Result
//	for scanner.Scan() {
//	    enrich.ParseBytes(scanner.Bytes(), &r)
//	    emit(&r) // must not retain r's fields past this call
//	}
//
// or, to retain anything, copy it out (or use ParseInto with
// scanner.Text(), which copies the line for you).
func ParseBytes(input []byte, result *Result) bool {
	// input is treated as read-only for the lifetime of result, which is
	// exactly the contract above; the string view therefore costs nothing.
	return ParseInto(unsafe.String(unsafe.SliceData(input), len(input)), result)
}

// ParseInto is Parse without the per-call allocation: it resets *result and
// fills it in place, for callers that process many lines and can reuse one
// Result. It reports whether any parsing strategy matched (result.Format !=
// FormatNone). The aliasing caveats of Parse apply — the filled fields share
// memory with input.
func ParseInto(input string, result *Result) bool {
	*result = Result{Body: input}
	return fillResult(result)
}

// fillResult is ParseInto's body for a Result holding nothing but its Body —
// every caller has just allocated or just reset one. Splitting the reset off is
// what lets Parse skip it; keeping it in ParseInto is what makes a reused
// Result safe (TestParseInto_ResetsResult pins that).
func fillResult(result *Result) bool {
	input := result.Body
	message := removeANSICodes(input)

	// Only a line that opens an object can decode; checking that here keeps the
	// 400-byte enrichFields off the stack (and out of the zeroing) for every
	// line that is not JSON, which is most of them.
	if looksLikeJSONObject(message) && result.enrichFromJSON(message) {
		result.Format = FormatJSON
	} else {
		// The memo lives across the logfmt scan and the pattern table, so a
		// byte one gate scanned for ('=' most of all) is never scanned again.
		var memo byteMemo
		if result.enrichFromLogFmt(message, &memo) {
			result.Format = FormatLogfmt
		} else if result.enrichFromPatterns(message, &memo) {
			result.Format = FormatPattern
		}
	}

	// Normalize the severity text, and keep a finer-grained severity number
	// (e.g. syslog notice -> INFO2) when a parser already set one — but only
	// while it still agrees with the text. A severity set early and overridden
	// later (a "notice" line that then reports a 500, say) would otherwise
	// leave the number describing the level the text no longer names. Enforcing
	// that here means no parser has to remember to clear it.
	sev, no := SeverityFromText(result.Severity)
	result.Severity = sev
	if result.SeverityNumber == 0 || SeverityFromNumber(result.SeverityNumber) != sev {
		result.SeverityNumber = no
	}

	return result.Format != FormatNone
}

// looksLikeJSONObject reports whether message can possibly decode as a JSON
// object: the decoder skips leading whitespace and then requires '{'.
func looksLikeJSONObject(message string) bool {
	for i := 0; i < len(message); i++ {
		switch message[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// enrichFromJSON decodes message as a JSON log line and fills the result from
// it, reporting whether it decoded. enrichFields is declared here rather than
// in ParseInto so that only the JSON path pays to zero it.
func (result *Result) enrichFromJSON(message string) bool {
	// The decoder only reads these bytes (nocopy fields alias them), so alias
	// the immutable string instead of copying it.
	messageBytes := unsafe.Slice(unsafe.StringData(message), len(message))

	var f enrichFields
	if err := f.UnmarshalJSON(messageBytes); err != nil {
		return false
	}
	result.applyJSON(&f)
	if result.Severity == "" {
		// Pino/Bunyan encode the level as a number, which the lax string
		// decoder skips; map it from the raw line.
		result.Severity = pinoSeverity(message)
	}
	return true
}

// applyJSON fills the result from a successfully decoded JSON log line.
func (result *Result) applyJSON(f *enrichFields) {
	// Nested objects first, so authoritative top-level scalars (notably the
	// Azure diagnostic-log "time") win over values lifted from properties.log.
	responseCode := result.applyProperties(&f.Properties)

	// Docker json-file records carry the original line in a top-level "log"
	// string; enrich it recursively, top-level scalars again winning.
	if f.Log != "" {
		nested := Result{Body: f.Log} // zeroed at declaration: no reset needed
		fillResult(&nested)
		result.mergeNested(&nested)
	}

	if code, ok := jsonInt(f.ResponseStatus.Code); ok {
		setHTTPResponseCode(result, code, StatusFailure)
	}

	// Timestamp (RFC3339 string or numeric epoch) decoded by the lax time.Time
	// field; a zero value means absent/unparseable, so keep any properties.log
	// time. MongoDB nests its timestamp as {"t":{"$date":...}}. Both shapes the
	// decoder accepts state their own offset — RFC3339 mandates one, an epoch
	// is an instant — so a JSON timestamp is always zoned
	// (TestJSONTimestampsAlwaysCarryAZone pins that dependency).
	if !f.Time.IsZero() {
		result.setTime(f.Time, true)
	} else if !f.MongoTime.Date.IsZero() {
		result.setTime(f.MongoTime.Date, true)
	}

	result.applySeverityHints(f)
	result.applyMetadata(f)

	// An exception payload with no level of its own is an error: the same rule
	// the pattern table applies to a Go panic or a Python traceback.
	if result.Severity == "" && (result.ExceptionType != "" || result.ExceptionMessage != "" || result.ExceptionStackTrace != "") {
		result.Severity = ErrorLevel
	}

	if f.ResponseCode != "" {
		responseCode = f.ResponseCode
	}
	result.applyResponseCode(f, responseCode)
}

// applyProperties handles the Azure diagnostic-log "properties" envelope: a
// nested log line (enriched recursively), a JSON-as-string HTTP response, or
// a plain status code. The plain code is returned instead of applied so a
// top-level response_code can take precedence.
func (result *Result) applyProperties(p *enrichProperties) json.Number {
	switch {
	case p.Log != "":
		nested := Result{Body: p.Log} // zeroed at declaration: no reset needed
		fillResult(&nested)
		result.mergeNested(&nested)
	case p.Response != "":
		var hr httpResponse
		// p.Response aliases the immutable input and the decoder only reads
		// it, so alias it once more instead of copying it into a []byte.
		if err := hr.UnmarshalJSON(unsafe.Slice(unsafe.StringData(p.Response), len(p.Response))); err == nil {
			if code, ok := jsonInt(hr.StatusCode); ok {
				setHTTPResponseCode(result, code, StatusFailure)
			}
		}
	case p.HTTPStatusCode != "":
		return p.HTTPStatusCode
	}
	return ""
}

// jsonInt converts a decoded JSON number to an int64, reporting whether the
// key was present and integral. An empty json.Number means the key was absent
// (or held a non-numeric value that the lax decoder skipped), which is what
// distinguishes an absent code from a present zero.
func jsonInt(n json.Number) (int64, bool) {
	if n == "" {
		return 0, false
	}
	// Nearly every code reaching this is a few plain digits; up to 18 of them
	// cannot overflow int64, so ParseInt's sign/base/cutoff bookkeeping is
	// only needed for the shapes the loop rejects (signs, floats, exponents,
	// 19+ digits), which keep the stdlib behavior verbatim.
	if len(n) <= 18 {
		var v int64
		i := 0
		for ; i < len(n); i++ {
			c := n[i] - '0'
			if c > 9 {
				break
			}
			v = v*10 + int64(c)
		}
		if i == len(n) {
			return v, true
		}
	}
	v, err := strconv.ParseInt(string(n), 10, 64)
	return v, err == nil
}

// mergeNested lifts the fields extracted from an embedded log line (a Docker
// json-file "log" string or an Azure properties.log payload) into the result.
// The caller applies the enclosing envelope's own values afterwards, so an
// authoritative top-level scalar still wins over a lifted one.
func (result *Result) mergeNested(nested *Result) {
	if !nested.Time.IsZero() {
		// The embedded line's own answer travels with its timestamp: a Docker
		// record wrapping a klog line carries a wall clock, whatever the
		// envelope's own (zoned) "time" would have said.
		result.setTime(nested.Time, nested.TimeHasZone)
	}
	if nested.SeverityNumber != 0 {
		result.SeverityNumber = nested.SeverityNumber
	}
	if nested.HTTPStatusCode != 0 {
		result.HTTPStatusCode = nested.HTTPStatusCode
	}
	setIfSet(&result.Severity, nested.Severity)
	setIfSet(&result.TraceID, nested.TraceID)
	setIfSet(&result.SpanID, nested.SpanID)
	setIfSet(&result.Template, nested.Template)
	setIfSet(&result.TemplateHash, nested.TemplateHash)
	setIfSet(&result.SourceContext, nested.SourceContext)
	setIfSet(&result.Service, nested.Service)
	setIfSet(&result.Version, nested.Version)
	setIfSet(&result.Product, nested.Product)
	setIfSet(&result.ExceptionType, nested.ExceptionType)
	setIfSet(&result.ExceptionMessage, nested.ExceptionMessage)
	setIfSet(&result.ExceptionStackTrace, nested.ExceptionStackTrace)

	// The embedded line *is* the message of the record that wraps it, so a
	// plain-text payload becomes the message verbatim (minus the trailing
	// newline Docker keeps).
	switch {
	case nested.Message != "":
		result.Message = nested.Message
	case nested.Format != FormatJSON && nested.Body != "":
		result.Message = strings.TrimRight(nested.Body, "\r\n")
	}
}

// applySeverityHints resolves the severity from the textual level field and,
// failing that, from MongoDB's single-letter "s" or a gRPC status number
// (0 → info, other valid codes → warn).
func (result *Result) applySeverityHints(f *enrichFields) {
	// Severity from a textual level/severity field; numeric levels (e.g. Pino's
	// "level":30) are skipped by the lax tag, leaving the last textual value.
	// The number is kept alongside the text: a spelling can be finer-grained
	// than the level it normalizes to ("notice" is an info with the INFO2
	// number), and normalizing early used to throw that away.
	if result.Severity == "" && f.Severity != "" {
		if s, no := SeverityFromText(f.Severity); s != "" {
			result.Severity, result.SeverityNumber = s, no
		}
	}

	if result.Severity == "" && f.MongoSeverity != "" && !f.MongoTime.Date.IsZero() {
		if s, no := SeverityFromText(f.MongoSeverity); s != "" {
			result.Severity, result.SeverityNumber = s, no
		}
	}

	// An OTLP-JSON record carries the OpenTelemetry SeverityNumber, which is
	// finer-grained than the text (a 10 is a notice, an info that outranks a
	// plain one). It names the level on its own, and refines a textual level
	// that agrees with it; a text that disagrees wins, since Severity and
	// SeverityNumber must never contradict each other.
	if no, ok := jsonInt(f.SeverityNumber); ok && no >= 1 && no <= 24 {
		if text := SeverityFromNumber(int(no)); text == result.Severity || result.Severity == "" {
			result.Severity, result.SeverityNumber = text, int(no)
		}
	}

	if grpc, ok := jsonInt(f.GrpcStatusNumber); ok && grpc >= 0 && grpc <= 16 {
		if result.Severity == "" || result.Severity == "info" {
			if grpc == 0 {
				result.Severity = InfoLevel
			} else {
				result.Severity = WarnLevel
			}
		}
	}
}

// setIfSet assigns src to *dst unless src is empty, so an envelope that does
// not carry a field leaves whatever a nested payload contributed in place.
func setIfSet(dst *string, src string) {
	if src != "" {
		*dst = src
	}
}

// applyMetadata copies the identifier and structured-log fields: validated
// trace/span IDs, the message, Serilog context fields, Azure resource
// metadata, and the exception payload.
func (result *Result) applyMetadata(f *enrichFields) {
	// A W3C traceparent carries both IDs and is the propagated value, so it
	// loses to explicit trace_id/span_id fields but beats having neither.
	if t, s := parseTraceparent(f.Traceparent); t != "" {
		result.TraceID, result.SpanID = t, s
	}
	if validTraceID(f.TraceID) {
		result.TraceID = removeDashesASCII(f.TraceID)
	}
	if validSpanID(f.SpanID) {
		result.SpanID = f.SpanID
	}
	setIfSet(&result.Message, f.Message)
	setIfSet(&result.SourceContext, f.SourceContext)
	setIfSet(&result.TemplateHash, f.TemplateHash)
	setIfSet(&result.Template, f.Template)
	if f.ResourceID != "" {
		result.ResourceID = lower(f.ResourceID)
		result.ResourceGroupID = resourceGroupID(result.ResourceID)
	}
	setIfSet(&result.EventCategory, f.EventCategory)
	setIfSet(&result.Version, f.Version)
	setIfSet(&result.Service, lower(f.Service))
	setIfSet(&result.Product, lower(f.Product))

	// @x carries type, message and stack trace in one payload; the ECS/OTel
	// spellings carry them apart and are authoritative when present.
	if f.Exception != "" {
		result.parseException(f.Exception)
	}
	setIfSet(&result.ExceptionType, f.ErrorType)
	setIfSet(&result.ExceptionMessage, f.ErrorMessage)
	setIfSet(&result.ExceptionStackTrace, f.ErrorStack)
}

// lower is strings.ToLower minus its unconditional allocation and its byte-at-
// a-time loop: an Azure resource ID that is already lowercase (many are) is
// returned as is, aliasing the input like every other extracted field, and an
// uppercase one — the benchmark shape, where ToLower's two passes plus copy
// were ~13% of the Azure parse — is case-flipped eight bytes at a time. Any
// non-ASCII byte defers to strings.ToLower, which is also the oracle lower is
// differential-tested against (TestLowerMatchesToLower).
func lower(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' || c >= utf8.RuneSelf {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := make([]byte, len(s))
	copy(b, s[:i])
	for ; i+8 <= len(s); i += 8 {
		w := le64(s, i)
		if w&swarHigh != 0 {
			return strings.ToLower(s) // non-ASCII: rune-aware lowering
		}
		// laneRange marks the A-Z lanes with 0x80; shifted to the 0x20 case
		// bit, the XOR flips exactly those bytes to lowercase.
		putLE64(b, i, w^(laneRange(w, 'A', 'Z')>>2))
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return strings.ToLower(s)
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	// b is freshly heap-allocated and never written again, so the view is as
	// immutable as any string.
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// applyResponseCode maps HTTP-ish status information to a severity: first an
// Azure resultType/resultDescription pair, then the response code (a
// top-level response_code, or one deferred from properties.httpStatusCode).
// A code of 0 is Envoy-specific: without a protocol the line is plain TCP
// proxying (info); with response_flags DR/DC the client disconnected (warn).
func (result *Result) applyResponseCode(f *enrichFields, responseCode json.Number) {
	if f.ResultType == "HttpStatusCode" && f.ResultDescription != "" {
		if code, err := strconv.ParseInt(f.ResultDescription, 10, 64); err == nil {
			setHTTPResponseCode(result, code, StatusObserved)
		}
	}

	code, ok := jsonInt(responseCode)
	if !ok {
		return
	}
	// Both rules are inferences from a missing response, so they defer to a
	// level the line states outright — the key also spells "statusCode" for
	// producers that do log one.
	if code == 0 {
		explicit := result.Severity != "" && result.Severity != InfoLevel
		if f.Protocol == "" {
			if !explicit {
				result.Severity = InfoLevel
			}
			return
		}
		if strings.EqualFold(f.ResponseFlags, "DR") || strings.EqualFold(f.ResponseFlags, "DC") {
			if !explicit {
				result.Severity = WarnLevel
			}
			return
		}
	}
	setHTTPResponseCode(result, code, StatusObserved)
}

// The W3C traceparent header enrichFromPatterns scans for. The scan anchors on
// the key's 'p', far rarer in log prose than its leading 't' (see
// indexAnchored).
const (
	traceparentKey    = "traceparent"
	traceparentAnchor = 5
	// version(2)-traceid(32)-spanid(16)-flags(2) plus three dashes.
	traceparentValueLen = 55
	// The shortest line a traceparent can be found in: the key, one separator
	// byte, and the value. Anything shorter cannot match, which spares most
	// plain-text lines the scan entirely.
	minTraceparentLine = len(traceparentKey) + 1 + traceparentValueLen
)

// enrichFromPatterns fills the result from the first matching entry in the
// compiled line-parser table (nginx, klog, redis, tracebacks, ...) and
// reports whether any entry matched. A W3C traceparent anywhere in the line
// is extracted independently of the table.
func (result *Result) enrichFromPatterns(message string, memo *byteMemo) bool {
	matched := false
	if message != "" {
		// One index picks the parsers this line's first byte can start, in
		// table (priority) order; the rest never run.
		plain, quoted := lineGates(message)
		for _, clp := range parsersByFirstByte[message[0]] {
			if clp.passes(plain, quoted) && clp.apply(result, message, memo) {
				matched = true
				break
			}
		}
	}

	// scanTraceparent needs room for the key, a separator and the 55-byte
	// value, and requires "traceparent[:=]" — so a line shorter than that, or
	// carrying neither ':' nor '=', cannot match. The length test is free and
	// covers most plain-text lines; the two byte probes are memoized SIMD
	// scans, far cheaper than the substring search. Like the regex it replaced,
	// the scan gets one attempt, at the first occurrence.
	if len(message) >= minTraceparentLine && (memo.has(message, '=') || memo.has(message, ':')) {
		if i := indexAnchored(message, traceparentKey, traceparentAnchor); i >= 0 {
			if t, s := scanTraceparent(message[i+len(traceparentKey):]); t != "" {
				result.TraceID, result.SpanID = t, s
				matched = true
			}
		}
	}
	return matched
}

// parseException splits a .NET-style exception payload — "Type: message"
// followed by the stack trace — into its three parts. Every part is a slice of
// exception (Cut, not Split: the slices allocate a header array per call and
// this runs per line on error-heavy streams).
func (result *Result) parseException(exception string) {
	head, stack, hasStack := strings.Cut(exception, "\n")
	if excType, message, ok := strings.Cut(head, ": "); ok {
		// .NET puts parenthesized error codes between the type and the colon —
		// "System.Net.Sockets.SocketException (00000005, 0xFFFDFFFF): ..." —
		// so drop a parenthetical suffix before isolating the type word, or the
		// last-word rule below would pick "0xFFFDFFFF)" as the type. Only a
		// parenthetical that runs to the END of the head is a code suffix:
		// Java thread names also contain " (" — 'Exception in thread "Thread-0
		// (ActiveMQ-client-global-threads)" java.lang.IllegalStateException' —
		// and cutting at the first " (" there would leave '"Thread-0' as the
		// type. The suffix check keeps nested .NET parens right too:
		// "HttpRequestException (Connection refused (localhost:5000))".
		if paren := strings.Index(excType, " ("); paren >= 0 && excType[len(excType)-1] == ')' {
			excType = excType[:paren]
		}
		// "Exception in thread "main" java.lang.IllegalStateException" and the
		// like put words before the type; the type is the last of them, the
		// one the ": " cut at.
		if space := strings.LastIndexByte(excType, ' '); space >= 0 {
			excType = excType[space+1:]
		}
		result.ExceptionType = excType
		result.ExceptionMessage = message
	} else {
		result.ExceptionMessage = head
	}

	if hasStack {
		result.ExceptionStackTrace = stack
	}
}

package enrich

import (
	"encoding/json"
	"regexp"
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
	zeros := 0
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
		if s[i] == '0' {
			zeros++
		}
	}
	return zeros != 16
}

var traceparentRE = regexp.MustCompile(`^traceparent[:=]\s*"?([0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2})`)

// resourceGroup extracts the "/subscriptions/<guid>/resourcegroups/<name>"
// prefix of an Azure resource ID — the scope a caller groups by — and returns
// "" when id carries no such prefix. id must already be lowercased.
//
// This was a regexp; the equivalent scan is here because every match form the
// regexp package offers (FindStringIndex included) allocates its result slice,
// which put an allocation on every Azure diagnostic line. enrich_test.go keeps
// the original pattern as an oracle and differential-tests this against it.
func resourceGroup(id string) string {
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

// validGUID reports whether s is a dashed GUID: 8-4-4-4-12 hex digits.
func validGUID(s string) bool {
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

	// Structured-log (Serilog-style) fields.
	Template      string
	TemplateHash  string
	SourceContext string
	Service       string
	Version       string
	Product       string

	// Azure resource metadata.
	ResourceID    string
	ResourceGroup string
	EventCategory string

	// Exception details parsed from .NET-style exception payloads.
	ExceptionType       string
	ExceptionMessage    string
	ExceptionStackTrace string
}

var ansiRe = regexp.MustCompile(`\x1b\[\d+(;\d+)*m`) // https://tforgione.fr/posts/ansi-escape-codes/

func removeANSICodes(input string) string {
	if strings.ContainsRune(input, '\x1b') {
		return ansiRe.ReplaceAllString(input, "")
	}
	return input
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
	return string(b)
}

// parseTraceparent splits a W3C traceparent value
// (version-traceid-spanid-flags, e.g. "00-4bf9...4736-00f0...02b7-01") into
// its trace and span IDs, returning empty strings if the value is malformed.
func parseTraceparent(v string) (traceID, spanID string) {
	// version(2)-traceid(32)-spanid(16)-flags(2), all hex: fixed offsets, so
	// slice it directly instead of allocating a split.
	if len(v) != 55 || v[2] != '-' || v[35] != '-' || v[52] != '-' {
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
// The first parseable timestamp wins. For the level, a value that normalizes to a
// known severity wins over an earlier non-normalizing one (e.g. the inner
// "level=a@1 level=info" keeps "info").
func (result *Result) enrichFromLogFmt(message string) bool {
	if strings.IndexByte(message, '=') < 0 {
		return false
	}

	var ts time.Time
	var tsFound, levelGood bool
	var level, msg, traceID, spanID string

	// message is immutable; alias its bytes rather than copying.
	buf := unsafe.Slice(unsafe.StringData(message), len(message))
	_ = logfmt.Iterate(buf, func(key, val []byte) bool {
		// val aliases message (or, for a bare key, a constant): both are
		// immutable, so a string view costs nothing and copies nothing.
		// Anything kept in the result therefore aliases the input, exactly
		// like the nocopy JSON fields.
		sval := unsafe.String(unsafe.SliceData(val), len(val))
		switch string(key) {
		case "t", "ts", "time", "timestamp":
			if !tsFound {
				if t, ok := logfmt.ParseTime(sval); ok {
					ts, tsFound = t, true
				}
			}
		case "level":
			if !levelGood {
				if sev, _ := SeverityFromText(sval); sev != "" {
					level, levelGood = sval, true
				} else if level == "" {
					level = sval
				}
			}
		case "msg", "message":
			if msg == "" {
				msg = sval
			}
		case "traceid", "traceId", "traceID", "TraceId", "TraceID", "trace_id", "trace.id":
			if traceID == "" {
				traceID = sval
			}
		case "spanid", "spanId", "spanID", "SpanId", "SpanID", "span_id", "span.id":
			if spanID == "" {
				spanID = sval
			}
		case "traceparent":
			if t, s := parseTraceparent(sval); t != "" {
				traceID, spanID = t, s
			}
		}
		return !levelGood || !tsFound || traceID == "" || spanID == ""
	})

	if validTraceID(traceID) {
		result.TraceID = removeDashesASCII(traceID)
	}
	if validSpanID(spanID) {
		result.SpanID = spanID
	}
	result.Time = ts
	result.Severity = level
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
	result := new(Result)
	ParseInto(input, result)
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
	message := removeANSICodes(input)

	// Only a line that opens an object can decode; checking that here keeps the
	// 400-byte enrichFields off the stack (and out of the zeroing) for every
	// line that is not JSON, which is most of them.
	if looksLikeJSONObject(message) && result.enrichFromJSON(message) {
		result.Format = FormatJSON
	} else if result.enrichFromLogFmt(message) {
		result.Format = FormatLogfmt
	} else if result.enrichFromPatterns(message) {
		result.Format = FormatPattern
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
		var nested Result
		ParseInto(f.Log, &nested)
		result.mergeNested(&nested)
	}

	if code, ok := jsonInt(f.ResponseStatus.Code); ok {
		setHTTPResponseCode(result, code, StatusFailure)
	}

	// Timestamp (RFC3339 string or numeric epoch) decoded by the lax time.Time
	// field; a zero value means absent/unparseable, so keep any properties.log
	// time. MongoDB nests its timestamp as {"t":{"$date":...}}.
	if !f.Time.IsZero() {
		result.Time = f.Time
	} else if !f.MongoTime.Date.IsZero() {
		result.Time = f.MongoTime.Date
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
		var nested Result
		ParseInto(p.Log, &nested)
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
	v, err := strconv.ParseInt(string(n), 10, 64)
	return v, err == nil
}

// mergeNested lifts the fields extracted from an embedded log line (a Docker
// json-file "log" string or an Azure properties.log payload) into the result.
// The caller applies the enclosing envelope's own values afterwards, so an
// authoritative top-level scalar still wins over a lifted one.
func (result *Result) mergeNested(nested *Result) {
	if !nested.Time.IsZero() {
		result.Time = nested.Time
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

	if grpc, ok := jsonInt(f.GrpcStatusNumber); ok && grpc <= 16 {
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
		result.ResourceGroup = resourceGroup(result.ResourceID)
	}
	setIfSet(&result.EventCategory, f.EventCategory)
	setIfSet(&result.Version, f.Version)
	setIfSet(&result.Service, f.Service)
	setIfSet(&result.Product, f.Product)

	// @x carries type, message and stack trace in one payload; the ECS/OTel
	// spellings carry them apart and are authoritative when present.
	if f.Exception != "" {
		result.parseException(f.Exception)
	}
	setIfSet(&result.ExceptionType, f.ErrorType)
	setIfSet(&result.ExceptionMessage, f.ErrorMessage)
	setIfSet(&result.ExceptionStackTrace, f.ErrorStack)
}

// lower is strings.ToLower without its unconditional allocation: an Azure
// resource ID that is already lowercase (many are) is returned as is, aliasing
// the input like every other extracted field.
func lower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' || c >= utf8.RuneSelf {
			return strings.ToLower(s)
		}
	}
	return s
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

// enrichFromPatterns fills the result from the first matching entry in the
// compiled line-parser table (nginx, klog, redis, tracebacks, ...) and
// reports whether any entry matched. A W3C traceparent anywhere in the line
// is extracted independently of the table.
func (result *Result) enrichFromPatterns(message string) bool {
	matched := false
	if message != "" {
		// One index picks the parsers this line's first byte can start, in
		// table (priority) order; the rest never run.
		for _, clp := range parsersByFirstByte[message[0]] {
			if clp.apply(result, message) {
				matched = true
				break
			}
		}
	}

	// traceparentRE requires "traceparent[:=]", so a line with neither ':'
	// nor '=' cannot match; both probes are SIMD byte scans, far cheaper than
	// the substring search on lines full of 't's.
	if strings.IndexByte(message, '=') >= 0 || strings.IndexByte(message, ':') >= 0 {
		if i := strings.Index(message, "traceparent"); i >= 0 {
			if m := traceparentRE.FindStringSubmatch(message[i:]); m != nil {
				if t, s := parseTraceparent(m[1]); t != "" {
					result.TraceID, result.SpanID = t, s
					matched = true
				}
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
		// "Exception in thread "main" java.lang.IllegalStateException" and the
		// like put words before the type; the type is the first of them.
		if space := strings.IndexByte(excType, ' '); space >= 0 {
			excType = excType[:space]
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

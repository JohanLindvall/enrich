package enrich

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
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
func validTraceID(s string) bool {
	if len(s) < 32 || len(s) > 36 {
		return false
	}
	hex := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isHex(c):
			hex++
		case c != '-':
			return false
		}
	}
	return hex == 32
}

// validSpanID reports whether s is a whole span ID: exactly 16 hex digits.
func validSpanID(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

var resourceGroupRE = regexp.MustCompile(`(?i)/subscriptions/[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}/resourcegroups/[^/]+`)
var traceparentRE = regexp.MustCompile(`^traceparent[:=]\s*"?([0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2})`)

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
	var level, traceID, spanID string

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
		case "traceid", "traceID", "TraceId", "TraceID", "trace_id":
			if traceID == "" {
				traceID = sval
			}
		case "spanid", "spanID", "SpanId", "SpanID", "span_id":
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

	// Normalize the severity text; keep a finer-grained severity number (e.g.
	// syslog notice -> INFO2) when the parser already set one.
	sev, no := SeverityFromText(result.Severity)
	result.Severity = sev
	if result.SeverityNumber == 0 || sev == "" {
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
		if err := hr.UnmarshalJSON([]byte(p.Response)); err == nil {
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
func (result *Result) mergeNested(nested *Result) {
	if !nested.Time.IsZero() {
		result.Time = nested.Time
	}
	if nested.Severity != "" {
		result.Severity = nested.Severity
	}
	if nested.TraceID != "" {
		result.TraceID = nested.TraceID
	}
	if nested.SpanID != "" {
		result.SpanID = nested.SpanID
	}
}

// applySeverityHints resolves the severity from the textual level field and,
// failing that, from MongoDB's single-letter "s" or a gRPC status number
// (0 → info, other valid codes → warn).
func (result *Result) applySeverityHints(f *enrichFields) {
	// Severity from a textual level/severity field; numeric levels (e.g. Pino's
	// "level":30) are skipped by the lax tag, leaving the last textual value.
	if result.Severity == "" && f.Severity != "" {
		if s, _ := SeverityFromText(f.Severity); s != "" {
			result.Severity = s
		}
	}

	if result.Severity == "" && f.MongoSeverity != "" && !f.MongoTime.Date.IsZero() {
		if s, _ := SeverityFromText(f.MongoSeverity); s != "" {
			result.Severity = s
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

// applyMetadata copies the identifier and structured-log fields: validated
// trace/span IDs, Serilog context fields, Azure resource metadata, and the
// exception payload.
func (result *Result) applyMetadata(f *enrichFields) {
	if validTraceID(f.TraceID) {
		result.TraceID = removeDashesASCII(f.TraceID)
	}
	if validSpanID(f.SpanID) {
		result.SpanID = f.SpanID
	}
	result.SourceContext = f.SourceContext
	result.TemplateHash = f.TemplateHash
	result.Template = f.Template
	if f.ResourceID != "" {
		result.ResourceID = strings.ToLower(f.ResourceID)
		if match := resourceGroupRE.FindStringSubmatch(result.ResourceID); len(match) != 0 {
			result.ResourceGroup = match[0]
		}
	}
	result.EventCategory = f.EventCategory
	result.Version = f.Version
	result.Service = f.Service
	result.Product = f.Product
	if f.Exception != "" {
		result.parseException(f.Exception)
	}
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
	if code == 0 {
		if f.Protocol == "" {
			result.Severity = InfoLevel
			return
		}
		if strings.EqualFold(f.ResponseFlags, "DR") || strings.EqualFold(f.ResponseFlags, "DC") {
			result.Severity = WarnLevel
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

func (result *Result) parseException(exception string) {
	lines := strings.SplitN(exception, "\n", 2)
	typeAndMessage := strings.SplitN(lines[0], ": ", 2)
	if len(typeAndMessage) == 2 {
		result.ExceptionType = strings.Split(typeAndMessage[0], " ")[0]
		result.ExceptionMessage = typeAndMessage[1]
	} else {
		result.ExceptionMessage = lines[0]
	}

	if len(lines) > 1 {
		result.ExceptionStackTrace = lines[1]
	}
}

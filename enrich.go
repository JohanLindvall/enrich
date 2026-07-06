package enrich

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/JohanLindvall/logfmt"
)

var traceIDRE = regexp.MustCompile(`(?i)[a-f0-9]{8}-?([a-f0-9]{4}-?){3}[a-f0-9]{12}`) // Relaxed to allow dashes from Envoy request ID
var spanIDRE = regexp.MustCompile(`(?i)[a-f0-9]{16}`)
var resourceGroupRE = regexp.MustCompile(`(?i)/subscriptions/[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}/resourcegroups/[^/]+`)

// Result holds the metadata extracted from a log line.
type Result struct {
	// Body is the original input line, unmodified.
	Body string

	// Time is the timestamp parsed from the line; zero when none was found.
	Time time.Time

	// Severity is the normalized level (trace/debug/info/warn/error/fatal, see
	// NormalizeSeverity) and SeverityNumber its numeric equivalent.
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

// parseLogFmt scans a logfmt line for a timestamp (key t/ts/time/timestamp) and a
// severity (key level), using the logfmt key/value reader instead of a regex. It
// returns the parsed time, the chosen level value, and whether the line is a
// logfmt line worth using — true when either a timestamp parsed or a non-empty
// level was seen. A zero time is returned for the level-only case.
//
// The first parseable timestamp wins. For the level, a value that normalizes to a
// known severity wins over an earlier non-normalizing one (e.g. the inner
// "level=a@1 level=info" keeps "info").
func parseLogFmt(message string) (time.Time, string, bool) {
	if strings.IndexByte(message, '=') < 0 {
		return time.Time{}, "", false
	}

	var ts time.Time
	var tsFound, levelGood bool
	var level string

	// message is immutable; alias its bytes rather than copying.
	buf := unsafe.Slice(unsafe.StringData(message), len(message))
	_ = logfmt.Iterate(buf, func(key, val []byte) bool {
		switch string(key) {
		case "t", "ts", "time", "timestamp":
			if !tsFound {
				if t, ok := logfmt.ParseTime(string(val)); ok {
					ts, tsFound = t, true
				}
			}
		case "level":
			if !levelGood {
				s := string(val)
				if sev, _ := NormalizeSeverity(s); sev != "" {
					level, levelGood = s, true
				} else if level == "" {
					level = s
				}
			}
		}
		return !levelGood || !tsFound
	})

	return ts, level, tsFound || level != ""
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
	result := Result{Body: input}
	message := removeANSICodes(input)

	// The decoder only reads messageBytes (nocopy fields alias it), so alias the
	// immutable string instead of copying it.
	messageBytes := unsafe.Slice(unsafe.StringData(message), len(message))

	var f enrichFields
	if err := f.UnmarshalJSON(messageBytes); err == nil {
		result.enrichFromJSON(&f)
	} else if ts, sev, ok := parseLogFmt(message); ok {
		// logfmt line: take the time and/or level from the parsed key/value pairs.
		// The time is zero for a level-only line.
		result.Time = ts
		result.Severity = sev
	} else {
		result.enrichFromPatterns(message)
	}

	result.Severity, result.SeverityNumber = NormalizeSeverity(result.Severity)

	return &result
}

// enrichFromJSON fills the result from a successfully decoded JSON log line.
func (result *Result) enrichFromJSON(f *enrichFields) {
	// Nested objects first, so authoritative top-level scalars (notably the
	// Azure diagnostic-log "time") win over values lifted from properties.log.
	responseCode := result.applyProperties(&f.Properties)

	if f.ResponseStatus.Code != nil {
		setHTTPResponseCode(result, *f.ResponseStatus.Code, true)
	}

	// Timestamp (RFC3339 string or numeric epoch) decoded by the lax time.Time
	// field; a zero value means absent/unparseable, so keep any properties.log time.
	if !f.Time.IsZero() {
		result.Time = f.Time
	}

	result.applySeverityHints(f)
	result.applyMetadata(f)

	if f.ResponseCode != nil {
		responseCode = f.ResponseCode
	}
	result.applyResponseCode(f, responseCode)
}

// applyProperties handles the Azure diagnostic-log "properties" envelope: a
// nested log line (enriched recursively), a JSON-as-string HTTP response, or
// a plain status code. The plain code is returned instead of applied so a
// top-level response_code can take precedence.
func (result *Result) applyProperties(p *enrichProperties) *int64 {
	switch {
	case p.Log != "":
		nested := Parse(p.Log)
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
	case p.Response != "":
		var hr httpResponse
		if err := hr.UnmarshalJSON([]byte(p.Response)); err == nil && hr.StatusCode != nil {
			setHTTPResponseCode(result, *hr.StatusCode, true)
		}
	case p.HTTPStatusCode != nil:
		return p.HTTPStatusCode
	}
	return nil
}

// applySeverityHints resolves the severity from the textual level field and,
// failing that, from a gRPC status number (0 → info, other valid codes → warn).
func (result *Result) applySeverityHints(f *enrichFields) {
	// Severity from a textual level/severity field; numeric levels (e.g. Pino's
	// "level":30) are skipped by the lax tag, leaving the last textual value.
	if result.Severity == "" && f.Severity != "" {
		if s, _ := NormalizeSeverity(f.Severity); s != "" {
			result.Severity = s
		}
	}

	if f.GrpcStatusNumber != nil && *f.GrpcStatusNumber <= 16 {
		if result.Severity == "" || result.Severity == "info" {
			if *f.GrpcStatusNumber == 0 {
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
	if f.TraceID != "" && traceIDRE.MatchString(f.TraceID) {
		result.TraceID = removeDashesASCII(f.TraceID)
	}
	if f.SpanID != "" && spanIDRE.MatchString(f.SpanID) {
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
func (result *Result) applyResponseCode(f *enrichFields, responseCode *int64) {
	if f.ResultType == "HttpStatusCode" && f.ResultDescription != "" {
		if code, err := strconv.ParseInt(f.ResultDescription, 10, 64); err == nil {
			setHTTPResponseCode(result, code, false)
		}
	}

	if responseCode == nil {
		return
	}
	if *responseCode == 0 {
		if f.Protocol == "" {
			result.Severity = InfoLevel
			return
		}
		if strings.EqualFold(f.ResponseFlags, "DR") || strings.EqualFold(f.ResponseFlags, "DC") {
			result.Severity = WarnLevel
			return
		}
	}
	setHTTPResponseCode(result, *responseCode, false)
}

// enrichFromPatterns fills the result from the first matching entry in the
// compiled line-parser table (nginx, klog, redis, tracebacks, ...).
func (result *Result) enrichFromPatterns(message string) {
	for _, clp := range compiledLineParsers {
		if clp.apply(result, message) {
			break
		}
	}
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

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

// Enriched holds the metadata extracted from a log line.
type Enriched struct {
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

// Enrich extracts metadata from a log message.
//
// The result shares memory with input: Body is input itself, and the string
// fields populated from a JSON line (TraceID, SourceContext, Template, ...) alias
// input's backing array rather than copying it. Go strings are immutable, so this
// is safe, but it means input is kept alive for as long as the returned *Enriched
// (or any string copied out of it) is reachable. Callers holding many Enriched
// results therefore retain the corresponding input strings; copy the fields you
// need if you want the large input buffers to be collected sooner.
func Enrich(input string) *Enriched {
	result := Enriched{Body: input}
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
func (result *Enriched) enrichFromJSON(f *enrichFields) {
	var responseCode *int64

	// Nested objects first, so authoritative top-level scalars (notably the
	// Azure diagnostic-log "time") win over values lifted from properties.log.
	if f.Properties.Log != "" {
		if enriched := Enrich(f.Properties.Log); enriched != nil {
			if !enriched.Time.IsZero() {
				result.Time = enriched.Time
			}
			if enriched.Severity != "" {
				result.Severity = enriched.Severity
			}
			if enriched.TraceID != "" {
				result.TraceID = enriched.TraceID
			}
			if enriched.SpanID != "" {
				result.SpanID = enriched.SpanID
			}
		}
	} else if f.Properties.Response != "" {
		var hr httpResponse
		if err := hr.UnmarshalJSON([]byte(f.Properties.Response)); err == nil && hr.StatusCode != nil {
			setHTTPResponseCode(result, *hr.StatusCode, true)
		}
	} else if f.Properties.HTTPStatusCode != nil {
		responseCode = f.Properties.HTTPStatusCode
	}

	if f.ResponseStatus.Code != nil {
		setHTTPResponseCode(result, *f.ResponseStatus.Code, true)
	}

	// Timestamp (RFC3339 string or numeric epoch) decoded by the lax time.Time
	// field; a zero value means absent/unparseable, so keep any properties.log time.
	if !f.Time.IsZero() {
		result.Time = f.Time
	}

	// Severity from a textual level/severity field; numeric levels (e.g. Pino's
	// "level":30) are skipped by the lax tag, leaving the last textual value.
	if result.Severity == "" && f.Severity != "" {
		if s, _ := NormalizeSeverity(f.Severity); s != "" {
			result.Severity = s
		}
	}

	if f.GrpcStatusNumber != nil {
		if code := *f.GrpcStatusNumber; code <= 16 {
			if result.Severity == "" || result.Severity == "info" {
				if code == 0 {
					result.Severity = InfoLevel
				} else {
					result.Severity = WarnLevel
				}
			}
		}
	}

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

	// A resultType/resultDescription pair carries an HTTP status code.
	if f.ResultType == "HttpStatusCode" && f.ResultDescription != "" {
		if code, err := strconv.ParseInt(f.ResultDescription, 10, 64); err == nil {
			setHTTPResponseCode(result, code, false)
		}
	}

	if f.ResponseCode != nil {
		responseCode = f.ResponseCode
	}

	setResponseCode := true

	if responseCode != nil && *responseCode == 0 {
		if f.Protocol == "" {
			result.Severity = InfoLevel
			setResponseCode = false
		} else if strings.EqualFold(f.ResponseFlags, "DR") || strings.EqualFold(f.ResponseFlags, "DC") {
			result.Severity = WarnLevel
			setResponseCode = false
		}
	}

	if setResponseCode && responseCode != nil {
		setHTTPResponseCode(result, *responseCode, false)
	}
}

// enrichFromPatterns fills the result from the first matching entry in the
// compiled line-parser table (nginx, klog, redis, tracebacks, ...).
func (result *Enriched) enrichFromPatterns(message string) {
	for _, clp := range compiledLineParsers {
		if clp.apply(result, message) {
			break
		}
	}
}

func (result *Enriched) parseException(exception string) {
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

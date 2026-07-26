package enrich

import (
	"encoding/json"
	"time"
)

// enrichFields lists the top-level JSON object keys that Parse inspects. The
// lightning generator turns this into a fast, allocation-light UnmarshalJSON
// (see fields_unmarshal.go); regenerate with `go run
// github.com/JohanLindvall/lightning fields.go`.
//
// Several logical fields accept more than one spelling, expressed with
// lightning's pipe-separated aliases (`json:"a|b|c"`). This replaces the
// previous case-insensitive (EqualFold) key matching with an explicit set of
// accepted spellings.
//
// Fields are concretely typed wherever the JSON type is stable. Numeric codes
// are json.Number rather than *int64: a pointer would make the generated
// decoder heap-allocate the pointee once per line per field, whereas a nocopy
// json.Number aliases the input. An empty json.Number means the key was absent,
// which is what tells a real "response_code": 0 apart from no code at all (see
// jsonInt). Protocol stays a plain string since a present protocol is never
// empty. The "lax" tag option makes a value of an unexpected JSON type a
// no-op (the field is left at its zero value and the rest of the object still
// decodes), reproducing the type-tolerance of the old jsonparser.ObjectEach loop.
//
// Time varies in type between producers (an RFC3339 string or a numeric epoch).
// A lax time.Time covers both: lightning's ReadTimeLaxOrNull accepts an RFC3339
// string (with 'T' or space separator) or a Unix timestamp in seconds, millis,
// or micros, and leaves the field zero for anything it cannot interpret.
//
// nocopy makes the string/raw fields alias the input buffer, which Parse keeps
// alive while the result is in use.
type enrichFields struct {
	Time time.Time `json:"@t|@timestamp|timestamp|Timestamp|ts|time|Time,nocopy,lax"`

	// level folds into Severity: a numeric level (e.g. Pino's "level":30) is
	// skipped by lax, so the field keeps the last textual value. It is listed last
	// so that, among textual values, a level present later in the object wins.
	// Capital "Level" is deliberately excluded: Serilog emits severity as @l and
	// uses "Level" for a message property (e.g. "Level":"Domains"), which must not
	// clobber the real severity.
	Severity string `json:"severity|Severity|severityText|SeverityText|log.level|levelname|@l|@level|level,nocopy,lax"`
	// The OpenTelemetry SeverityNumber, carried by OTLP-JSON log records. It
	// only refines the level (notice being an info that outranks a plain one),
	// so a textual severity that disagrees with it wins; see applySeverityHints.
	SeverityNumber json.Number `json:"severityNumber|severity_number,nocopy,lax"`
	// Message is the rendered log message. Serilog's @m and @mt differ: @mt is
	// the template with holes, @m the filled-in text, and both are kept.
	Message       string `json:"@m|message|Message|MESSAGE|msg,nocopy,lax"`
	TraceID       string `json:"traceid|traceId|traceID|TraceId|TraceID|trace_id|trace.id|request_id,nocopy,lax"`
	SpanID        string `json:"spanid|spanId|spanID|SpanId|SpanID|span_id|span.id,nocopy,lax"`
	Traceparent   string `json:"traceparent|Traceparent|TraceParent,nocopy,lax"`
	SourceContext string `json:"sourcecontext|sourceContext|SourceContext|logger|loggerName|logger_name,nocopy,lax"`
	TemplateHash  string `json:"@i,nocopy,lax"`
	Template      string `json:"@mt,nocopy,lax"`
	ResourceID    string `json:"resourceID|resourceId|ResourceId|resourceUri|resourceURI,nocopy,lax"`
	EventCategory string `json:"eventCategory|eventcategory|EventCategory,nocopy,lax"`
	Version       string `json:"@sv|service.version,nocopy,lax"`
	Service       string `json:"@sn|service.name,nocopy,lax"`
	Product       string `json:"@sp,nocopy,lax"`
	// Exception is a whole exception payload (type, message and stack trace in
	// one string), split by parseException. The ECS/OTel semantic-convention
	// spellings carry the same information pre-split, in Error* below.
	Exception    string `json:"@x|exception,nocopy,lax"`
	ErrorType    string `json:"error.type|exception.type,nocopy,lax"`
	ErrorMessage string `json:"error.message|exception.message,nocopy,lax"`
	ErrorStack   string `json:"error.stack_trace|exception.stacktrace,nocopy,lax"`

	ResultType        string `json:"resultType,nocopy,lax"`
	ResultDescription string `json:"resultDescription,nocopy,lax"`

	// Docker json-file (and fluent-bit) records carry the original line in a
	// top-level "log" string; it is enriched recursively like properties.log.
	Log string `json:"log,nocopy,lax"`

	// MongoDB structured logs (4.4+) nest the timestamp as {"t":{"$date":...}}
	// and carry a single-letter severity (I/W/E/F/D1-D5) in "s".
	MongoTime     mongoDate `json:"t,nocopy,lax"`
	MongoSeverity string    `json:"s,nocopy,lax"`

	ResponseCode     json.Number `json:"response_code|responseCode|status_code|statusCode|StatusCode|http.response.status_code,nocopy,lax"`
	GrpcStatusNumber json.Number `json:"grpc_status_number,nocopy,lax"`
	Protocol         string      `json:"protocol,nocopy,lax"`
	ResponseFlags    string      `json:"response_flags,nocopy,lax"`

	Properties     enrichProperties     `json:"properties|Properties,nocopy,lax"`
	ResponseStatus enrichResponseStatus `json:"responseStatus|ResponseStatus,nocopy,lax"`
}

// enrichProperties is the Azure diagnostic-log "properties" envelope. Log and
// Response carry JSON encoded as a string, decoded in turn (Response via
// httpResponse); HTTPStatusCode is a plain number. The whole field is lax, so a
// non-object "properties" value is ignored.
type enrichProperties struct {
	Log            string      `json:"log,nocopy,lax"`
	Response       string      `json:"response,nocopy,lax"`
	HTTPStatusCode json.Number `json:"httpStatusCode,nocopy,lax"`
}

// enrichResponseStatus is the "responseStatus" envelope carrying an HTTP code.
type enrichResponseStatus struct {
	Code json.Number `json:"code,nocopy,lax"`
}

// mongoDate is MongoDB's extended-JSON date envelope ({"$date": "..."}).
type mongoDate struct {
	Date time.Time `json:"$date,nocopy,lax"`
}

// httpResponse decodes the small JSON document carried as a string in
// properties.response.
type httpResponse struct {
	StatusCode json.Number `json:"statusCode,nocopy,lax"`
}

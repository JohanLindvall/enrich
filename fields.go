package enrich

import "time"

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
// Fields are concretely typed wherever the JSON type is stable. The *int64
// fields are pointers so a present 0 (a real response/grpc code) is told apart
// from an absent key; Protocol stays a plain string since a present protocol is
// never empty. The "lax" tag option makes a value of an unexpected JSON type a
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
	Severity      string `json:"severity|Severity|@l|@level|level,nocopy,lax"`
	TraceID       string `json:"traceid|traceID|TraceId|TraceID|trace_id|request_id,nocopy,lax"`
	SpanID        string `json:"spanid|spanID|SpanId|SpanID|span_id,nocopy,lax"`
	SourceContext string `json:"sourcecontext|sourceContext|SourceContext,nocopy,lax"`
	TemplateHash  string `json:"@i,nocopy,lax"`
	Template      string `json:"@mt,nocopy,lax"`
	ResourceID    string `json:"resourceID|resourceId|ResourceId|resourceUri|resourceURI,nocopy,lax"`
	EventCategory string `json:"eventCategory|eventcategory|EventCategory,nocopy,lax"`
	Version       string `json:"@sv,nocopy,lax"`
	Service       string `json:"@sn,nocopy,lax"`
	Product       string `json:"@sp,nocopy,lax"`
	Exception     string `json:"@x,nocopy,lax"`

	ResultType        string `json:"resultType,nocopy,lax"`
	ResultDescription string `json:"resultDescription,nocopy,lax"`

	// Docker json-file (and fluent-bit) records carry the original line in a
	// top-level "log" string; it is enriched recursively like properties.log.
	Log string `json:"log,nocopy,lax"`

	// MongoDB structured logs (4.4+) nest the timestamp as {"t":{"$date":...}}
	// and carry a single-letter severity (I/W/E/F/D1-D5) in "s".
	MongoTime     mongoDate `json:"t,nocopy,lax"`
	MongoSeverity string    `json:"s,nocopy,lax"`

	ResponseCode     *int64 `json:"response_code|responseCode|statusCode|StatusCode,nocopy,lax"`
	GrpcStatusNumber *int64 `json:"grpc_status_number,nocopy,lax"`
	Protocol         string `json:"protocol,nocopy,lax"`
	ResponseFlags    string `json:"response_flags,nocopy,lax"`

	Properties     enrichProperties     `json:"properties|Properties,nocopy,lax"`
	ResponseStatus enrichResponseStatus `json:"responseStatus|ResponseStatus,nocopy,lax"`
}

// enrichProperties is the Azure diagnostic-log "properties" envelope. Log and
// Response carry JSON encoded as a string, decoded in turn (Response via
// httpResponse); HTTPStatusCode is a plain number. The whole field is lax, so a
// non-object "properties" value is ignored.
type enrichProperties struct {
	Log            string `json:"log,nocopy,lax"`
	Response       string `json:"response,nocopy,lax"`
	HTTPStatusCode *int64 `json:"httpStatusCode,nocopy,lax"`
}

// enrichResponseStatus is the "responseStatus" envelope carrying an HTTP code.
type enrichResponseStatus struct {
	Code *int64 `json:"code,nocopy,lax"`
}

// mongoDate is MongoDB's extended-JSON date envelope ({"$date": "..."}).
type mongoDate struct {
	Date time.Time `json:"$date,nocopy,lax"`
}

// httpResponse decodes the small JSON document carried as a string in
// properties.response.
type httpResponse struct {
	StatusCode *int64 `json:"statusCode,nocopy,lax"`
}

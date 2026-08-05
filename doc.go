// Package enrich extracts metadata from log lines: the timestamp, a
// normalized severity, the message, trace/span identifiers, an HTTP status
// code, structured-log fields (message template, source context,
// service/version/product), Azure resource metadata, and exception details.
//
// # Parsing
//
// Parse is the entry point. It tries three strategies in order and stops at
// the first that applies:
//
//  1. JSON: the line is decoded with a generated, allocation-light decoder
//     that recognizes the common key spellings for each logical field
//     (e.g. @t/@timestamp/timestamp/ts/time for the timestamp, @m/message/msg
//     for the message, Serilog's @l/@mt/@x, Envoy's
//     response_code/response_flags, Elastic Common Schema's dotted keys
//     (log.level, trace.id, service.name, error.type, ...), OTLP-JSON's
//     severityNumber/severityText, Azure diagnostic-log envelopes with nested
//     properties.log payloads, Docker json-file records, MongoDB structured
//     logs, and Pino/Bunyan numeric levels).
//  2. logfmt: a key/value scan picks up t/ts/time/timestamp, level, msg, and
//     trace correlation IDs (trace_id/span_id spellings and W3C
//     traceparent).
//  3. Pattern table: a list of regular expressions covering common plain-text
//     formats — nginx/Apache access and error logs, klog, redis, syslog
//     (RFC3164, RFC5424, and librdkafka's <N>| prefix), AWS Lambda, Spring
//     Boot, Python logging, Go panics, .NET unhandled exceptions, Python
//     tracebacks, and Java exceptions.
//
// Result.Format reports which strategy matched (FormatJSON, FormatLogfmt,
// FormatPattern, or FormatNone), so callers can count enrichment hit rates
// and debug unparsed lines.
//
// A timestamp that carries no zone offset is interpreted as UTC, and every
// Result.Time is returned in UTC. Formats whose timestamp has no year (klog,
// syslog RFC3164) infer it from the clock.
//
// Result.TimeHasZone reports which of those two happened: true when the line's
// timestamp stated its own offset (an RFC3339 stamp, a numeric epoch, any
// zoned layout) and false when it carried only a wall clock that had to be
// read as UTC. A caller holding a second, unambiguous timestamp — a container
// runtime's or a journal's ingest time — needs it to decide which is the
// better datum: a process running with TZ set to anything but UTC writes
// zone-less stamps displaced by exactly that zone's offset, and nothing in the
// line says so.
//
// # Severity
//
// Severities are normalized to trace, debug, info, warn, error, and fatal.
// SeverityFromText maps any spelling in the wild to a canonical level and its
// OpenTelemetry severity number; SeverityFromNumber is the inverse. HTTP
// response codes and gRPC status codes map to severities when the line
// carries no explicit level (see HTTPStatusSeverity and StatusKind).
//
// The OTLP severity numbers are finer-grained than the six level names, and
// that grading is preserved where a source provides it: syslog's notice (and
// the "notice" spelling) is an info with the Info2LevelNo number, its alert
// and emergency are fatals with Fatal2LevelNo and Fatal3LevelNo. Severity and
// SeverityNumber never contradict each other — SeverityFromNumber of the
// number is always the level in Severity.
//
// # Trace identifiers
//
// TraceID and SpanID are only set from a value that is a whole identifier: 32
// (16 for a span) hex digits, dashes permitted in a trace ID so that an Envoy
// request_id UUID is accepted and de-dashed. A field that merely contains an
// ID inside a longer sentence is not one, and neither is the all-zero ID that
// W3C trace-context defines as invalid and OpenTelemetry SDKs emit for a
// record with no active span.
//
// # Entry points
//
// Parse allocates a Result per line. ParseInto fills a caller-owned Result
// instead, and ParseBytes does the same for a []byte, skipping the copy that
// string(b) would make — a per-line pipeline should use one of those two, and
// then parsing is allocation-free.
//
// # Memory
//
// The result shares memory with the input: Result.Body is the input
// itself, and string fields populated from a JSON line alias the input's
// backing array rather than copying it. Go strings are immutable, so this is
// safe, but the input stays reachable for as long as the result (or any
// string taken from it) is. Copy the fields you need if you hold many
// results and want the large input strings collected sooner.
//
// The exceptions are values the input does not contain verbatim: a JSON
// string with escape sequences, an uppercase Azure resource ID (lowercased),
// and a dashed trace ID (de-dashed) are copies.
//
// The package holds no mutable state and is safe for concurrent use. It never
// logs: a line it cannot parse is reported through Result.Format (and a zero
// Result.Time), not written to a logger.
package enrich

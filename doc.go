// Package enrich extracts metadata from log lines: the timestamp, a
// normalized severity, trace/span identifiers, structured-log fields
// (message template, source context, service/version/product), Azure
// resource metadata, and .NET-style exception details.
//
// # Parsing
//
// Parse is the entry point. It tries three strategies in order and stops at
// the first that applies:
//
//  1. JSON: the line is decoded with a generated, allocation-light decoder
//     that recognizes the common key spellings for each logical field
//     (e.g. @t/@timestamp/timestamp/ts/time for the timestamp, Serilog's
//     @l/@m/@mt/@x, Envoy's response_code/response_flags, Azure
//     diagnostic-log envelopes with nested properties.log payloads, Docker
//     json-file records, MongoDB structured logs, and Pino/Bunyan numeric
//     levels).
//  2. logfmt: a key/value scan picks up t/ts/time/timestamp, level, and
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
// # Severity
//
// Severities are normalized to trace, debug, info, warn, error, and fatal.
// SeverityFromText maps any spelling in the wild to a canonical level and its
// OpenTelemetry severity number; SeverityFromNumber is the inverse. HTTP
// response codes and gRPC status codes map to severities when the line
// carries no explicit level (see HTTPStatusSeverity and StatusKind). Syslog's
// notice severity normalizes to info but keeps the finer-grained INFO2
// severity number (Info2LevelNo).
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
// The package holds no mutable state and is safe for concurrent use. It never
// logs: a line it cannot parse is reported through Result.Format (and a zero
// Result.Time), not written to a logger.
package enrich

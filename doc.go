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
//     diagnostic-log envelopes with nested properties.log payloads).
//  2. logfmt: a key/value scan picks up t/ts/time/timestamp and level.
//  3. Pattern table: a list of regular expressions covering common plain-text
//     formats — nginx and other access logs, klog, redis, syslog-prefixed
//     lines (librdkafka), Go panics, .NET unhandled exceptions, Python
//     tracebacks, and Java exceptions.
//
// # Severity
//
// Severities are normalized to trace, debug, info, warn, error, and fatal
// (see NormalizeSeverity and the level constants). HTTP response codes and
// gRPC status codes map to severities when the line carries no explicit
// level (see HTTPStatusSeverity).
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
// The package holds no per-call state and is safe for concurrent use.
package enrich

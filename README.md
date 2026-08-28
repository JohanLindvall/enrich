# enrich

[![Go Reference](https://pkg.go.dev/badge/github.com/JohanLindvall/enrich.svg)](https://pkg.go.dev/github.com/JohanLindvall/enrich)
[![CI](https://github.com/JohanLindvall/enrich/actions/workflows/ci.yml/badge.svg)](https://github.com/JohanLindvall/enrich/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/JohanLindvall/enrich)](https://goreportcard.com/report/github.com/JohanLindvall/enrich)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Extracts metadata from log lines in Go: timestamp, normalized severity, the
message, trace/span IDs, HTTP status code, structured-log fields, Azure
resource metadata, and exception details — from JSON, logfmt, and a wide range
of plain-text formats.

```go
e := enrich.Parse(`{"@t":"2021-09-01T12:00:00Z","@l":"Information","@m":"Hello, World!"}`)
fmt.Println(e.Time)     // 2021-09-01 12:00:00 +0000 UTC
fmt.Println(e.Severity) // info
fmt.Println(e.Message)  // Hello, World!
fmt.Println(e.Format)   // json
```

## Install

```sh
go get github.com/JohanLindvall/enrich
```

## What it recognizes

`Parse` tries three strategies in order and stops at the first that applies:

1. **JSON** — decoded with a generated, allocation-light decoder
   ([lightning](https://github.com/JohanLindvall/lightning)) that accepts the
   common key spellings per logical field: `@t`/`@timestamp`/`timestamp`/`ts`/`time`
   for the timestamp; `@m`/`message`/`msg` for the message; Serilog's `@l`,
   `@mt`, `@x`, `@i`, `@sn`, `@sv`, `@sp`; every capitalization of
   `traceId`/`spanId` plus `trace_id`/`span_id`, `traceparent` and Envoy's
   `request_id`; Elastic Common Schema's dotted keys (`log.level`, `trace.id`,
   `service.name`, `error.type`/`error.message`/`error.stack_trace`);
   OTLP-JSON's `severityNumber`/`severityText`; Envoy's `response_code` and
   `response_flags`; Azure diagnostic-log envelopes, including nested
   `properties.log` payloads that are themselves enriched recursively; Docker
   json-file records (the embedded `log` line is enriched recursively);
   MongoDB structured logs (`{"t":{"$date":…},"s":"I"}`); and Pino/Bunyan
   numeric levels (`"level":30`).
2. **logfmt** — a key/value scan
   ([logfmt](https://github.com/JohanLindvall/logfmt)) picks up
   `t`/`ts`/`time`/`timestamp`, `level`, `msg`/`message`, `logger`, and trace
   correlation IDs (`trace_id`/`span_id` spellings and W3C `traceparent`).
3. **Pattern table** — regular expressions covering common plain-text formats:
   nginx and Apache access/error logs, klog, redis, syslog (RFC3164, RFC5424,
   and librdkafka's `<N>|` prefix), AWS Lambda, Spring Boot, Python logging
   (both the `asctime - name - LEVEL` style and `basicConfig`'s
   `LEVEL:name:message` default), the .NET console formatter's
   `info: Category[0]` header, Azure DevOps and GitHub Actions agent lines,
   `date(1)`-stamped shell output, Go panics, .NET unhandled exceptions,
   Python tracebacks, and Java exceptions.

`Result.Format` reports which strategy matched (`json`, `logfmt`, `pattern`,
or empty for none), so callers can export enrichment hit-rate metrics and
debug unparsed lines.

## What it extracts

| Field | |
|---|---|
| `Body`, `Format` | the input line, and the strategy that parsed it |
| `Time` | always UTC; a timestamp with no offset is read as UTC, and a format with no year (klog, syslog RFC3164) infers it from the clock |
| `TimeHasZone` | whether the timestamp stated its own offset (RFC3339, an epoch, any layout carrying a numeric offset or a literal `UTC`/`GMT`) or was a bare wall clock read as UTC — what a caller holding a runtime's own ingest time needs to know before preferring the line's |
| `Severity`, `SeverityNumber` | normalized level and its OTLP severity number |
| `Message` | the message without its envelope (JSON/logfmt only — a plain-text line's message is not separable from `Body`) |
| `HTTPStatusCode` | the status code the line reports, 0 if none |
| `TraceID`, `SpanID` | whole identifiers only — see below |
| `Template`, `TemplateHash`, `SourceContext`, `Service`, `Version`, `Product` | structured-log context (`SourceContext` is the logger/category name: a JSON `logger`, a logfmt `logger=`, or the name a Python `basicConfig` or .NET console-formatter line carries) |
| `ResourceID`, `ResourceGroupID`, `EventCategory` | Azure resource metadata (`ResourceGroupID` is the group's own full ARM resource ID, not its bare name) |
| `ExceptionType`, `ExceptionMessage`, `ExceptionStackTrace` | from a Serilog `@x` payload, the ECS/OTel `error.*` keys, or a .NET unhandled-exception line |

A trace ID is only taken from a value that *is* one — 32 hex digits (16 for a
span), dashes permitted in a trace ID so an Envoy `request_id` UUID is
accepted and de-dashed. A field that merely contains an ID inside a sentence
is not one, and neither is the all-zero ID that W3C trace-context defines as
invalid and that OpenTelemetry SDKs emit for a record with no active span.

## Timestamps

`Time` is always UTC, but only some of the formats out there say what zone
their timestamp is in. RFC3339 stamps, numeric epochs and any layout carrying
an offset name an instant; klog's `MMDD hh:mm:ss`, syslog RFC3164's
`Mmm dd hh:mm:ss`, `2006-01-02 15:04:05` and the slash-date forms carry a bare
wall clock, which this package reads as UTC because nothing in the line says
otherwise. A process running with `TZ` set to anything else therefore produces
a `Time` displaced by exactly that zone's offset.

`TimeHasZone` reports which kind you got. It matters to callers that hold a
second timestamp they trust — a container runtime's or a journal's ingest time
— and have to decide which is the better datum: a zoned `Time` is an instant
and can be preferred however far apart the two are, while a zone-less one is a
wall clock in an unknown zone, and the ingest time is usually closer to the
truth than a stamp that may be hours out.

One shape gets there by an unusual route. A `date(1)` line names its zone as
an abbreviation, and Go's `MST` layout token resolves an abbreviation against
the *host's* zone database — `Wed Aug 26 22:26:14 CEST 2026` parses to
`20:26:14Z` where `TZ=Europe/Stockholm` and to `22:26:14Z` everywhere else, and
a name the host does not know silently becomes offset zero. So the entry does
not use that token: it accepts only `UTC` and `GMT`, matched as literal text.
That is offset zero on any host, and any other zone name is declined rather
than misread — which is what lets these lines count as zoned. A layout whose
only zone element *is* the `MST` token would not, and `layoutHasZone` says so.

## Severity

Severities normalize to `trace`, `debug`, `info`, `warn`, `error`, `fatal`.
`SeverityFromText` maps any spelling in the wild ("WRN", "Warning", "w",
"Information", Serilog's "VRB", syslog's "notice"/"alert"/"emerg",
java.util.logging's "SEVERE"/"FINE"/"FINEST", the .NET console formatter's
"trce"/"dbug"/"fail") to a canonical level plus its OpenTelemetry severity
number; `SeverityFromNumber` is the inverse.

The numbers give each level a range of four, which is where the grading the
six names flatten away is kept: syslog's *notice* is an info with
`Info2LevelNo`, its *alert* and *emergency* are fatals with `Fatal2LevelNo`
and `Fatal3LevelNo`, and an OTLP-JSON record's own `severityNumber` is taken
as given. `Severity` and `SeverityNumber` never contradict each other, whatever
order the signals in a line arrive in.

A short list of logger/message pairs is graded *down*. Some producers log a
condition at error level that nobody has to act on — a lookup that timed out
and will be retried on the next pass, an inconsistency the producer logs and
then recovers from. Those become `warn` with `Warn4LevelNo`, the top of the
warn range, so the line stays visible without paging anyone and a caller can
still tell a downgraded error from a warning the producer meant. This is the
only place the package overrides a level the line states outright, so the bar
is deliberately high: both the logger (`SourceContext`) and the message must
match whole, and a line whose logger is not on the list is left alone. See
`benignError` in `severity.go` for the current list and the reasoning behind
each entry.

When a line carries no explicit level, HTTP response codes and gRPC status
codes map to a severity (`HTTPStatusSeverity`): 1xx–3xx → info, 5xx → warn,
and 4xx depends on how the line reports it — `StatusObserved` (an access log,
→ warn) or `StatusFailure` (the code *is* the failure being reported, →
error). The code itself is kept in `HTTPStatusCode` either way. A JSON line
carrying an exception payload but no level is an error, like a Go panic or a
Python traceback.

## Memory model

The result shares memory with the input: `Result.Body` is the input itself,
and the extracted fields alias the input's backing array instead of copying.
This is what makes parsing allocation-free, at the cost of two rules:

- The input is kept alive as long as the result is reachable. Copy the fields
  you need if you hold many results over large lines.
- With `ParseBytes`, the input must not be modified while the result is in use
  — see the `bufio.Scanner` note under Benchmarks.

The package holds no mutable state, does not log, and is safe for concurrent
use.

## Development

```sh
make            # regenerate + format + tidy + lint + test
make test       # go test -cover
make lint       # golangci-lint
make bench      # run the benchmarks
make generate   # regenerate fields_unmarshal.go from fields.go
```

The JSON decoder in `fields_unmarshal.go` is generated from the field
definitions in `fields.go` by the lightning generator — edit `fields.go` and
run `make generate`; never edit the generated file by hand. CI verifies the
generated code is up to date, tests on amd64 and arm64, lints, and tags a new
patch version on every green main build.

## Benchmarks

```sh
go test -run='^$' -bench=. -benchmem .
```

On a Ryzen 7 8840HS (amd64): ~465 ns to enrich a ~900 B JSON Envoy
access-log line, ~570 ns for a ~1.9 kB logfmt line, ~232 ns for a plain-text
line resolved by the pattern table (the common Go-log and RFC3339 shapes are
decided by hand-written matchers, with no regex run; their timestamps parse
via per-layout hand parsers or the stdlib's dedicated RFC3339 fast path, so
no layout string is ever re-tokenized), ~705 ns for an Azure diagnostic record
with a nested `properties.log` payload, and ~197 ns for a 1 kB line that
matches nothing (the table is skipped almost entirely via first-byte
dispatch, positional gates, and memoized substring prefilters).

A line carrying ANSI colour codes — what a logger writes when it thinks it is
attached to a terminal — is stripped of them first, by a hand scan rather than
a regexp, so a coloured stream costs about the same as an uncoloured one.

Each of those figures includes one allocation: the 352-byte `Result`. The
parsing itself allocates nothing — JSON and logfmt values alias the input
rather than being copied — so reusing a `Result` runs the whole pipeline
**allocation-free**. For a caller that already holds `[]byte` (a
`bufio.Scanner`, a network buffer), `ParseBytes` also skips the line copy that
`string(b)` would make — 326 ns and 0 B/line, against 544 ns and 768 B for
`Parse(string(b))`:

```go
var r enrich.Result
for scanner.Scan() {
    enrich.ParseBytes(scanner.Bytes(), &r)
    emit(&r) // r's fields alias the scanner's buffer: consume before the next Scan
}
```

`ParseInto(scanner.Text(), &r)` is the safe alternative when the result must
outlive the line — `Text` copies, so the fields do not dangle.

## Alternatives

There is no other embeddable Go library that auto-detects the log format and
extracts timestamp, severity, and trace IDs in one zero-config call; that
functionality otherwise lives inside the big log pipeline tools:

- **[Grafana Loki's `detected_level`](https://grafana.com/docs/loki/latest/)**
  is the closest in spirit: at ingest it tries JSON, logfmt, and keyword
  scanning to attach a severity label. It handles levels only — no
  timestamps, traces, or exceptions — and its keyword scan is prone to
  picking severities out of message text
  ([grafana/loki#12645](https://github.com/grafana/loki/issues/12645),
  [#14443](https://github.com/grafana/loki/issues/14443),
  [#15444](https://github.com/grafana/loki/issues/15444)), which this
  package's table-driven parsers avoid.
- **[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)**
  (filelog receiver / Stanza operators) parses the same fields — its severity
  parser targets the same OTLP severity numbers used here — but every source
  needs explicit parser configuration; nothing auto-detects.
- **[Vector](https://vector.dev/)** ships `parse_json`, `parse_logfmt`,
  `parse_syslog`, `parse_apache_log`, `parse_klog`, ... as VRL functions, but
  you write a remap script per source, and it is a Rust daemon rather than a
  library.
- **Fluent Bit, Fluentd, Promtail/Alloy** pipeline stages: per-input parser
  configuration, same story.
- **Datadog's backend pipelines** auto-parse JSON and remap status/timestamp/
  trace attributes server-side (SaaS only); its per-pipeline parsing hit-rate
  view is what `Result.Format` lets you build.

Piecemeal Go libraries cover fragments of the job:
[araddon/dateparse](https://github.com/araddon/dateparse) auto-detects
timestamp formats (time only), grok ports like
[elastic/go-grok](https://github.com/elastic/go-grok) extract fields from
patterns you supply, and [go-logfmt](https://github.com/go-logfmt/logfmt) is
a parsing primitive. The standard Go logging libraries (slog, zap, logrus,
zerolog) are writers, not readers — none parse foreign logs.

## License

MIT — see [LICENSE](LICENSE).

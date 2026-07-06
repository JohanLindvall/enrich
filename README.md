# enrich

Extracts metadata from log lines in Go: timestamp, normalized severity,
trace/span IDs, structured-log fields, Azure resource metadata, and
.NET-style exception details — from JSON, logfmt, and a wide range of
plain-text formats.

```go
e := enrich.Parse(`{"@t":"2021-09-01T12:00:00Z","@l":"Information","@m":"Hello, World!"}`)
fmt.Println(e.Time)     // 2021-09-01 12:00:00 +0000 UTC
fmt.Println(e.Severity) // info
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
   for the timestamp; Serilog's `@l`, `@m`, `@mt`, `@x`, `@i`, `@sn`, `@sv`, `@sp`;
   `traceid`/`traceID`/`TraceId`/`trace_id`/`request_id`; Envoy's `response_code`
   and `response_flags`; Azure diagnostic-log envelopes, including nested
   `properties.log` payloads that are themselves enriched recursively; Docker
   json-file records (the embedded `log` line is enriched recursively);
   MongoDB structured logs (`{"t":{"$date":…},"s":"I"}`); and Pino/Bunyan
   numeric levels (`"level":30`).
2. **logfmt** — a key/value scan
   ([logfmt](https://github.com/JohanLindvall/logfmt)) picks up
   `t`/`ts`/`time`/`timestamp`, `level`, and trace correlation IDs
   (`trace_id`/`span_id` spellings and W3C `traceparent`).
3. **Pattern table** — regular expressions covering common plain-text formats:
   nginx and Apache access/error logs, klog, redis, syslog (RFC3164, RFC5424,
   and librdkafka's `<N>|` prefix), AWS Lambda, Spring Boot, Python logging,
   Go panics, .NET unhandled exceptions, Python tracebacks, and Java
   exceptions.

`Result.Format` reports which strategy matched (`json`, `logfmt`, `pattern`,
or empty for none), so callers can export enrichment hit-rate metrics and
debug unparsed lines.

## Severity

Severities normalize to `trace`, `debug`, `info`, `warn`, `error`, `fatal`
(`NormalizeSeverity`, with numeric equivalents and `SeverityText`). When a
line carries no explicit level, HTTP response codes and gRPC status codes map
to a severity (`HTTPStatusSeverity`): 1xx–3xx → info, 4xx/5xx → warn
(or error where the context indicates a failure).

## Memory model

The result shares memory with the input: `Result.Body` is the input string
itself, and fields populated from a JSON line alias the input's backing array
instead of copying. This keeps `Parse` fast (single-digit allocations per
line) but keeps the input alive as long as the result is reachable — copy the
fields you need if you hold many results.

The package holds no per-call state and is safe for concurrent use.

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

On a Ryzen 7 8840HS (amd64): ~840 ns and 3 allocations to enrich a ~900 B JSON
Envoy access-log line; ~770 ns and 2 allocations for a ~1.9 kB logfmt line.

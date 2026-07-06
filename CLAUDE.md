# CLAUDE.md — enrich

Log-line metadata extraction: timestamp, normalized severity, trace/span IDs,
structured-log fields, Azure resource metadata, exception details. Single
public entry point `Parse(input string) *Result`.

## Layout

- `doc.go` — package documentation.
- `enrich.go` — `Parse` itself and the `Result` result type. Dispatch
  order: generated JSON decode → logfmt scan (`parseLogFmt`) → regex pattern
  table (`enrichFromPatterns`). First strategy that applies wins.
- `fields.go` — the `enrichFields` struct listing the JSON keys `Parse`
  inspects, with lightning tag options (`a|b|c` key aliases, `nocopy`, `lax`).
- `fields_unmarshal.go` — **GENERATED** from `fields.go` by the lightning
  generator. Never edit by hand; edit `fields.go` and run `make generate`.
  CI fails if it is stale.
- `lineparser.go` — the regex pattern table for plain-text formats (nginx,
  Apache, klog, redis, syslog, Lambda, Spring Boot, tracebacks, ...) plus
  timestamp-layout parsing. `firstBytes` derives a first-byte prefilter from
  each pattern's anchored prefix — a new anchored shape needs a classifier
  case or it silently loses the cheap skip (the miss path is ~9x slower
  without it). Unanchored entries must carry a `contain` prefilter.
- `severity.go` — severity normalization, numeric levels, HTTP/gRPC/syslog/
  redis code-to-severity mapping.

## Invariants and gotchas

- **Results alias the input.** `Body` is the input string; JSON-populated
  string fields alias the input's backing array via `nocopy`/`unsafe.Slice`.
  Never mutate the byte views; anything returned to callers must be a string
  aliasing the immutable input or a copy.
- **JSON field order matters** in `enrichFromJSON`: nested `properties.log`
  is enriched first so authoritative top-level scalars (notably the Azure
  "time") win over lifted values. `level` is listed last in the Severity tag
  so a later textual value wins; capital `"Level"` is deliberately excluded
  (Serilog uses it for a message property, not severity).
- **`parseLogFmt` runs before the pattern table** and also handles the
  level-only case; the table's logfmt-ish entries only see lines without
  `=` pairs.
- **klog timestamps carry no year** — `expandKlogTime` infers it and adjusts
  across year boundaries; the corresponding test skips the year.
- **Envoy `response_code: 0`**: no `protocol` field → TCP proxying, info;
  `response_flags` DR/DC → client disconnect, warn.
- **Pino numeric levels** are handled by a raw-line scan (`pinoSeverity`),
  not the decoder: the "level" key must stay on the string Severity field
  (textual levels are far more common) and lightning rejects a key mapped to
  two fields.
- **Severity numbers can be finer-grained than the text**: syslog notice is
  info with SeverityNumber Info2 (10). Parse's final normalization keeps a
  pre-set number, so don't reset SeverityNumber after applySubmatch.
- **Test data is anonymized.** Log lines in tests use example.com/acme/base
  names, TEST-NET IPs (203.0.113.x), and all-zero dummy GUIDs. Keep it that
  way: never paste raw production log lines into tests — scrub domains,
  emails, GUIDs, tokens, public IPs, and user identifiers first.

## Commands

```sh
make            # fix (generate+gofmt+tidy) + lint + test
make test       # go test -cover ./...
make lint       # golangci-lint (config: .golangci.yml)
make bench      # benchmarks
make generate   # regenerate fields_unmarshal.go
go test -run='^$' -fuzz=FuzzParse -fuzztime=30s .   # fuzz Parse after parser changes
```

Local note: this machine has cgo disabled, so `-race` doesn't run here; CI
runs the race detector on amd64 and arm64.

## Lint

`.golangci.yml` excludes staticcheck SA5008 for `fields.go` only — it flags
lightning's `nocopy`/`lax` tag options as unknown. Don't widen the exclusion.

## Performance

`Parse` is on a hot path (one call per log line). Current numbers
(Ryzen 7 8840HS, amd64): ~840 ns / 3 allocs for a ~900 B JSON line, ~770 ns /
2 allocs for a ~1.9 kB logfmt line. The allocation budget comes from the
nocopy JSON decode and logfmt's zero-alloc iteration — keep new fields
`nocopy,lax` and avoid per-line allocations in new code paths. The pattern
table is ordered roughly most-common-first and each entry can carry a cheap
`contain` substring pre-filter — give new entries one whenever possible.

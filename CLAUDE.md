# CLAUDE.md — enrich

Log-line metadata extraction: timestamp, normalized severity, message,
trace/span IDs, HTTP status code, structured-log fields, Azure resource
metadata, exception details. Entry points: `Parse(string) *Result` (allocates
the Result), `ParseInto(string, *Result) bool` and `ParseBytes([]byte,
*Result) bool` (caller-owned Result; allocation-free).

## Layout

- `doc.go` — package documentation.
- `enrich.go` — `Parse` itself and the `Result` result type. Dispatch
  order: generated JSON decode → logfmt scan (`enrichFromLogFmt`) → regex
  pattern table (`enrichFromPatterns`). First strategy that applies wins;
  `Result.Format` records which one did.
- `fields.go` — the `enrichFields` struct listing the JSON keys `Parse`
  inspects, with lightning tag options (`a|b|c` key aliases, `nocopy`, `lax`).
- `fields_unmarshal.go` — **GENERATED** from `fields.go` by the lightning
  generator. Never edit by hand; edit `fields.go` and run `make generate`.
  CI fails if it is stale.
- `lineparser.go` — the regex pattern table for plain-text formats (nginx,
  Apache, klog, redis, syslog, Lambda, Spring Boot, tracebacks, ...) plus
  timestamp-layout parsing. `firstBytes` derives a first-byte prefilter from
  each pattern's anchored prefix, and `init` inverts those into
  `parsersByFirstByte[256]` — a line's first byte indexes straight to the
  parsers it can start (a lorem-ipsum miss tries 6 of 32), so **a new anchored
  shape needs a `firstBytes` case or it silently loses the skip**. Unanchored
  entries have no gate and land in every bucket, so they must carry a
  `contain` prefilter or a hand matcher that pre-decides their prefix (nginx
  has the matcher, everything else the needle).
  `posGates` derives the fixed-position byte requirements of an anchored
  timestamp prefix, and `compileGates` folds them into one masked word compare
  against `lineGates`' eight-byte window at offset 4 — `clp.passes` is then a
  single AND, run by the dispatch loop *before* it calls `apply`, so a
  wrong-family entry costs neither a call nor a look inside the parser.
  `compileGates` panics on a gate outside that window rather than quietly
  dropping it, and `TestGateWordsMatchPosGates` differential-tests the word
  form against the per-byte one. The gate windows are two `uint64` values, not
  an array: indexing an array by the entry's `quoted` flag made the compiler
  copy it to the stack on every iteration of the dispatch loop.
- `severity.go` — severity normalization, numeric levels, HTTP/gRPC/syslog/
  redis code-to-severity mapping. `severityLUT` **is** the normalizer, not a
  cache in front of one: the set of level spellings is finite, so every input
  is decided in O(1) (an unknown word used to cost ~330 ns walking 8 regexes;
  it now costs ~12 ns). The regexes live on in `severity_test.go` as an
  oracle, and a 500k-input randomized differential test pins the table to
  them — extend the table and that test together, **including
  `severityInitials`** (the one-byte prefilter: a spelling whose first letter
  is missing there is never looked up) and the sweep's alphabet. The map is
  the registry only: lookups go through `sevTable`, a perfect-hash array
  built from it in init — a new spelling that collides makes init panic with
  freshly searched replacement constants to paste in, so the two cannot
  drift.
- `hex.go` — SWAR byte-classification helpers (`le64`, `laneRange`, `hex8`,
  `hexRun`) behind `validTraceID`/`validSpanID`/`validGUID`, the ASCII fast
  path of `lower`, and `stampSkeleton`. Every formula is exact per lane (no
  cross-lane borrow), unlike the find-first-stop masks in the logfmt package;
  `hex_test.go` pins them to the per-byte originals.
- `timeparse.go` — per-layout-family timestamp parsers (the sanctioned
  replacement for `time.Parse`, which fast-paths only the literal
  RFC3339/RFC3339Nano layout constants and re-tokenizes every other layout
  per call). Contract: a parser may return `!ok` freely — the caller falls
  back to the old `time.Parse` path, so a miss cannot change behavior — but a
  claim must be byte-identical to what the family's layout loop produces.
  `timeparse_test.go` differential-tests each family against its own layouts
  *and* asserts the canonical shapes are claimed, so a fast path can neither
  drift nor silently rot into always-missing. `parseGoStringTime` (the Go
  `time.Time.String()` shape browser-telemetry logfmt carries) fronts
  `logfmt.ParseTime` the same way. Every family funnels through `utcStamp`,
  which converts a *validated* date straight to Unix seconds
  (`daysFromCivil`) instead of paying `time.Date`'s normalization and zone
  lookup; `TestUtcStampMatchesTimeDate` pins it to `time.Date` over every
  month end of years 0-9999, the leap-rule corners and a randomized sweep.
  `parseStamp19` gets its structural check from `stampSkeleton` — the same one
  the hand matchers use — so the fourteen digits are validated once, a word at
  a time, and the extraction re-validates nothing.
- `fastmatch.go` — hand matchers for the hottest pattern-table entries, the
  per-line `byteMemo`, and `indexAnchored`. A matcher returns a proven
  `fastNoMatch`/`fastMatched` (with capture spans) or `fastUndecided`, which
  falls through to the regex; `fastMatcherFor` keys matchers on the *exact*
  pattern string, so editing an entry detaches its matcher instead of
  desynchronizing it. `fastmatch_test.go` pins every matcher to its regex
  over the fuzz corpus plus mutation sweeps, and asserts each one both decides
  something and has its match side exercised — extend it when adding one. The
  memo dedupes whole-line `IndexByte` gate scans (each distinct byte scanned
  at most once per line) and is plain stack state, not a cache.
  `indexAnchored` is `strings.Index` anchored on a *rare* byte of the needle
  instead of its first: the package's needles lead with the commonest byte in
  their haystack (the 't' of "traceparent" in prose, the '"' of `"level":` in
  JSON), and `strings.Index` restarts an `IndexByte` at every one. It is only
  for short needles — long ones keep `strings.Contains`, whose Rabin-Karp
  fallback is the guard against hostile input.
- `testdata/fuzz/FuzzParse/` — the corpus the fuzzer accumulated. `go test`
  replays every entry as a seed, so it is a regression suite; add to it by
  running the fuzzer and copying new finds out of `$(go env GOCACHE)/fuzz`.

## Invariants and gotchas

- **Results alias the input.** `Body` is the input string; JSON-populated
  string fields alias the input's backing array via `nocopy`/`unsafe.Slice`.
  Never mutate the byte views; anything returned to callers must be a string
  aliasing the immutable input or a copy.
- **JSON field order matters** in `enrichFromJSON`: nested `properties.log`
  is enriched first so authoritative top-level scalars (notably the Azure
  "time") win over lifted values. `level` is listed last in the Severity tag
  so a later textual value wins; capital `"Level"` is deliberately excluded
  (Serilog uses it for a message property, not severity). Because
  `mergeNested` now lifts *every* field the embedded line carried, the
  envelope's own assignments in `applyMetadata` must stay conditional
  (`setIfSet`) — an unconditional `result.X = f.X` would clobber a lifted
  value with the envelope's empty one.
- **Severity and SeverityNumber must never contradict each other.** Anything
  in `Result` may set both, and a later signal may rename the level (a
  "notice" line that then reports a 500); `ParseInto`'s final step therefore
  drops a pre-set number whose `SeverityFromNumber` no longer matches the
  text. Don't push that check back into the individual parsers — it is
  exactly the invariant `FuzzParse` asserts on every input.
- **All-zero trace/span IDs are rejected** (`validTraceID`/`validSpanID`).
  They are W3C trace-context's "invalid" value, which OTel SDKs emit for a
  record with no active span; accepting them files every untraced line in a
  fleet under one trace.
- **`Result.Message` is JSON/logfmt only.** The pattern table captures no
  message — a plain-text line's message is not separable from `Body`. The
  logfmt scan stores `msg=` even when it does *not* claim the line, so a
  key=value line the table resolves (a Kubernetes event) still gets one.
- **`resourceGroupID` is a hand scan, not a regexp**, because every match form
  the regexp package offers allocates its result slice — that was one
  allocation on every Azure line, and the scan is also ~2x faster on the
  Azure benchmark. `enrich_test.go` keeps the original pattern as an oracle
  and differential-tests the scan against it, as `severity_test.go` does for
  the severity LUT.
- **`enrichFromLogFmt` runs before the pattern table** and also handles the
  level-only case; the table's logfmt-ish entries only see lines without
  `=` pairs. It scans the whole line (no early exit) so trace_id/span_id/
  traceparent keys are found wherever they appear. Its callback rejects a key
  it does not care about with one probe of `logfmtKeyGate`, which holds the
  *lengths* the keys starting with each byte come in — the first byte alone is
  a weak filter, since every `session_attr_*` key of a browser-telemetry line
  shares its 's' with the span-ID spellings. `logfmtKeys` is the single list
  the gate is built from and `TestLogfmtKeyGate` pins it against the switch in
  both directions, so a new case and a new spelling cannot drift apart.
- **klog timestamps carry no year** — `expandKlogTime` infers it and adjusts
  across year boundaries; the corresponding test skips the year.
- **`Result.TimeHasZone` says whether `Time` is an instant or a wall clock.**
  A zone-less layout is read as UTC because nothing else is possible, so a
  process with `TZ` set elsewhere emits stamps displaced by that offset — a
  caller holding a runtime's own ingest time has to be able to tell the two
  apart. Zonedness is a property of the **layout that claimed the value**, not
  of the table entry (the nginx entry offers `02/Jan/2006:15:04:05 -0700` *and*
  `02/Jan/2006 15:04:05`), which is why layouts are compiled into `tsLayout`
  pairs rather than a `[]string` beside a `[]bool`. `layoutHasZone` decides it
  by the reference-layout tokens (`Z07`/`-07`/`MST`) and
  `TestLayoutHasZoneMatchesRoundTrip` pins that to an oracle that formats one
  instant in two zones and parses both back — a new layout the token test reads
  wrong fails there. The JSON and logfmt paths assert `true` outright because
  neither dependency accepts a zone-less shape (lightning's lax time decoder
  wants RFC3339 or an epoch; `logfmt.ParseTime` wants RFC3339Nano, the
  `-0700 MST` form or an epoch); `TestJSONTimestampsAlwaysCarryAZone` and
  `TestLogfmtTimestampsAlwaysCarryAZone` fail if either widens. Every write to
  `Time` goes through `setTime`, so the two fields cannot drift apart — an
  embedded line's answer travels with its timestamp through `mergeNested`.
- **Envoy `response_code: 0`**: no `protocol` field → TCP proxying, info;
  `response_flags` DR/DC → client disconnect, warn.
- **Pino numeric levels** are handled by a raw-line scan (`pinoSeverity`),
  not the decoder: the "level" key must stay on the string Severity field
  (textual levels are far more common) and lightning rejects a key mapped to
  two fields.
- **Severity numbers can be finer-grained than the text**: the OTLP numbers
  give each level a range of four (`InfoLevelNo`..`Info4LevelNo`), so syslog
  notice is info with SeverityNumber Info2 (10). Parse's final normalization
  keeps a pre-set number, so don't reset SeverityNumber after applySubmatch.
- **Don't add a dynamic severity cache.** It cannot beat the LUT's ~20 ns on
  hits, it would need locking (the package has no mutable state today), and it
  would be keyed by attacker-influenced log content — an unbounded map that a
  flood of junk level tokens grows without limit.
- **The package never logs.** A library writing to the global slog is
  unconfigurable by its callers; an unparseable line is reported through
  `Result.Format` and a zero `Result.Time` instead. Don't reintroduce it.
- **`ParseInto` must fully reset the Result** (`*result = Result{Body: input}`)
  — callers reuse one across lines, so any field left behind leaks into the
  next line. Guarded by TestParseInto_ResetsResult. The reset is *only* in
  `ParseInto`: the shared body is `fillResult`, which assumes a Result holding
  nothing but its `Body`, and `Parse` and the two nested-line parses go
  straight there because their Result was just allocated (or declared) zeroed.
  Clearing eighteen string headers in a heap Result is a bulk write barrier,
  not a memset, so doing it twice was worth ~25 ns a line.
- **`removeANSICodes` strips by hand, with `ansiRe` kept as the oracle**
  (`TestRemoveANSICodesMatchesRegex`), the same arrangement as
  `resourceGroupID`. Handing a coloured line to `regexp.ReplaceAllString` cost
  ~1.1 µs and five allocations, several times the rest of Parse. The
  `IndexByte` guard in front of it is what keeps uncoloured lines free, and it
  runs on every line before any strategy: a colourised line has to be seen
  without its escapes by `looksLikeJSONObject`, by the logfmt tokenizer and by
  the pattern table alike, so this is not something to make lazy.
- **The traceparent scan is gated on length as well as bytes.** A match needs
  the key, a separator and the 55-byte value, so a line shorter than
  `minTraceparentLine` cannot carry one — which is most plain-text lines.
- **Every fast path is claim-or-fallback, pinned to an oracle.** The family
  timestamp parsers, the hand matchers, `scanTraceparent`, `lower`, the SWAR
  ID validators, `validGUID` and `jsonInt` each shadow a slower
  implementation that remains the oracle in a differential test
  (`timeparse_test.go`, `fastmatch_test.go`, `hex_test.go`, `micro_test.go`).
  A fast path may decline an input — the slow path then decides — but a
  claimed answer must be byte-identical to the oracle's. When you touch one,
  extend its differential test in the same commit; never delete an oracle.
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
(Ryzen 7 8840HS, amd64), with the result escaping as it does for a real
caller: ~465 ns / 1 alloc for a ~900 B JSON line, ~570 ns / 1 alloc for a
~1.9 kB logfmt line, ~232 ns / 1 alloc for a pattern-table line (Go-log or
RFC3339 shape alike), ~705 ns / 2 allocs for an Azure record with a nested
`properties.log`, ~197 ns / 1 alloc for a 1 kB line that matches nothing.
**That single alloc is the 352 B `Result` itself** — `ParseInto` with a
reused `Result` is fully zero-allocation (~327 ns), and is what a per-line
pipeline should call. (Same-machine-state deltas of the 2026-07 optimization
pass, measured interleaved: JSON −7%, logfmt −19%, pattern −67%, Azure −25%,
miss −14%, geomean −24%. Benchmark A/B on this laptop is only meaningful
interleaved on one machine state — the absolute numbers drift ~10% with
thermals.)

The absolute figures above predate the 2026-08 pass and are now conservative;
re-run `make bench` on that machine to refresh them. That pass was measured on
a Neoverse-N2 (arm64) by alternating two prebuilt test binaries, eight rounds
each: **pattern −20%, miss −9%, RFC3339 line −9%, logfmt −3%, JSON −2.5%,
dashed trace ID −2%, Azure unchanged; geomean −4%** over those. Separately,
a coloured console line — until then by far the slowest shape in the package,
because it went through `regexp.ReplaceAllString` — went from ~1280 ns and 6
allocations to ~195 ns and 1 (`BenchmarkParseColoured`).

`BenchmarkParseIntoReused` and `BenchmarkParseBytes` did not move at all, and
that is the honest summary of where the remaining time is: with the `Result`
allocation taken out of the picture, what is left of a JSON line is the
generated decoder, and of a logfmt line `logfmt.Iterate`. Nearly all of this
pass landed on the plain-text paths and on what `Parse` does around whichever
strategy runs.

**Adding a field to `Result` or `enrichFields` costs real time; adding a key
spelling to an existing field does not.** Measured: the ~20 extra aliases
(ECS dotted keys, `traceId`, `message`, ...) are free to within noise, while
the five new fields behind them plus the wider `Result` cost ~25 ns on the
JSON line (and pushed the `Result` from the 320 B size class to 352 B). Weigh
new fields accordingly; weigh new spellings barely at all.

The parsing work itself allocates nothing on the JSON and logfmt paths. What
does allocate is anything the input does not contain verbatim: an escaped
JSON string (the decoder must unescape), an uppercase Azure resource ID
(`lower` returns the input unchanged when it is already lowercase), a dashed
trace ID, and the `[]int` of a pattern-table match.

- **Never add a `*int64` (or other pointer) field to `enrichFields`.** The
  generated decoder heap-allocates the pointee, once per line per field. Use
  `json.Number` with `nocopy` instead: it aliases the input, and an empty
  value means the key was absent — which is the only reason the pointers
  existed. See `jsonInt`.
- **Never `string(val)` inside the logfmt callback.** The bytes alias the
  input and the input is immutable, so `unsafe.String` is free; a conversion
  copies the value on every line.
- A pattern-path entry only allocates when its regex actually runs: the
  `[]int` that `FindStringSubmatchIndex` returns scales with the
  capture-group count, which is why `nonCapturing` rewrites every unnamed
  group to `(?:`. Seven of the nine hand-matched entries (fastmatch.go) skip
  the regex and the alloc entirely on their shapes; the redis and nginx
  matchers only pre-decide the miss side, so genuine lines of those shapes
  still run their regex. Entries without a matcher always pay it, so keep new
  table entries free of unnamed capturing groups — and consider a matcher for
  a shape that will be hot.
- Trace/span IDs are validated by hand (`validTraceID`/`validSpanID`), not by
  regex — the old regexes cost ~40% of the JSON path on a line carrying a
  request_id. Same reasoning retired `resourceGroupRE`.
- **A string carried inside JSON is still the input's memory.** Decode it with
  `unsafe.Slice(unsafe.StringData(s), len(s))`, never `[]byte(s)` — the
  conversion copied `properties.response` on every Azure line.

The pattern table is ordered roughly most-common-first; every entry needs
either a `firstBytes` classifier match, a `contain` substring pre-filter or a
prefix matcher (see the lineparser.go note above) — the miss path regressed 9x
without them. What the miss path costs now is essentially the whole-line
`IndexByte` scans that prove those prefilters absent: ~40% of it, four scans
(the ANSI guard, `=`, `:`, `\n`) over a 1 kB line. Removing one is worth ~8%,
which is why the nginx entry got a matcher; there is no rare byte left to
merge the remaining four into.

Parse's own overhead is now small: profiling the JSON and logfmt paths shows
the time going to `logfmt.Iterate` and the generated lightning decoder, both
of which are already SIMD-optimized (they are ~65-75% of those paths — the
next real wins live in those modules, not here). Gating works: the common
plain-text shapes execute **zero** regexes (hand matchers decide them), other
lines 1-2, and a miss executes none.

## Rejected optimizations (measured; do not re-attempt without new evidence)

- **One generic hand-rolled timestamp parser** to replace `time.Parse`. A
  differential test immediately showed it accepting shapes the layouts
  reject (`2026/07/06T12:00:00`, slash dates with zone offsets, 6-digit
  fractions against a `.000` layout) — it passed the suite only because
  nothing captures those shapes *today*, which is exactly the danger. What
  ultimately landed (timeparse.go) is the remedy that note prescribed: one
  parser **per layout family**, each free to fall back to `time.Parse`, each
  differential-tested against its own layouts. Keep that discipline; do not
  collapse the families back into one parser.
- **Early-exit for `enrichFromLogFmt`.** It scans every line to the end because
  it cannot know that no `trace_id` is coming, and almost no line carries one.
  Pre-scanning with `strings.Contains` for "level="/"race"/"pan" to prove
  absence and stop early made the 1.9 kB logfmt benchmark **39% slower**: the
  three needles cost ~810 ns, against ~1016 ns for the whole parse. Needles
  starting with a common letter are ruinous here — Go's `Index` restarts
  `IndexByte` at every candidate, and 'l'/'r'/'p' are everywhere in log text
  (one *rare*-byte `IndexByte` over the same line costs 24 ns). There is no
  rare byte common to the trace-key spellings to gate on, so proving absence
  costs as much as parsing. The full scan is already the cheapest correct
  option.
- **Carrying the positional gate inline in the dispatch bucket** (a
  `{mask, want, window, *compiledLineParser}` struct per entry instead of a
  bare pointer). The idea was to spare a rejected entry the dependent load
  into the parser; measured **+5%** on the miss and pattern benchmarks
  instead, because 32-byte bucket entries move four times the memory through
  the loop and the parsers are allocated consecutively anyway. The gate lives
  on the parser; only the *test* is hoisted into the loop, which is where the
  win was.
- **A hand matcher for the http-echo entry**
  (`^ymdSlash(Z:)?\s([^\s]+\s){2}"...`). Stepping over its two space-separated
  tokens costs more than the memoized whole-line `"` probe it would replace —
  ~17 ns against ~8 ns on a 65-byte line. A prefix matcher only pays off when
  it replaces a scan the memo cannot share (nginx's `-`) or when it decides the
  match side too (the bracketed-level and Lambda entries). Weigh new matchers
  that way, not by "the regex is slow".
- **Shrinking `Result` into the 320-byte size class.** It is 336 bytes, so
  `Parse` allocates 352. Getting under 320 needs 16 bytes, and the only
  candidates are the two `int` fields; narrowing both to `int32` (an API break)
  saves 8 and lands at 328 — still the same size class. Not worth breaking the
  API for nothing.

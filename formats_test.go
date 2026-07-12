package enrich

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParse_Syslog_RFC5424(t *testing.T) {
	enriched := Parse(`<134>1 2026-07-06T12:00:00.123Z host app 1234 ID47 - An application event`)
	assert.Equal(t, "info", enriched.Severity) // 134&7 = 6
	assert.Equal(t, InfoLevelNo, enriched.SeverityNumber)
	assert.Equal(t, "2026-07-06 12:00:00.123 +0000 UTC", enriched.Time.String())
	assert.Equal(t, FormatPattern, enriched.Format)
}

func TestParse_Syslog_RFC3164(t *testing.T) {
	enriched := Parse(`<11>Jul  6 12:00:00 host app[42]: something failed`)
	assert.Equal(t, "error", enriched.Severity) // 11&7 = 3
	assert.Equal(t, "07-06 12:00:00", enriched.Time.Format("01-02 15:04:05"))
	assert.Equal(t, time.Now().UTC().Year(), enriched.Time.Year())
}

func TestParse_Syslog_Notice_Info2(t *testing.T) {
	// Syslog notice (severity 5) keeps the finer-grained OTLP INFO2 number.
	enriched := Parse(`<13>plain message without timestamp`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, Info2LevelNo, enriched.SeverityNumber)
}

func TestParse_Syslog_InvalidPri(t *testing.T) {
	// A priority above 191 is not valid syslog.
	enriched := Parse(`<999>not really syslog`)
	assert.Empty(t, enriched.Severity)
}

func TestParse_RFC3339_Offset(t *testing.T) {
	enriched := Parse(`2026-07-06T12:00:00.5+02:00 ERROR something broke`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2026-07-06 10:00:00.5 +0000 UTC", enriched.Time.String())
}

func TestParse_ApacheErrorLog(t *testing.T) {
	// Apache 2.4: microsecond timestamp and module:level.
	enriched := Parse(`[Thu Jun 27 11:55:44.569531 2024] [core:error] [pid 42:tid 140] AH00126: Invalid URI in request`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2024-06-27 11:55:44.569531 +0000 UTC", enriched.Time.String())

	// Apache 2.2: seconds and a bare level.
	enriched = Parse(`[Wed Oct 11 14:32:52 2000] [error] [client 203.0.113.1] client denied by server configuration`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2000-10-11 14:32:52 +0000 UTC", enriched.Time.String())
}

func TestParse_Lambda(t *testing.T) {
	enriched := Parse("2026-07-06T12:00:00.123Z\t00000000-0000-0000-0000-000000000001\tERROR\tsomething failed")
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2026-07-06 12:00:00.123 +0000 UTC", enriched.Time.String())
}

func TestParse_SpringBoot(t *testing.T) {
	// Spring Boot right-pads the level, so two spaces precede WARN.
	enriched := Parse(`2026-07-06 12:00:00.123  WARN 1 --- [main] c.e.ClientApp : Connection refused`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-07-06 12:00:00.123 +0000 UTC", enriched.Time.String())
}

func TestParse_PythonLogging(t *testing.T) {
	enriched := Parse(`2026-07-06 12:00:00,123 - app.web - WARNING - disk almost full`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-07-06 12:00:00.123 +0000 UTC", enriched.Time.String())
}

func TestParse_Log4jCommaMillis(t *testing.T) {
	enriched := Parse(`2026-07-06 12:00:00,123 INFO [main] com.example.App - started`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2026-07-06 12:00:00.123 +0000 UTC", enriched.Time.String())
}

func TestParse_PinoNumericLevel(t *testing.T) {
	enriched := Parse(`{"level":50,"time":1751805600000,"pid":7,"hostname":"web-1","msg":"connection refused"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, FormatJSON, enriched.Format)
	assert.Equal(t, "2025-07-06 12:40:00 +0000 UTC", enriched.Time.String())

	// A textual level on the same key still wins over the numeric fallback.
	enriched = Parse(`{"severity":"INFO","level":30,"msg":"x"}`)
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_MongoDB(t *testing.T) {
	enriched := Parse(`{"t":{"$date":"2026-06-27T09:19:42.778+00:00"},"s":"W","c":"COMMAND","id":51803,"ctx":"conn1","msg":"Slow query"}`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-06-27 09:19:42.778 +0000 UTC", enriched.Time.String())
}

func TestParse_DockerJSONFile(t *testing.T) {
	// The embedded line is enriched recursively; the top-level time wins.
	enriched := Parse(`{"log":"ERROR: connection refused\n","stream":"stderr","time":"2026-07-06T12:00:00Z"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_Logfmt_TraceIDs(t *testing.T) {
	enriched := Parse(`ts=2026-07-06T12:00:00Z level=info trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span_id=00f067aa0ba902b7 msg=x`)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)
	assert.Equal(t, FormatLogfmt, enriched.Format)
}

func TestParse_Logfmt_Traceparent(t *testing.T) {
	enriched := Parse(`level=info traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 msg=x`)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)
}

func TestParse_PlainText_Traceparent(t *testing.T) {
	enriched := Parse(`request handled traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)
	assert.Equal(t, FormatPattern, enriched.Format)
}

func TestParseTraceparent_Malformed(t *testing.T) {
	for _, v := range []string{
		"",
		"00-short-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-short-01",
		"no dashes at all",
		"00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
	} {
		traceID, spanID := parseTraceparent(v)
		assert.Empty(t, traceID, "value %q", v)
		assert.Empty(t, spanID, "value %q", v)
	}
}

func TestParse_JSON_TraceUnderscoreKeys(t *testing.T) {
	enriched := Parse(`{"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","msg":"x"}`)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)
}

func TestParse_Format(t *testing.T) {
	assert.Equal(t, FormatJSON, Parse(`{"level":"info"}`).Format)
	assert.Equal(t, FormatLogfmt, Parse(`level=info msg=x`).Format)
	assert.Equal(t, FormatPattern, Parse(`INFO: plain line`).Format)
	assert.Equal(t, FormatNone, Parse(`completely unparseable line`).Format)
}

func TestExpandStampTime(t *testing.T) {
	june := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "2026 Jun 15 12:00:00", expandStampTime("Jun 15 12:00:00", june))

	// A December timestamp seen in January belongs to the previous year.
	january := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "2025 Dec 31 23:59:59", expandStampTime("Dec 31 23:59:59", january))

	// A January timestamp seen in December belongs to the next year.
	december := time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, "2027 Jan  1 00:00:01", expandStampTime("Jan  1 00:00:01", december))
}

func FuzzParse(f *testing.F) {
	f.Add(`{"@t":"2021-09-01T12:00:00Z","@l":"Information","@m":"Hello"}`)
	f.Add(`level=info ts=2026-07-06T12:00:00Z msg="user login"`)
	f.Add(`<134>1 2026-07-06T12:00:00.123Z host app - - - event`)
	f.Add(`E0507 18:45:23.697929 3747 pod_workers.go:1298] "Error syncing pod"`)
	f.Add("Unhandled exception. System.Exception: boom\n   at Program.Main()")
	f.Add(`{"level":30,"time":1751805600000,"msg":"pino"}`)
	f.Add("\x1b[31mERROR\x1b[0m colored")
	f.Add(`traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`)
	f.Fuzz(func(t *testing.T, line string) {
		result := Parse(line)
		if result.Body != line {
			t.Fatalf("Body must be the input, got %q", result.Body)
		}
		// The severity is either empty or normalized, with a matching number.
		switch result.Severity {
		case "":
			if result.SeverityNumber != 0 {
				t.Fatalf("empty severity with number %d", result.SeverityNumber)
			}
		case TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel:
			if SeverityFromNumber(result.SeverityNumber) != result.Severity {
				t.Fatalf("severity %q has inconsistent number %d", result.Severity, result.SeverityNumber)
			}
		default:
			t.Fatalf("non-normalized severity %q", result.Severity)
		}
	})
}

func TestValidTraceID(t *testing.T) {
	for _, valid := range []string{
		"4bf92f3577b34da6a3ce929d0e0e4736",     // 32 bare hex
		"aebbb7bc-7ece-ee11-d090-84a20f1aa7b4", // Envoy request_id (UUID)
		"4BF92F3577B34DA6A3CE929D0E0E4736",     // uppercase
	} {
		assert.True(t, validTraceID(valid), "should be valid: %q", valid)
	}
	for _, invalid := range []string{
		"",
		"4bf92f3577b34da6a3ce929d0e0e47",     // 30 hex: too short
		"4bf92f3577b34da6a3ce929d0e0e4736ab", // 34 hex: too long
		"zzz92f3577b34da6a3ce929d0e0e4736",   // non-hex
		"trace 4bf92f3577b34da6a3ce929d0e0e4736 (cache)", // embedded in a sentence
	} {
		assert.False(t, validTraceID(invalid), "should be invalid: %q", invalid)
	}
}

func TestValidSpanID(t *testing.T) {
	assert.True(t, validSpanID("00f067aa0ba902b7"))
	assert.True(t, validSpanID("00F067AA0BA902B7"))
	assert.False(t, validSpanID(""))
	assert.False(t, validSpanID("00f067aa0ba902"))        // too short
	assert.False(t, validSpanID("00f067aa0ba902b7ab"))    // too long
	assert.False(t, validSpanID("zzf067aa0ba902b7"))      // non-hex
	assert.False(t, validSpanID("span 00f067aa0ba902b7")) // embedded
}

// Regression: the trace/span validators used to be unanchored regexes, so a
// field merely containing 32 (or 16) hex digits validated, and the whole field
// value — sentence and all — was then stored as the ID.
func TestParse_TraceID_NotSubstringMatched(t *testing.T) {
	enriched := Parse(`{"traceID":"trace was 4bf92f3577b34da6a3ce929d0e0e4736 (cached)","spanID":"span 00f067aa0ba902b7 end"}`)
	assert.Empty(t, enriched.TraceID, "a sentence containing a trace ID is not a trace ID")
	assert.Empty(t, enriched.SpanID, "a sentence containing a span ID is not a span ID")

	enriched = Parse(`level=info trace_id=xxxx4bf92f3577b34da6a3ce929d0e0e4736xxxx`)
	assert.Empty(t, enriched.TraceID)
}

func TestParseBytes(t *testing.T) {
	var r Result
	ok := ParseBytes([]byte(`{"@t":"2026-07-06T12:00:00Z","@l":"Warning","@m":"disk almost full"}`), &r)
	assert.True(t, ok)
	assert.Equal(t, FormatJSON, r.Format)
	assert.Equal(t, "warn", r.Severity)
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", r.Time.String())

	// A line matching nothing reports false and leaves Format empty.
	assert.False(t, ParseBytes([]byte(`nothing to see here`), &r))
	assert.Equal(t, FormatNone, r.Format)
}

// ParseBytes must agree with Parse on every strategy, and Body must alias the
// input rather than copy it.
func TestParseBytes_MatchesParse(t *testing.T) {
	for _, line := range []string{
		`{"level":"error","ts":"2026-07-06T12:00:00Z","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}`,
		`level=warn ts=2026-07-06T12:00:00Z msg="cache miss"`,
		`2026/07/06 12:00:00 [error] upstream refused`,
		`nothing matches this line`,
	} {
		want := Parse(line)
		var got Result
		ParseBytes([]byte(line), &got)
		assert.Equal(t, want.Format, got.Format, "line %q", line)
		assert.Equal(t, want.Severity, got.Severity, "line %q", line)
		assert.Equal(t, want.Time, got.Time, "line %q", line)
		assert.Equal(t, want.TraceID, got.TraceID, "line %q", line)
		assert.Equal(t, line, got.Body, "line %q", line)
	}
}

// ParseInto must fully reset the result, so a reused Result never leaks a
// field from the previous line.
func TestParseInto_ResetsResult(t *testing.T) {
	var r Result
	ParseInto(`{"@l":"Error","traceID":"4bf92f3577b34da6a3ce929d0e0e4736","@x":"System.Exception: boom"}`, &r)
	assert.NotEmpty(t, r.TraceID)
	assert.NotEmpty(t, r.ExceptionType)

	ParseInto(`plain line with nothing in it`, &r)
	assert.Empty(t, r.TraceID, "trace ID must not survive into the next line")
	assert.Empty(t, r.ExceptionType, "exception must not survive into the next line")
	assert.Empty(t, r.Severity)
	assert.Equal(t, FormatNone, r.Format)
}

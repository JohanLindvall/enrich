package enrich

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// JSON lines
// ---------------------------------------------------------------------------

func TestParse_JSON_Serilog(t *testing.T) {
	line := `{"@t":"2026-03-14T09:26:53.5Z","@l":"Warning","@m":"Order 42 rejected","@mt":"Order {Id} rejected","@i":"a1b2c3d4","@sn":"Orders-API","@sv":"2.4.1","@sp":"Acme-Shop","SourceContext":"Acme.Orders.Validator","traceID":"aaaabbbbccccdddd0000111122223333","spanID":"0123456789abcdef"}`
	enriched := Parse(line)
	assert.Equal(t, line, enriched.Body)
	assert.Equal(t, FormatJSON, enriched.Format)
	assert.Equal(t, "2026-03-14 09:26:53.5 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, WarnLevelNo, enriched.SeverityNumber)
	assert.Equal(t, "Order {Id} rejected", enriched.Template)
	assert.Equal(t, "a1b2c3d4", enriched.TemplateHash)
	assert.Equal(t, "orders-api", enriched.Service)
	assert.Equal(t, "2.4.1", enriched.Version)
	assert.Equal(t, "acme-shop", enriched.Product)
	assert.Equal(t, "Acme.Orders.Validator", enriched.SourceContext)
	assert.Equal(t, "aaaabbbbccccdddd0000111122223333", enriched.TraceID)
	assert.Equal(t, "0123456789abcdef", enriched.SpanID)
}

func TestParse_JSON_TimestampKeys(t *testing.T) {
	for _, key := range []string{"@t", "@timestamp", "timestamp", "Timestamp", "ts", "time", "Time"} {
		enriched := Parse(`{"` + key + `":"2026-03-14T09:26:53Z"}`)
		assert.Equal(t, "2026-03-14 09:26:53 +0000 UTC", enriched.Time.String(), "key %s", key)
	}
}

func TestParse_JSON_EpochTime(t *testing.T) {
	// Seconds and milliseconds since the epoch (1767225600 = 2026-01-01T00:00:00Z).
	enriched := Parse(`{"time":1767225600}`)
	assert.Equal(t, "2026-01-01 00:00:00 +0000 UTC", enriched.Time.String())

	enriched = Parse(`{"time":1767225600123,"level":"info"}`)
	assert.Equal(t, "2026-01-01 00:00:00.123 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_JSON_SeverityKeys(t *testing.T) {
	for _, key := range []string{"severity", "Severity", "@l", "@level", "level"} {
		enriched := Parse(`{"` + key + `":"Error"}`)
		assert.Equal(t, "error", enriched.Severity, "key %s", key)
	}
}

func TestParse_JSON_CapitalLevelIsNotSeverity(t *testing.T) {
	// Serilog uses "Level" for a message property, not severity; it must not
	// clobber the real @l value nor set one on its own.
	enriched := Parse(`{"@l":"Warning","Level":"Domains"}`)
	assert.Equal(t, "warn", enriched.Severity)

	enriched = Parse(`{"Level":"Domains","@t":"2026-03-14T09:26:53Z"}`)
	assert.Empty(t, enriched.Severity)
}

func TestParse_JSON_NonNormalizingSeverity(t *testing.T) {
	enriched := Parse(`{"level":"v2-preview"}`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, 0, enriched.SeverityNumber)
}

func TestParse_JSON_TraceValidation(t *testing.T) {
	// A dashed request id (Envoy style) is accepted and de-dashed.
	enriched := Parse(`{"request_id":"12345678-1234-5678-9abc-def012345678"}`)
	assert.Equal(t, "12345678123456789abcdef012345678", enriched.TraceID)

	// Non-hex or wrong-length IDs are rejected.
	enriched = Parse(`{"traceID":"not-a-trace-id","spanID":"xyz"}`)
	assert.Empty(t, enriched.TraceID)
	assert.Empty(t, enriched.SpanID)
}

func TestParse_JSON_ResourceID(t *testing.T) {
	enriched := Parse(`{"resourceId":"/SUBSCRIPTIONS/11111111-1111-1111-1111-111111111111/RESOURCEGROUPS/SHOP/PROVIDERS/MICROSOFT.WEB/SITES/ORDERS","eventCategory":"Administrative"}`)
	assert.Equal(t, "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/shop/providers/microsoft.web/sites/orders", enriched.ResourceID)
	assert.Equal(t, "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/shop", enriched.ResourceGroup)
	assert.Equal(t, "Administrative", enriched.EventCategory)
}

func TestParse_JSON_ResourceURIAlias(t *testing.T) {
	enriched := Parse(`{"resourceUri":"/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/db/providers/Microsoft.Sql/servers/main"}`)
	assert.Equal(t, "/subscriptions/22222222-2222-2222-2222-222222222222/resourcegroups/db/providers/microsoft.sql/servers/main", enriched.ResourceID)
	assert.Equal(t, "/subscriptions/22222222-2222-2222-2222-222222222222/resourcegroups/db", enriched.ResourceGroup)
}

func TestParse_JSON_PropertiesLog(t *testing.T) {
	// The nested line is enriched recursively; the authoritative top-level
	// time wins over the nested one.
	enriched := Parse(`{"time":"2026-03-14T10:00:00Z","properties":{"log":"{\"@t\":\"2026-03-14T09:00:00Z\",\"@l\":\"Error\",\"traceID\":\"ffff0000ffff0000ffff0000ffff0000\",\"spanID\":\"ffff0000ffff0000\"}"}}`)
	assert.Equal(t, "2026-03-14 10:00:00 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "ffff0000ffff0000ffff0000ffff0000", enriched.TraceID)
	assert.Equal(t, "ffff0000ffff0000", enriched.SpanID)
}

func TestParse_JSON_PropertiesResponse(t *testing.T) {
	// properties.response is JSON-as-string; the failing context escalates 4xx.
	enriched := Parse(`{"properties":{"response":"{\"statusCode\":403}"}}`)
	assert.Equal(t, "error", enriched.Severity)

	enriched = Parse(`{"properties":{"response":"{\"statusCode\":503}"}}`)
	assert.Equal(t, "warn", enriched.Severity)

	enriched = Parse(`{"properties":{"response":"{\"statusCode\":204}"}}`)
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_JSON_PropertiesHTTPStatusCode(t *testing.T) {
	// A plain properties.httpStatusCode is a tolerant-context response code.
	enriched := Parse(`{"properties":{"httpStatusCode":418}}`)
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_JSON_ResponseStatusCode(t *testing.T) {
	enriched := Parse(`{"responseStatus":{"code":400}}`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_JSON_ResultTypeStatusCode(t *testing.T) {
	enriched := Parse(`{"time":"2026-03-14T09:26:53Z","resultType":"HttpStatusCode","resultDescription":"429"}`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-03-14 09:26:53 +0000 UTC", enriched.Time.String())
}

func TestParse_JSON_Envoy_OK(t *testing.T) {
	enriched := Parse(`{"@timestamp":"2026-03-14T15:59:12.289Z","method":"GET","path":"/api/cart","protocol":"HTTP/2","response_code":200,"response_flags":"-","request_id":"5566aabb-77cc-88dd-99ee-001122334455","authority":"cart.api.example.net","duration":3,"bytes_sent":412}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2026-03-14 15:59:12.289 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "5566aabb77cc88dd99ee001122334455", enriched.TraceID)
}

func TestParse_JSON_Envoy_GrpcFail(t *testing.T) {
	// gRPC status 7 (PermissionDenied) escalates an otherwise-info line.
	enriched := Parse(`{"@timestamp":"2026-03-14T16:06:54.717Z","grpc_status_number":7,"grpc_status":"PermissionDenied","protocol":"HTTP/2","response_code":200,"request_id":"00ff11ee22dd33cc44bb55aa66997788","method":"POST"}`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "00ff11ee22dd33cc44bb55aa66997788", enriched.TraceID)
}

func TestParse_JSON_Envoy_GrpcOK(t *testing.T) {
	enriched := Parse(`{"@timestamp":"2026-03-14T16:06:54.717Z","grpc_status_number":0,"protocol":"HTTP/2","response_code":200}`)
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_JSON_Envoy_TCPProxy(t *testing.T) {
	// response_code 0 with no protocol field means plain TCP proxying: info.
	enriched := Parse(`{"@timestamp":"2026-03-14T10:24:28.592Z","response_code":0,"bytes_received":184,"bytes_sent":8,"upstream_host":"10.1.6.110:5672","requested_server_name":"mq.internal.example.net"}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2026-03-14 10:24:28.592 +0000 UTC", enriched.Time.String())
}

func TestParse_JSON_Envoy_ClientDisconnect(t *testing.T) {
	// response_code 0 with DR/DC response flags is a client disconnect: warn.
	for _, flags := range []string{"DR", "DC"} {
		enriched := Parse(`{"@timestamp":"2026-03-14T11:03:05.461Z","response_code":0,"protocol":"HTTP/2","response_flags":"` + flags + `","method":"POST","path":"/api/checkout"}`)
		assert.Equal(t, "warn", enriched.Severity, "flags %s", flags)
	}
}

func TestParse_JSON_Envoy_NoResponse(t *testing.T) {
	// response_code 0 with a protocol and non-disconnect flags is a real failure.
	enriched := Parse(`{"@timestamp":"2026-03-14T14:57:23.461Z","response_code":0,"protocol":"HTTP/1.1","response_flags":"UF","path":"/healthz","duration":2001}`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_JSON_ResponseCodeKeepsExplicitSeverity(t *testing.T) {
	// An explicit non-info severity is not overridden by the response code.
	enriched := Parse(`{"level":"debug","response_code":500}`)
	assert.Equal(t, "debug", enriched.Severity)
}

func TestParse_JSON_PinoTextualBeatsNumeric(t *testing.T) {
	enriched := Parse(`{"severity":"DEBUG","level":50,"time":1767225600123,"msg":"verbose detail"}`)
	assert.Equal(t, "debug", enriched.Severity)
}

// The lax decoder must tolerate structure it does not expect — wrong-typed
// envelopes, unknown nesting, malformed embedded JSON — and still extract
// what it can; truly malformed JSON falls through to the other strategies.
func TestParse_JSON_LaxTolerance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		line   string
		format string
		level  string
	}{
		{"unknown nesting is skipped", `{"arr":[true,null,{"x":[]}],"level":"info"}`, FormatJSON, "info"},
		{"non-object properties", `{"properties":"not an object","level":"warn"}`, FormatJSON, "warn"},
		{"non-numeric responseStatus code", `{"responseStatus":{"code":"200"},"level":"warn"}`, FormatJSON, "warn"},
		{"broken embedded response", `{"properties":{"response":"{bad"},"level":"info"}`, FormatJSON, "info"},
		{"null level", `{"level":null,"msg":null}`, FormatJSON, ""},
		{"non-string embedded log", `{"log":123,"level":"warn"}`, FormatJSON, "warn"},
		{"non-string properties log", `{"properties":{"log":123},"level":"warn"}`, FormatJSON, "warn"},
		{"non-object responseStatus", `{"responseStatus":123,"level":"warn"}`, FormatJSON, "warn"},
		{"non-object mongo date", `{"t":{"$date":[1]},"level":"warn"}`, FormatJSON, "warn"},
		{"leading whitespace", `  {"level":"info"}`, FormatJSON, "info"},
		{"truncated object", `{"level":"info"`, FormatNone, ""},
		// The lax skipper does not re-validate a nested value it discards, so
		// a syntax error confined to one envelope still lets later keys decode.
		{"malformed nested envelope", `{"properties":{bad},"level":"info"}`, FormatJSON, "info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			assert.Equal(t, tc.format, enriched.Format)
			assert.Equal(t, tc.level, enriched.Severity)
		})
	}

	// A JSON "t" key is MongoDB's timestamp envelope, not a timestamp string:
	// the logfmt t= spelling does not carry over to JSON.
	enriched := Parse(`{"t":"2026-07-06T12:00:00Z","msg":"x"}`)
	assert.Equal(t, FormatJSON, enriched.Format)
	assert.True(t, enriched.Time.IsZero())

	// An escaped message cannot alias the input; it is unescaped into a copy.
	assert.Equal(t, "line1\nline2 A", Parse(`{"msg":"line1\nline2 A"}`).Message)
}

// Codes that are not HTTP statuses are ignored wherever they appear: a
// negative or exponent-form response_code records neither code nor severity.
func TestParse_JSON_NonHTTPResponseCodes(t *testing.T) {
	for _, line := range []string{
		`{"response_code":-200,"protocol":"HTTP/2"}`,
		`{"response_code":2e2}`,
	} {
		enriched := Parse(line)
		assert.Empty(t, enriched.Severity, "line %s", line)
		assert.Zero(t, enriched.HTTPStatusCode, "line %s", line)
	}
}

// An embedded access-log line's status code is lifted into the envelope's
// result like the rest of its metadata.
func TestParse_JSON_NestedHTTPStatusLifted(t *testing.T) {
	enriched := Parse(`{"log":"203.0.113.7 - - [14/Mar/2026:06:42:27 +0000] \"GET / HTTP/1.1\" 404 13 \"\" \"probe/2.7\"\n","stream":"stdout"}`)
	assert.Equal(t, 404, enriched.HTTPStatusCode)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-03-14 06:42:27 +0000 UTC", enriched.Time.String())
}

// A gRPC status is 0-16; a negative number names nothing.
func TestParse_JSON_NegativeGrpcStatusRejected(t *testing.T) {
	enriched := Parse(`{"grpc_status_number":-5,"@timestamp":"2026-03-14T16:06:54Z"}`)
	assert.Empty(t, enriched.Severity)
}

// A JVM-style payload puts words before the exception class; the class — the
// last word before the ": " — is the type, not the leading "Exception".
func TestParse_JSON_Exception_JavaThreadHeader(t *testing.T) {
	enriched := Parse(`{"@x":"Exception in thread \"main\" java.lang.IllegalStateException: queue full\n\tat com.example.shop.Worker.run(Worker.java:44)"}`)
	assert.Equal(t, "java.lang.IllegalStateException", enriched.ExceptionType)
	assert.Equal(t, "queue full", enriched.ExceptionMessage)
	assert.Equal(t, "\tat com.example.shop.Worker.run(Worker.java:44)", enriched.ExceptionStackTrace)
}

func TestParse_JSON_Exception(t *testing.T) {
	enriched := Parse(`{"@t":"2026-03-14T09:26:53Z","@m":"Unhandled exception","@x":"Acme.Domain.OrderException: quantity must be positive\n   at Acme.Orders.Validate(Order o)\n   at Acme.Api.Handle(Request r)"}`)
	assert.Equal(t, "Acme.Domain.OrderException", enriched.ExceptionType)
	assert.Equal(t, "quantity must be positive", enriched.ExceptionMessage)
	assert.True(t, strings.HasPrefix(enriched.ExceptionStackTrace, "   at Acme.Orders.Validate"))
}

// ---------------------------------------------------------------------------
// logfmt lines
// ---------------------------------------------------------------------------

func TestParse_Logfmt_TimeAndLevel(t *testing.T) {
	enriched := Parse(`ts=2026-03-14T09:26:53.123456789Z level=info msg="cache warmed" items=113`)
	assert.Equal(t, FormatLogfmt, enriched.Format)
	assert.Equal(t, "2026-03-14 09:26:53.123456789 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Logfmt_TimeLast(t *testing.T) {
	enriched := Parse(`component=scheduler level=warn msg="retrying in 5s" ts=2026-03-14T09:26:53Z`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2026-03-14 09:26:53 +0000 UTC", enriched.Time.String())
}

func TestParse_Logfmt_LevelOnly(t *testing.T) {
	enriched := Parse(`level=error msg="connection refused"`)
	assert.Equal(t, "error", enriched.Severity)
	assert.True(t, enriched.Time.IsZero())
}

func TestParse_Logfmt_NormalizingLevelWins(t *testing.T) {
	// A level value that normalizes wins over an earlier one that does not.
	enriched := Parse(`level=v2-preview level=warning msg=x`)
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Logfmt_QuotedTime(t *testing.T) {
	enriched := Parse(`time="2026-03-14 09:26:53.4 +0000 UTC" kind=event event_name=page_view`)
	assert.Equal(t, "2026-03-14 09:26:53.4 +0000 UTC", enriched.Time.String())
}

func TestParse_Logfmt_TKey(t *testing.T) {
	enriched := Parse(`logger=ingester t=2026-03-14T09:26:53.05Z level=debug msg="flushed chunk"`)
	assert.Equal(t, "debug", enriched.Severity)
	assert.Equal(t, "2026-03-14 09:26:53.05 +0000 UTC", enriched.Time.String())
}

func TestParse_Logfmt_QuotedRFC3339(t *testing.T) {
	enriched := Parse(`time="2026-03-14T08:03:05Z" level=debug msg="skipping endpoint web.example.com because owner id does not match"`)
	assert.Equal(t, "debug", enriched.Severity)
	assert.Equal(t, "2026-03-14 08:03:05 +0000 UTC", enriched.Time.String())
}

// The scan must keep going until the message is found too — the early exit
// used to drop a msg= that followed the timestamp, level and both trace IDs.
func TestParse_Logfmt_MessageAfterAllOtherSignals(t *testing.T) {
	enriched := Parse(`ts=2026-03-14T09:26:53Z level=info trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span_id=00f067aa0ba902b7 msg="cache warmed"`)
	assert.Equal(t, "cache warmed", enriched.Message)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)
}

func TestParse_Logfmt_TimestampKeys(t *testing.T) {
	for _, key := range []string{"t", "ts", "time", "timestamp"} {
		enriched := Parse(key + `=2026-03-14T09:26:53Z msg=x`)
		assert.Equal(t, "2026-03-14 09:26:53 +0000 UTC", enriched.Time.String(), "key %s", key)
	}
}

// Explicit trace_id/span_id keys name the record's own IDs and win over a
// propagated traceparent wherever either appears — the same precedence the
// JSON path applies (TestParse_JSON_Traceparent).
func TestParse_Logfmt_TraceparentLosesToExplicitIDs(t *testing.T) {
	const tp = "traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	for _, line := range []string{
		`level=info trace_id=11111111111111111111111111111111 span_id=2222222222222222 ` + tp,
		`level=info ` + tp + ` trace_id=11111111111111111111111111111111 span_id=2222222222222222`,
	} {
		enriched := Parse(line)
		assert.Equal(t, "11111111111111111111111111111111", enriched.TraceID, "line %s", line)
		assert.Equal(t, "2222222222222222", enriched.SpanID, "line %s", line)
	}

	// The traceparent fills whichever side no explicit key names.
	enriched := Parse(`level=info trace_id=11111111111111111111111111111111 ` + tp)
	assert.Equal(t, "11111111111111111111111111111111", enriched.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", enriched.SpanID)

	// An invalid explicit value does not shadow a later valid one.
	enriched = Parse(`level=info trace_id=not-a-trace-id trace_id=4bf92f3577b34da6a3ce929d0e0e4736`)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
}

func TestParse_KubernetesEvent_TypePattern(t *testing.T) {
	// A key=value line without ts/level/trace keys is not logfmt-enriched; the
	// type=Warning pattern picks it up instead.
	enriched := Parse(`name=web-0 kind=Pod reason=Unhealthy type=Warning count=3 msg="Liveness probe failed: connection refused"`)
	assert.Equal(t, FormatPattern, enriched.Format)
	assert.Equal(t, "warn", enriched.Severity)
	assert.True(t, enriched.Time.IsZero())
}

// ---------------------------------------------------------------------------
// Pattern-table lines: entries with a timestamp and a level
// ---------------------------------------------------------------------------

func TestParse_Pattern_TimeAndLevel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  string
		level string
		time  string
	}{
		{
			"nginx error",
			`2026/03/14 09:26:53 [error] 42#42: connect() failed while connecting to upstream, server: web.example.com`,
			"error", "2026-03-14 09:26:53 +0000 UTC",
		},
		{
			"rust tracing",
			`2026-03-14T09:26:53.582245Z  INFO worker: scan complete file_count=88`,
			"info", "2026-03-14 09:26:53.582245 +0000 UTC",
		},
		{
			"cloudflared",
			`2026-03-14T06:31:22Z WRN your version 4.1 is outdated, please upgrade to 4.9`,
			"warn", "2026-03-14 06:31:22 +0000 UTC",
		},
		{
			"erlang bracket level",
			`2026-03-14 14:55:10.587 [info] <0.7545.176> closing AMQP connection (10.1.4.4:38958)`,
			"info", "2026-03-14 14:55:10.587 +0000 UTC",
		},
		{
			"envoy admin",
			`[2026-03-14 09:26:53.337][1][info][upstream] [source/common/cds.cc:71] added 0 clusters, skipped 60`,
			"info", "2026-03-14 09:26:53.337 +0000 UTC",
		},
		{
			"github runner",
			`[WORKER 2026-03-14 15:15:43Z INFO HostContext] well known directory 'Work': '/home/runner/_work'`,
			"info", "2026-03-14 15:15:43 +0000 UTC",
		},
		{
			"dotnet console",
			`[14/03/2026 09:26:53 INF Acme.Hosting.Lifetime 17  ] application started, press ctrl+c to shut down`,
			"info", "2026-03-14 09:26:53 +0000 UTC",
		},
		{
			"dotnet console error",
			`[14/03/2026 06:00:07 ERR Acme.Media.BlobUploadService 14  ] upload failed for media/v1/banner.json`,
			"error", "2026-03-14 06:00:07 +0000 UTC",
		},
		{
			"launchdarkly sdk",
			`2026-03-14 13:48:24.929 +00:00 [Acme.Sdk.Evaluation] INFO: unknown feature flag "new-checkout"; returning default`,
			"info", "2026-03-14 13:48:24.929 +0000 UTC",
		},
		{
			"oauth2 proxy error",
			`[2026/03/14 09:26:53] [proxy.go:113] error: dial tcp 10.1.5.6:8080: connection refused`,
			"error", "2026-03-14 09:26:53 +0000 UTC",
		},
		{
			"fluent bit",
			`[2026/03/14 09:26:53] [ info] [engine] flush chunk succeeded`,
			"info", "2026-03-14 09:26:53 +0000 UTC",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			assert.Equal(t, FormatPattern, enriched.Format)
			assert.Equal(t, tc.level, enriched.Severity)
			assert.Equal(t, tc.time, enriched.Time.String())
		})
	}
}

func TestParse_Pattern_Klog(t *testing.T) {
	enriched := Parse(`E0314 09:26:53.697929    3747 pod_workers.go:1298] "Error syncing pod" pod="shop/orders-7d4b9"`)
	assert.Equal(t, "error", enriched.Severity)
	// klog timestamps carry no year; it is inferred from the clock, so the
	// assertion skips it.
	assert.Equal(t, "-03-14 09:26:53.697929 +0000 UTC", enriched.Time.String()[4:])

	enriched = Parse(`I0314 15:00:59.214583       1 utils.go:135] "Skipping service due to cluster IP" service="shop/cart"`)
	assert.Equal(t, "info", enriched.Severity)
}

// ---------------------------------------------------------------------------
// Pattern-table lines: access logs mapping response codes to severities
// ---------------------------------------------------------------------------

func TestParse_Pattern_AccessLogs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  string
		level string
		time  string
	}{
		{
			"nginx combined 200",
			`203.0.113.7 - - [14/Mar/2026:06:42:27 -0700] "POST /api/orders HTTP/1.1" 200 658 "-" "curl/8.5" 650 0.023`,
			"info", "2026-03-14 13:42:27 +0000 UTC",
		},
		{
			"nginx combined 404",
			`198.51.100.4 - - [14/Mar/2026:06:43:18 +0000] "GET /healthz HTTP/1.1" 404 13 "" "probe/2.7"`,
			"warn", "2026-03-14 06:43:18 +0000 UTC",
		},
		{
			"nginx code before request",
			`10.1.8.33 - - [14/Mar/2026:06:45:43 +0000]  204 "POST /api/v1/push HTTP/1.1" 0 "-" "pusher/1.0" "-"`,
			"info", "2026-03-14 06:45:43 +0000 UTC",
		},
		{
			"registry head",
			`10.1.6.253 - - [14/Mar/2026:06:43:06 +0000] "HEAD /v2/orders-api/blobs/sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999 HTTP/1.1" 200 0 "" "buildkit/0.16"`,
			"info", "2026-03-14 06:43:06 +0000 UTC",
		},
		{
			"oauth2 proxy 202",
			`203.0.113.9:51234 - 00112233445566778899aabbccddeeff - jane@example.com [2026/03/14 06:46:40] auth.example.com GET - "/oauth2/auth" HTTP/1.1 "Mozilla/5.0" 202 0 0.000`,
			"info", "2026-03-14 06:46:40 +0000 UTC",
		},
		{
			"oauth2 proxy 401",
			`10.1.5.6:48444 - ffeeddccbbaa99887766554433221100 - - [2026/03/14 06:47:55] auth.example.com GET - "/oauth2/auth" HTTP/1.1 "Traffic Monitor" 401 13 0.00`,
			"warn", "2026-03-14 06:47:55 +0000 UTC",
		},
		{
			"http echo",
			`2026/03/14 06:38:47 ping.example.com 203.0.113.5:54380 "GET / HTTP/1.1" 200 12 "HealthBot/1.0" 6.68µs`,
			"info", "2026-03-14 06:38:47 +0000 UTC",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			assert.Equal(t, tc.level, enriched.Severity)
			assert.Equal(t, tc.time, enriched.Time.String())
		})
	}
}

func TestParse_Pattern_Redis(t *testing.T) {
	for _, tc := range []struct {
		line  string
		level string
		time  string
	}{
		{
			`1:M 14 Mar 2026 09:26:53.123 * Ready to accept connections tcp`,
			"info", "2026-03-14 09:26:53.123 +0000 UTC",
		},
		{
			`1:C 14 Mar 2026 07:19:58.546 # Warning: no config file specified, using the default config`,
			"warn", "2026-03-14 07:19:58.546 +0000 UTC",
		},
		{
			`1234:M 14 Mar 2026 07:19:58.546 . debug detail message`,
			"debug", "2026-03-14 07:19:58.546 +0000 UTC",
		},
		{
			`7:S 14 Mar 2026 07:19:58 - accepted 10.1.0.4:12345`,
			"debug", "2026-03-14 07:19:58 +0000 UTC",
		},
	} {
		enriched := Parse(tc.line)
		assert.Equal(t, tc.level, enriched.Severity, "line %s", tc.line)
		assert.Equal(t, tc.time, enriched.Time.String(), "line %s", tc.line)
	}
}

// ---------------------------------------------------------------------------
// Pattern-table lines: level only, timestamp only
// ---------------------------------------------------------------------------

func TestParse_Pattern_LevelOnly(t *testing.T) {
	enriched := Parse(`[ERROR] failed to connect to database shop-primary`)
	assert.Equal(t, "error", enriched.Severity)
	assert.True(t, enriched.Time.IsZero())

	enriched = Parse(`INFO: any empty folders will not be processed`)
	assert.Equal(t, "info", enriched.Severity)
	assert.True(t, enriched.Time.IsZero())
}

func TestParse_Pattern_TimestampOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		time string
	}{
		{
			"plain seconds",
			`2026-03-14 09:26:53 starting watch loop`,
			"2026-03-14 09:26:53 +0000 UTC",
		},
		{
			"azdo agent",
			`2026-03-14 06:32:14Z: Job deploy-shop completed with result: Succeeded`,
			"2026-03-14 06:32:14 +0000 UTC",
		},
		{
			"go stdlog slash",
			`2026/03/14 06:56:51 [1] [releaseIPs] releasing pod with key web-0-eth0`,
			"2026-03-14 06:56:51 +0000 UTC",
		},
		{
			"go stdlog micros",
			`2026/03/14 09:26:53.400089 cost for tenant shop-a: 677.65`,
			"2026-03-14 09:26:53.400089 +0000 UTC",
		},
		{
			"go stdlog quoted",
			`2026/03/14 06:36:55 watching directory: "/etc/config"`,
			"2026-03-14 06:36:55 +0000 UTC",
		},
		{
			"rfc3339 lowercase word",
			`2026-03-14T12:55:12.8539173Z start tracking orphan processes`,
			"2026-03-14 12:55:12.8539173 +0000 UTC",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			assert.Empty(t, enriched.Severity)
			assert.Equal(t, tc.time, enriched.Time.String())
		})
	}
}

// ---------------------------------------------------------------------------
// Pattern-table lines: panics, tracebacks, exceptions
// ---------------------------------------------------------------------------

func TestParse_Pattern_GoPanic(t *testing.T) {
	enriched := Parse("panic: runtime error: invalid memory address or nil pointer dereference\n\ngoroutine 1 [running]:\nmain.handleOrder(0x0)\n\t/app/main.go:14 +0x1d")
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Pattern_PythonTraceback(t *testing.T) {
	enriched := Parse("Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>\n    main()\nValueError: quantity must be positive")
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Pattern_JavaException(t *testing.T) {
	enriched := Parse("Exception in thread \"main\" java.lang.IllegalStateException: queue full\n\tat com.example.shop.Worker.run(Worker.java:44)")
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Pattern_DotNetUnhandledException(t *testing.T) {
	enriched := Parse("Unhandled exception. System.InvalidOperationException: sequence contains no elements\n   at Acme.Orders.Single[T](IEnumerable`1 source)\n   at Acme.Api.Program.Main(String[] args)")
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "System.InvalidOperationException", enriched.ExceptionType)
	assert.Equal(t, "sequence contains no elements", enriched.ExceptionMessage)
	assert.Equal(t, "   at Acme.Orders.Single[T](IEnumerable`1 source)\n   at Acme.Api.Program.Main(String[] args)", enriched.ExceptionStackTrace)
}

func TestParse_Pattern_DotNetUnhandledException_MessageOnly(t *testing.T) {
	enriched := Parse("Unhandled exception. Acme.ConfigException: missing connection string\nsee documentation for details")
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "Acme.ConfigException", enriched.ExceptionType)
	assert.Equal(t, "missing connection string", enriched.ExceptionMessage)
	assert.Equal(t, "see documentation for details", enriched.ExceptionStackTrace)
}

// ---------------------------------------------------------------------------
// Cross-cutting behavior
// ---------------------------------------------------------------------------

func TestParse_ANSIColorCodes(t *testing.T) {
	enriched := Parse("\x1b[31mERROR:\x1b[0m disk /data is 97% full")
	assert.Equal(t, "error", enriched.Severity)
	// Body keeps the original bytes, escape codes included.
	assert.Equal(t, "\x1b[31mERROR:\x1b[0m disk /data is 97% full", enriched.Body)
}

func TestParse_NoMatch(t *testing.T) {
	line := `the quick brown fox jumps over the lazy dog`
	enriched := Parse(line)
	assert.Equal(t, line, enriched.Body)
	assert.Equal(t, FormatNone, enriched.Format)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, 0, enriched.SeverityNumber)
	assert.True(t, enriched.Time.IsZero())
}

func TestParse_EmptyInput(t *testing.T) {
	enriched := Parse("")
	assert.Equal(t, "", enriched.Body)
	assert.Equal(t, FormatNone, enriched.Format)
	assert.Empty(t, enriched.Severity)
}

// ---------------------------------------------------------------------------
// Message, status code, and the identifier spellings
// ---------------------------------------------------------------------------

func TestParse_JSON_Message(t *testing.T) {
	for _, key := range []string{"@m", "message", "Message", "MESSAGE", "msg"} {
		enriched := Parse(`{"` + key + `":"disk almost full","level":"warn"}`)
		assert.Equal(t, "disk almost full", enriched.Message, "key %s", key)
	}

	// The template and the rendered message are different fields, and both are
	// kept.
	enriched := Parse(`{"@mt":"Order {Id} rejected","@m":"Order 42 rejected"}`)
	assert.Equal(t, "Order {Id} rejected", enriched.Template)
	assert.Equal(t, "Order 42 rejected", enriched.Message)

	// A plain-text line has no separable message.
	assert.Empty(t, Parse(`2026-03-14 09:26:53 starting watch loop`).Message)
}

func TestParse_Logfmt_Message(t *testing.T) {
	assert.Equal(t, "cache warmed", Parse(`ts=2026-03-14T09:26:53Z level=info msg="cache warmed"`).Message)
	assert.Equal(t, "cache warmed", Parse(`level=info message="cache warmed"`).Message)

	// A key=value line the pattern table resolves instead still yields its
	// message: the logfmt scan ran, it just did not claim the line.
	enriched := Parse(`name=web-0 kind=Pod reason=Unhealthy type=Warning msg="Liveness probe failed"`)
	assert.Equal(t, FormatPattern, enriched.Format)
	assert.Equal(t, "Liveness probe failed", enriched.Message)
}

func TestParse_TraceIDSpellings(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const spanID = "00f067aa0ba902b7"
	for _, keys := range [][2]string{
		{"traceId", "spanId"}, // Micrometer/Sleuth, OpenTelemetry JS
		{"traceID", "spanID"},
		{"TraceId", "SpanId"}, // .NET
		{"trace_id", "span_id"},
		{"trace.id", "span.id"}, // Elastic Common Schema
	} {
		enriched := Parse(`{"` + keys[0] + `":"` + traceID + `","` + keys[1] + `":"` + spanID + `"}`)
		assert.Equal(t, traceID, enriched.TraceID, "key %s", keys[0])
		assert.Equal(t, spanID, enriched.SpanID, "key %s", keys[1])

		enriched = Parse(`level=info ` + keys[0] + `=` + traceID + ` ` + keys[1] + `=` + spanID)
		assert.Equal(t, traceID, enriched.TraceID, "logfmt key %s", keys[0])
		assert.Equal(t, spanID, enriched.SpanID, "logfmt key %s", keys[1])
	}
}

// An all-zero ID is W3C trace-context's "invalid" value, which OpenTelemetry
// SDKs emit for a record with no active span. Keeping it would file every
// untraced line in a fleet under one trace.
func TestParse_ZeroTraceIDRejected(t *testing.T) {
	assert.False(t, validTraceID("00000000000000000000000000000000"))
	assert.False(t, validTraceID("00000000-0000-0000-0000-000000000000"))
	assert.False(t, validSpanID("0000000000000000"))
	assert.True(t, validTraceID("00000000000000000000000000000001"))
	assert.True(t, validSpanID("0000000000000001"))

	enriched := Parse(`{"TraceId":"00000000000000000000000000000000","SpanId":"0000000000000000","@l":"Information"}`)
	assert.Empty(t, enriched.TraceID)
	assert.Empty(t, enriched.SpanID)

	traceID, spanID := parseTraceparent("00-00000000000000000000000000000000-0000000000000000-00")
	assert.Empty(t, traceID)
	assert.Empty(t, spanID)
}

func TestParse_HTTPStatusCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  string
		code  int
		level string
	}{
		{"envoy", `{"response_code":503,"protocol":"HTTP/2"}`, 503, "warn"},
		{"snake case", `{"status_code":404}`, 404, "warn"},
		{"ecs", `{"http.response.status_code":201}`, 201, "info"},
		{"azure response", `{"properties":{"response":"{\"statusCode\":403}"}}`, 403, "error"},
		{"azure plain", `{"properties":{"httpStatusCode":418}}`, 418, "warn"},
		{"azure result type", `{"resultType":"HttpStatusCode","resultDescription":"429"}`, 429, "warn"},
		{"response status", `{"responseStatus":{"code":400}}`, 400, "error"},
		{
			"nginx access log",
			`198.51.100.4 - - [14/Mar/2026:06:43:18 +0000] "GET /healthz HTTP/1.1" 404 13 "" "probe/2.7"`,
			404, "warn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enriched := Parse(tc.line)
			assert.Equal(t, tc.code, enriched.HTTPStatusCode)
			assert.Equal(t, tc.level, enriched.Severity)
		})
	}

	// A code that is not an HTTP status is not recorded as one: Envoy writes 0
	// when there was no response at all.
	assert.Zero(t, Parse(`{"response_code":0,"protocol":"HTTP/1.1","response_flags":"UF"}`).HTTPStatusCode)
	// An explicit level still wins over the code, which is kept regardless.
	enriched := Parse(`{"level":"debug","response_code":500}`)
	assert.Equal(t, "debug", enriched.Severity)
	assert.Equal(t, 500, enriched.HTTPStatusCode)
}

func TestParse_JSON_OTelSeverityNumber(t *testing.T) {
	// The number names the level on its own, at its own granularity: 10 is a
	// notice, an info that outranks a plain one.
	enriched := Parse(`{"severityNumber":10,"severityText":"NOTICE","body":"listening"}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, Info2LevelNo, enriched.SeverityNumber)

	// It refines a textual level that agrees with it...
	enriched = Parse(`{"severity_number":18,"severity":"ERROR"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, Error2LevelNo, enriched.SeverityNumber)

	// ...and loses to one that does not, so the two never contradict.
	enriched = Parse(`{"severityNumber":10,"level":"error"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, ErrorLevelNo, enriched.SeverityNumber)

	// A number outside the OTLP range names nothing.
	enriched = Parse(`{"severityNumber":99}`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, 0, enriched.SeverityNumber)
}

func TestParse_JSON_ECSAndOTelErrorFields(t *testing.T) {
	enriched := Parse(`{"log.level":"error","message":"upload failed","service.name":"media-api","service.version":"1.2.0","error.type":"System.IO.IOException","error.message":"disk full","error.stack_trace":"   at Acme.Media.Upload()"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "upload failed", enriched.Message)
	assert.Equal(t, "media-api", enriched.Service)
	assert.Equal(t, "1.2.0", enriched.Version)
	assert.Equal(t, "System.IO.IOException", enriched.ExceptionType)
	assert.Equal(t, "disk full", enriched.ExceptionMessage)
	assert.Equal(t, "   at Acme.Media.Upload()", enriched.ExceptionStackTrace)

	// A Python/structlog "exception" string is a whole payload, like Serilog's @x.
	enriched = Parse(`{"levelname":"ERROR","logger":"app.web","exception":"ValueError: quantity must be positive\n  File \"app.py\", line 10"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "app.web", enriched.SourceContext)
	assert.Equal(t, "ValueError", enriched.ExceptionType)
	assert.Equal(t, "quantity must be positive", enriched.ExceptionMessage)
}

// An exception payload with no level of its own is an error, matching what the
// pattern table does for a Go panic or a Python traceback.
func TestParse_JSON_ExceptionImpliesError(t *testing.T) {
	enriched := Parse(`{"@t":"2026-03-14T09:26:53Z","@x":"System.Exception: boom\n   at Program.Main()"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, ErrorLevelNo, enriched.SeverityNumber)

	// An explicit level still wins: Serilog logs a caught exception at warn.
	enriched = Parse(`{"@l":"Warning","@x":"System.Exception: boom"}`)
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_JSON_NestedMetadataIsLifted(t *testing.T) {
	// The Docker json-file envelope has no metadata of its own; everything the
	// embedded line carries is lifted, and the line itself becomes the message.
	enriched := Parse(`{"log":"{\"@l\":\"Error\",\"@m\":\"order rejected\",\"@mt\":\"order {Id} rejected\",\"SourceContext\":\"Acme.Orders\",\"traceID\":\"4bf92f3577b34da6a3ce929d0e0e4736\"}","stream":"stdout","time":"2026-07-06T12:00:00Z"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "order rejected", enriched.Message)
	assert.Equal(t, "order {Id} rejected", enriched.Template)
	assert.Equal(t, "Acme.Orders", enriched.SourceContext)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", enriched.TraceID)
	// The envelope's own timestamp is authoritative.
	assert.Equal(t, "2026-07-06 12:00:00 +0000 UTC", enriched.Time.String())

	// A plain-text payload is the message verbatim, without Docker's newline.
	enriched = Parse(`{"log":"ERROR: connection refused\n","stream":"stderr","time":"2026-07-06T12:00:00Z"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "ERROR: connection refused", enriched.Message)
}

func TestParse_JSON_PinoPrettyPrinted(t *testing.T) {
	enriched := Parse(`{"level": 50, "time": 1751805600000, "msg": "connection refused"}`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "connection refused", enriched.Message)
}

// resourceGroupRE is the pattern resourceGroup replaced, kept as the oracle
// for the hand-rolled scan that took its place (the regexp package allocates
// its match slice, which put an allocation on every Azure line).
var resourceGroupRE = regexp.MustCompile(`(?i)/subscriptions/[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}/resourcegroups/[^/]+`)

func regexResourceGroup(id string) string {
	if match := resourceGroupRE.FindString(id); match != "" {
		return match
	}
	return ""
}

// TestResourceGroupMatchesRegex differential-tests the scan against the regex,
// over hand-picked shapes and a randomized sweep of the alphabet the pattern
// is built from.
func TestResourceGroupMatchesRegex(t *testing.T) {
	check := func(id string) {
		t.Helper()
		assert.Equal(t, regexResourceGroup(id), resourceGroup(id), "resource id %q", id)
	}

	const guid = "11111111-2222-3333-4444-555555555555"
	for _, id := range []string{
		"",
		"/subscriptions/" + guid + "/resourcegroups/shop",
		"/subscriptions/" + guid + "/resourcegroups/shop/providers/microsoft.web/sites/orders",
		"/subscriptions/" + guid + "/resourcegroups/shop-eu_1.prod/providers/x",
		"/subscriptions/" + guid + "/resourcegroups/",                          // empty group name
		"/subscriptions/" + guid + "/resourcegroups",                           // no trailing slash
		"/subscriptions/" + guid + "/providers/microsoft.web",                  // no group
		"/subscriptions/1111/resourcegroups/shop",                              // short guid
		"/subscriptions/" + guid + "x/resourcegroups/shop",                     // guid too long
		"/subscriptions/" + guid[:8] + "x" + guid[9:] + "/resourcegroups/shop", // dash replaced
		"prefix/subscriptions/" + guid + "/resourcegroups/shop/x",              // unanchored
		"/subscriptions/nope/subscriptions/" + guid + "/resourcegroups/shop",   // second occurrence wins
		"/subscriptions/",
		"/subscriptions/" + guid,
	} {
		check(id)
	}

	const alphabet = "0159abcdef-/subscriptonrgh"
	rng := rand.New(rand.NewSource(2))
	buf := make([]byte, 0, 80)
	for i := 0; i < 200000; i++ {
		buf = buf[:0]
		for n := rng.Intn(80); n > 0; n-- {
			buf = append(buf, alphabet[rng.Intn(len(alphabet))])
		}
		check(string(buf))
	}

	// Randomly damaged real resource IDs: the shapes a sweep rarely stumbles on.
	full := "/subscriptions/" + guid + "/resourcegroups/shop/providers/microsoft.web/sites/orders"
	for i := 0; i < 20000; i++ {
		b := []byte(full)
		for n := rng.Intn(3) + 1; n > 0; n-- {
			b[rng.Intn(len(b))] = alphabet[rng.Intn(len(alphabet))]
		}
		check(string(b))
	}
}

func TestParse_SeverityVocabulary(t *testing.T) {
	// Spellings from vocabularies the six canonical names do not cover; where
	// the source grades within a level, the OTLP number keeps the grading.
	for _, tc := range []struct {
		text  string
		level string
		no    int
	}{
		{"notice", InfoLevel, Info2LevelNo}, // syslog, Apache, nginx
		{"NOTICE", InfoLevel, Info2LevelNo},
		{"alert", FatalLevel, Fatal2LevelNo},
		{"emerg", FatalLevel, Fatal3LevelNo},
		{"emergency", FatalLevel, Fatal3LevelNo},
		{"Verbose", TraceLevel, TraceLevelNo}, // Serilog
		{"VRB", TraceLevel, TraceLevelNo},
		{"SEVERE", ErrorLevel, ErrorLevelNo}, // java.util.logging
		{"FINE", DebugLevel, DebugLevelNo},
		{"FINEST", TraceLevel, TraceLevelNo},
	} {
		level, no := SeverityFromText(tc.text)
		assert.Equal(t, tc.level, level, "text %q", tc.text)
		assert.Equal(t, tc.no, no, "text %q", tc.text)

		// The number survives the JSON path, which used to normalize the text
		// and drop it.
		enriched := Parse(`{"level":"` + tc.text + `"}`)
		assert.Equal(t, tc.level, enriched.Severity, "text %q", tc.text)
		assert.Equal(t, tc.no, enriched.SeverityNumber, "text %q", tc.text)

		enriched = Parse(`level=` + tc.text + ` msg=x`)
		assert.Equal(t, tc.level, enriched.Severity, "logfmt %q", tc.text)
		assert.Equal(t, tc.no, enriched.SeverityNumber, "logfmt %q", tc.text)
	}

	// An Apache error log grades its own vocabulary.
	enriched := Parse(`[Wed Oct 11 14:32:52 2000] [notice] [client 203.0.113.1] caught SIGTERM, shutting down`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, Info2LevelNo, enriched.SeverityNumber)
}

// The response_code 0 rules are inferences from a missing response, so a level
// the line states outright wins over both of them.
func TestParse_JSON_ZeroCodeKeepsExplicitSeverity(t *testing.T) {
	assert.Equal(t, "error", Parse(`{"level":"error","response_code":0}`).Severity)
	assert.Equal(t, "error", Parse(`{"level":"error","response_code":0,"protocol":"HTTP/2","response_flags":"DC"}`).Severity)
	// With no level of its own, Envoy's TCP-proxy line is still info.
	assert.Equal(t, "info", Parse(`{"response_code":0}`).Severity)
}

func TestParse_Pattern_DotNetExceptionWithErrorCodes(t *testing.T) {
	// .NET socket/native exceptions carry parenthesized error codes between the
	// type and the colon; the parenthetical must not be mistaken for the type.
	enriched := Parse("Unhandled exception. System.Net.Sockets.SocketException (00000005, 0xFFFDFFFF): Name or service not known\n   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName)")
	assert.Equal(t, "System.Net.Sockets.SocketException", enriched.ExceptionType)
	assert.Equal(t, "Name or service not known", enriched.ExceptionMessage)
	assert.Equal(t, "   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName)", enriched.ExceptionStackTrace)
	assert.Equal(t, ErrorLevel, enriched.Severity)
}

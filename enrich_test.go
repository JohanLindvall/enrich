package enrich

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// JSON lines
// ---------------------------------------------------------------------------

func TestParse_JSON_Serilog(t *testing.T) {
	line := `{"@t":"2026-03-14T09:26:53.5Z","@l":"Warning","@m":"Order 42 rejected","@mt":"Order {Id} rejected","@i":"a1b2c3d4","@sn":"orders-api","@sv":"2.4.1","@sp":"acme-shop","SourceContext":"Acme.Orders.Validator","traceID":"aaaabbbbccccdddd0000111122223333","spanID":"0123456789abcdef"}`
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

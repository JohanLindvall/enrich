package enrich

import (
	"testing"
)

// sink keeps the parsed result alive so it escapes, as it does for a real
// caller that forwards the Result. Without it the compiler proves the Result
// never leaves the loop and stack-allocates it, hiding the 320 B/line that
// production code actually pays. Use ParseInto with a reused Result to avoid
// that allocation for real (see BenchmarkParseIntoReused).
var sink *Result

// A ~900 B Envoy-style JSON access-log line.
var line = `{"@timestamp":"2026-03-14T09:26:53.394Z","grpc_status_number":0,"grpc_status":"OK","response_flags":"-","requested_server_name":"orders.api.example.net","upstream_local_address":"10.1.23.22:35290","upstream_service_time":"4","path":"/orders.v1.OrderService/GetOrders","bytes_received":43,"request_id":"aabbccdd11223344556677889900aabb","x_forwarded_for":"10.1.7.14","authority":"orders.api.example.net","bytes_sent":75,"upstream_host":"10.1.18.8:5000","user_agent":"grpc-go/1.60.0 (linux; amd64) orders-client/2026.3.1","downstream_remote_address":"10.1.7.14:41882","protocol":"HTTP/2","response_code":200,"downstream_local_address":"10.1.23.22:8443","method":"POST","upstream_cluster":"orders-service-blue_5000","duration":4}`

// go test -bench=BenchmarkEnrich -benchmem -memprofile memprofile.out -cpuprofile profile.out -benchtime=30s
func BenchmarkEnrich(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sink = Parse(line)
	}
}

// A ~1.9 kB browser-telemetry logfmt line with many key/value pairs.
var faro = `timestamp="2026-03-14 06:11:46.397 +0000 UTC" kind=event event_name=visibility_changed event_domain=browser event_data_ctx.account.productId=12345 event_data_ctx.account.sessionGuid=11111111-2222-3333-4444-555555555555 event_data_ctx.account.sessionId=1700000000 event_data_ctx.account.status=4 event_data_ctx.account.userId=10000001 event_data_ctx.app.formFactor=desktop event_data_ctx.app.infoInstance=66666666-7777-8888-9999-aaaaaaaaaaaa event_data_ctx.app.infoRevision=1 event_data_ctx.app.subbrand=shop event_data_ctx.checkout.basket.id=bbbbbbbb-cccc-dddd-eeee-ffffffffffff event_data_ctx.checkout.basket.ref=bbbbbbbb-cccc-dddd-eeee-ffffffffffff:0 event_data_ctx.metrics.userEngagementDuration=0 event_data_ctx.page.href=https://www.example.com/en/shop/orders/active event_data_ctx.profile.id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 event_data_ctx.visit.visitor.id=12121212-3434-5656-7878-909090909090 event_data_ctx.visit.visitor.startTime=2026-03-14T06:08:24.763Z event_data_state=HIDDEN sdk_version=1.3.9 app_name=Shop-Client app_version=2026.3.1 user_id=10000001 session_attr_cf_colo=AMS session_attr_cf_ray=0123456789abcdef session_attr_client_brand=acme session_attr_client_id=13131313-2424-3535-4646-575757575757 session_attr_client_ip=203.0.113.10 session_attr_client_jurisdiction=nl session_attr_client_locale=nl session_attr_client_location=nl session_attr_ff_new_checkout_ab_flag=true session_attr_ff_lobby_layout_ab_flag=true session_attr_profile_id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 session_attr_visit_id=14141414-2525-3636-4747-585858585858 session_attr_visitor_id=12121212-3434-5656-7878-909090909090 session_attr_visitor_location=NL page_url=https://www.example.com/en/shop/orders/active browser_name=Chrome browser_version=140 browser_os="Windows 10" browser_mobile=false browser_userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"`

// go test -bench=BenchmarkFaroEvent -benchmem -memprofile memprofile.out -cpuprofile profile.out -benchtime=30s
// go tool pprof -http=:8080 profile.out
func BenchmarkFaroEvent(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sink = Parse(faro)
	}
}

// A long line that matches no strategy — the worst case for the pattern table.
var missLine = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium totam rem aperiam eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt neque porro quisquam est qui dolorem ipsum quia dolor sit amet consectetur adipisci velit sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem"

func BenchmarkParseMiss(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sink = Parse(missLine)
	}
}

// A Go-log-style plain-text line that resolves via the pattern table (the
// timestamp-family positional gates decide how many regexes run).
var patternLine = `2026/07/11 10:00:00 error contacting upstream: connection refused`

func BenchmarkParsePattern(b *testing.B) {
	for n := 0; n < b.N; n++ {
		sink = Parse(patternLine)
	}
}

// The hot-loop shape: one reused Result, no per-line allocation at all.
func BenchmarkParseIntoReused(b *testing.B) {
	var r Result
	for n := 0; n < b.N; n++ {
		ParseInto(line, &r)
	}
	sink = &r
}

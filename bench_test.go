package enrich

import (
	"testing"
)

var line = `{"@timestamp":"2025-03-19T12:10:20.394Z","grpc_status_number":0,"grpc_status":"OK","response_flags":"-","requested_server_name":"entity-live-we.api.row.example.net","upstream_local_address":"172.19.23.22:35290","upstream_service_time":"4","path":"/entity.v1.EntityRelationsService/GetEntities","bytes_received":43,"request_id":"aebbb7bc7eceee11d09084a20f1aa7b4","x_forwarded_for":"172.19.7.14","authority":"entity-live-we.api.row.example.net","bytes_sent":75,"upstream_host":"172.19.18.8:5000","user_agent":"grpc-dotnet/2.67.0 (.NET 8.0.14; CLR 8.0.14; net8.0; linux; arm64) Acme-Feed-Domain/20250317.1","downstream_remote_address":"172.19.7.14:41882","protocol":"HTTP/2","response_code":200,"downstream_local_address":"172.19.23.22:8443","method":"POST","upstream_cluster":"entity-service-blue_service_5000","duration":4}`

// go test -bench=BenchmarkEnrich -benchmem -memprofile memprofile.out -cpuprofile profile.out -benchtime=30s
// BenchmarkEnrich-22     27761505              1300 ns/op             684 B/op          4 allocs/op
func BenchmarkEnrich(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Parse(line)
	}
}

var faro = `timestamp="2025-09-25 06:11:46.397 +0000 UTC" kind=event event_name=visibility_changed event_domain=browser event_data_ctx.account.productId=23699 event_data_ctx.account.sessionGuid=00000000-0000-0000-0000-000000000001 event_data_ctx.account.sessionId=1700000000 event_data_ctx.account.status=4 event_data_ctx.account.userId=10000001 event_data_ctx.app.formFactor=desktop event_data_ctx.app.infoInstance=00000000-0000-0000-0000-000000000002 event_data_ctx.app.infoRevision=1 event_data_ctx.app.subbrand=base event_data_ctx.betting.betslip.id=00000000-0000-0000-0000-000000000003 event_data_ctx.betting.betslip.ref=00000000-0000-0000-0000-000000000003:0 event_data_ctx.metrics.userEngagementDuration=0 event_data_ctx.page.href=https://acme.es/es/es/base/my-bets/active event_data_ctx.profile.id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 event_data_ctx.visit.visitor.id=00000000-0000-0000-0000-000000000004 event_data_ctx.visit.visitor.startTime=2025-09-25T06:08:24.763Z event_data_state=HIDDEN sdk_version=1.3.9 app_name=Acme-Client app_version=20250924.6 user_id=10000001 session_attr_cf_colo=MAD session_attr_cf_ray=98485db8187dcbca session_attr_client_brand=acme session_attr_client_id=00000000-0000-0000-0000-000000000005 session_attr_client_ip=203.0.113.14 session_attr_client_jurisdiction=es session_attr_client_locale=es session_attr_client_location=es session_attr_ff_casino_in_game_menu_ab_flag=true session_attr_ff_casino_lobby_swimlanes_orientation_ab_flag=true session_attr_profile_id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 session_attr_visit_id=00000000-0000-0000-0000-000000000006 session_attr_visitor_id=00000000-0000-0000-0000-000000000004 session_attr_visitor_location=ES page_url=https://acme.es/es/es/base/my-bets/active browser_name=Chrome browser_version=140 browser_os="Windows 10" browser_mobile=false browser_userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"`

//	go test -bench=BenchmarkFaroEvent -benchmem -memprofile memprofile.out -cpuprofile profile.out -benchtime=30s
//	go tool pprof -http=:8080 profile.out
//
// BenchmarkFaroEvent-22   13112888              2743 ns/op             996 B/op          3 allocs/op
func BenchmarkFaroEvent(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Parse(faro)
	}
}

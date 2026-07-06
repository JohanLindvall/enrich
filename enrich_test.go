package enrich

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	log1                 = `{"@t":"2021-09-01T12:00:00Z","@l":"Information","foo":1,"traceID":"12345678901234567890123456789012","spanID":"1234567890123456","resourceID":"RESOURCE-ID","attr":"xyz", "@m":"Hello, World!","val":1.3,"obj":{"key":"value"},"arr":[1,2,3]}`
	log2                 = `2024-05-07T13:50:58.582245Z  INFO source{component_kind="source" component_id=kubernetes_source component_type=kubernetes_logs}:file_server: vector::internal_events::file::source: Found new file to watch. file=/var/log/pods/kube-system_overlay-vpa-cert-webhook-check-8j2pb_00000000-0000-0000-0000-000000000007/overlay-vpa-webhook-generation/0.lo`
	log3                 = `E0507 18:45:23.697929    3747 pod_workers.go:1298] "Error syncing pod, skipping" err="failed to \"StartContainer\" for \"calico-kube-controllers\" with CrashLoopBackOff: \"back-off 5m0s restarting failed container=calico-kube-controllers pod=calico-kube-controllers-6587db486-57mpl_calico-system(00000000-0000-0000-0000-000000000008)\"" pod="calico-system/calico-kube-controllers-6587db486-57mpl" podUID="00000000-0000-0000-0000-000000000008"`
	microsoftInsightsLog = `{"authorization":{"action":"Microsoft.Network/dnsZones/TXT/write","scope":"/subscriptions/00000000-0000-0000-0000-000000000009/resourceGroups/DNS/providers/Microsoft.Network/dnsZones/example.dev/TXT/@"},"caller":"00000000-0000-0000-0000-000000000010","channels":"Operation","claims":{"aud":"https://management.core.windows.net/","iss":"https://sts.windows.net/00000000-0000-0000-0000-000000000011/","iat":"1723706439","nbf":"1723706439","exp":"1723710339","aio":"REDACTED","appid":"00000000-0000-0000-0000-000000000012","appidacr":"1","http://schemas.microsoft.com/identity/claims/identityprovider":"https://sts.windows.net/00000000-0000-0000-0000-000000000011/","idtyp":"app","http://schemas.microsoft.com/identity/claims/objectidentifier":"00000000-0000-0000-0000-000000000010","rh":"REDACTED","http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":"00000000-0000-0000-0000-000000000010","http://schemas.microsoft.com/identity/claims/tenantid":"00000000-0000-0000-0000-000000000011","uti":"REDACTED","ver":"1.0","xms_idrel":"7 28","xms_tcdt":"1390215724"},"correlationId":"00000000-0000-0000-0000-000000000013","description":"","eventDataId":"00000000-0000-0000-0000-000000000014","eventName":{"value":"EndRequest","localizedValue":"End request"},"category":{"value":"Administrative","localizedValue":"Administrative"},"eventTimestamp":"2024-08-15T07:33:48.6456673Z","id":"/subscriptions/00000000-0000-0000-0000-000000000009/resourceGroups/DNS/providers/Microsoft.Network/dnsZones/example.dev/TXT/%40/events/00000000-0000-0000-0000-000000000014/ticks/638593040286456673","level":"Informational","operationId":"00000000-0000-0000-0000-000000000013","operationName":{"value":"Microsoft.Network/dnsZones/TXT/write","localizedValue":"Create or update record set of type TXT"},"resourceGroupName":"DNS","resourceProviderName":{"value":"Microsoft.Network","localizedValue":"Microsoft.Network"},"resourceType":{"value":"Microsoft.Network/dnsZones/TXT","localizedValue":"Microsoft.Network/dnsZones/TXT"},"resourceId":"/subscriptions/00000000-0000-0000-0000-000000000009/resourceGroups/DNS/providers/Microsoft.Network/dnsZones/example.dev/TXT/@","status":{"value":"Succeeded","localizedValue":"Succeeded"},"subStatus":{"value":"OK","localizedValue":"OK (HTTP Status Code: 200)"},"submissionTimestamp":"2024-08-15T07:35:06Z","subscriptionId":"00000000-0000-0000-0000-000000000009","tenantId":"00000000-0000-0000-0000-000000000011","properties":{"statusCode":"OK","serviceRequestId":null,"responseBody":"{\"id\":\"/subscriptions/00000000-0000-0000-0000-000000000009/resourceGroups/dns/providers/Microsoft.Network/dnszones/example.dev/TXT/@\",\"name\":\"@\",\"type\":\"Microsoft.Network/dnszones/TXT\",\"etag\":\"00000000-0000-0000-0000-000000000015\",\"properties\":{\"fqdn\":\"example.dev.\",\"TTL\":300,\"TXTRecords\":[{\"value\":[\"\\\"heritage=external-dns,external-dns/owner=development,external-dns/resource=ingress/devportal/devportal\\\"\"]}],\"targetResource\":{},\"provisioningState\":\"Succeeded\"}}","eventCategory":"Administrative","entity":"/subscriptions/00000000-0000-0000-0000-000000000009/resourceGroups/DNS/providers/Microsoft.Network/dnsZones/example.dev/TXT/@","message":"Microsoft.Network/dnsZones/TXT/write","hierarchy":"00000000-0000-0000-0000-000000000009"},"relatedEvents":[]}`
)

func TestParse_T(t *testing.T) {
	enriched := Parse(log1)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
	assert.Equal(t, log1, enriched.Body)
}

func TestParse_Keep_Handled(t *testing.T) {
	enriched := Parse(log1)
	assert.Equal(t, log1, enriched.Body)
}

func TestParse_TraceId(t *testing.T) {
	enriched := Parse(log1)
	assert.Equal(t, "12345678901234567890123456789012", enriched.TraceID)
}

func TestParse_SpanId(t *testing.T) {
	enriched := Parse(log1)
	assert.Equal(t, "1234567890123456", enriched.SpanID)
}

func TestParse_ResourceId(t *testing.T) {
	enriched := Parse(log1)
	assert.Equal(t, "resource-id", enriched.ResourceID)
}

func TestParse_Timestamp(t *testing.T) {
	enriched := Parse(`{"timestamp":"2021-09-01T12:00:00Z"}`)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_AtTimestamp(t *testing.T) {
	enriched := Parse(`{"@timestamp":"2021-09-01T12:00:00Z"}`)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_Ts(t *testing.T) {
	enriched := Parse(`{"ts":"2021-09-01T12:00:00Z"}`)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_Time(t *testing.T) {
	enriched := Parse(`{"time":"2021-09-01T12:00:00Z"}`)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_Att(t *testing.T) {
	enriched := Parse(`{"@t":"2021-09-01T12:00:00Z"}`)
	assert.Equal(t, "2021-09-01 12:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_logfmt_ts_last(t *testing.T) {
	enriched := Parse(`{"foo=xyz level=bar ts=2024-06-17T17:24:04.687974124Z}`)
	assert.Equal(t, "2024-06-17 17:24:04.687974124 +0000 UTC", enriched.Time.String())
}

func TestParse_azdo_ts(t *testing.T) {
	enriched := Parse(`2024-09-20T12:55:12.8539173Z Start tracking orphan processes.`)
	assert.Equal(t, "2024-09-20 12:55:12.8539173 +0000 UTC", enriched.Time.String())
}

func TestParse_Level(t *testing.T) {
	enriched := Parse(log2)
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Level2(t *testing.T) {
	enriched := Parse(log3)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Properties(t *testing.T) {
	enriched := Parse(`{"properties":{"log":"{\"@l\":\"Error\"}"}}`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Exception(t *testing.T) {
	enriched := Parse(`{"@m":"Unhandled exception","@mt":"Unhandled exception","@x":"System.AggregateException: One or more errors occurred. (A timeout occurred after 30000ms selecting a server using CompositeServerSelector{ Selectors = ReadPreferenceServerSelector{ ReadPreference = { Mode : Primary } }, LatencyLimitingServerSelector{ AllowedLatencyRange = 00:00:00.0150000 }, OperationsCountServerSelector }. Client view of cluster state is { ClusterId : \"1\", ConnectionMode : \"ReplicaSet\", Type : \"ReplicaSet\", State : \"Disconnected\", Servers : [{ ServerId: \"{ ClusterId : 1, EndPoint : \"Unspecified/acme-client-subscriptions-dev.mongo.cosmos.azure.com:10255\" }\", EndPoint: \"Unspecified/acme-client-subscriptions-dev.mongo.cosmos.azure.com:10255\", ReasonChanged: \"Heartbeat\", State: \"Disconnected\", ServerVersion: , TopologyVersion: , Type: \"Unknown\", HeartbeatException: \"MongoDB.Driver.MongoConnectionException: An exception occurred while opening a connection to the server.\n ---> System.Net.Internals.SocketExceptionFactory+ExtendedSocketException (00000005, 0xFFFDFFFF): Name or service not known\n   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName, Boolean justAddresses, AddressFamily addressFamily, ValueStopwatch stopwatch)\n   at System.Net.Dns.GetHostAddresses(String hostNameOrAddress, AddressFamily family)\n   at MongoDB.Driver.Core.Connections.TcpStreamFactory.ResolveEndPoints(EndPoint initial)\n   at MongoDB.Driver.Core.Connections.TcpStreamFactory.CreateStream(EndPoint endPoint, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.SslStreamFactory.CreateStream(EndPoint endPoint, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.BinaryConnection.OpenHelper(CancellationToken cancellationToken)\n   --- End of inner exception stack trace ---\n   at MongoDB.Driver.Core.Connections.BinaryConnection.OpenHelper(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.BinaryConnection.Open(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Servers.ServerMonitor.InitializeConnection(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Servers.ServerMonitor.Heartbeat(CancellationToken cancellationToken)\", LastHeartbeatTimestamp: \"2024-06-26T17:14:00.0575786Z\", LastUpdateTimestamp: \"2024-06-26T17:14:00.0575788Z\" }] }.)\n ---> System.TimeoutException: A timeout occurred after 30000ms selecting a server using CompositeServerSelector{ Selectors = ReadPreferenceServerSelector{ ReadPreference = { Mode : Primary } }, LatencyLimitingServerSelector{ AllowedLatencyRange = 00:00:00.0150000 }, OperationsCountServerSelector }. Client view of cluster state is { ClusterId : \"1\", ConnectionMode : \"ReplicaSet\", Type : \"ReplicaSet\", State : \"Disconnected\", Servers : [{ ServerId: \"{ ClusterId : 1, EndPoint : \"Unspecified/acme-client-subscriptions-dev.mongo.cosmos.azure.com:10255\" }\", EndPoint: \"Unspecified/acme-client-subscriptions-dev.mongo.cosmos.azure.com:10255\", ReasonChanged: \"Heartbeat\", State: \"Disconnected\", ServerVersion: , TopologyVersion: , Type: \"Unknown\", HeartbeatException: \"MongoDB.Driver.MongoConnectionException: An exception occurred while opening a connection to the server.\n ---> System.Net.Internals.SocketExceptionFactory+ExtendedSocketException (00000005, 0xFFFDFFFF): Name or service not known\n   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName, Boolean justAddresses, AddressFamily addressFamily, ValueStopwatch stopwatch)\n   at System.Net.Dns.GetHostAddresses(String hostNameOrAddress, AddressFamily family)\n   at MongoDB.Driver.Core.Connections.TcpStreamFactory.ResolveEndPoints(EndPoint initial)\n   at MongoDB.Driver.Core.Connections.TcpStreamFactory.CreateStream(EndPoint endPoint, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.SslStreamFactory.CreateStream(EndPoint endPoint, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.BinaryConnection.OpenHelper(CancellationToken cancellationToken)\n   --- End of inner exception stack trace ---\n   at MongoDB.Driver.Core.Connections.BinaryConnection.OpenHelper(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Connections.BinaryConnection.Open(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Servers.ServerMonitor.InitializeConnection(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Servers.ServerMonitor.Heartbeat(CancellationToken cancellationToken)\", LastHeartbeatTimestamp: \"2024-06-26T17:14:00.0575786Z\", LastUpdateTimestamp: \"2024-06-26T17:14:00.0575788Z\" }] }.\n   at MongoDB.Driver.Core.Clusters.Cluster.ThrowTimeoutException(IServerSelector selector, ClusterDescription description)\n   at MongoDB.Driver.Core.Clusters.Cluster.WaitForDescriptionChangedHelper.HandleCompletedTask(Task completedTask)\n   at MongoDB.Driver.Core.Clusters.Cluster.WaitForDescriptionChangedAsync(IServerSelector selector, ClusterDescription description, Task descriptionChangedTask, TimeSpan timeout, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Clusters.Cluster.SelectServerAsync(IServerSelector selector, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Clusters.IClusterExtensions.SelectServerAndPinIfNeededAsync(ICluster cluster, ICoreSessionHandle session, IServerSelector selector, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Bindings.ReadPreferenceBinding.GetReadChannelSourceAsync(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Operations.RetryableReadContext.InitializeAsync(CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Operations.RetryableReadContext.CreateAsync(IReadBinding binding, Boolean retryRequested, CancellationToken cancellationToken)\n   at MongoDB.Driver.Core.Operations.ListCollectionsOperation.ExecuteAsync(IReadBinding binding, CancellationToken cancellationToken)\n   at MongoDB.Driver.OperationExecutor.ExecuteReadOperationAsync[TResult](IReadBinding binding, IReadOperation1 operation, CancellationToken cancellationToken)\n   at MongoDB.Driver.MongoDatabaseImpl.ExecuteReadOperationAsync[T](IClientSessionHandle session, IReadOperation1 operation, ReadPreference readPreference, CancellationToken cancellationToken)\n   at MongoDB.Driver.MongoDatabaseImpl.UsingImplicitSessionAsync[TResult](Func2 funcAsync, CancellationToken cancellationToken)\n   at Acme.Manager.Providers.MongoDbProvider.CollectionExistsAsync(String collectionName) in /src/src/Acme.Manager/Providers/MongoDbProvider.cs:line 47\n","ThreadId":1}`)
	assert.Equal(t, "System.AggregateException", enriched.ExceptionType)
	assert.True(t, strings.HasPrefix(enriched.ExceptionMessage, "One or more errors occurred."))
	assert.True(t, strings.HasPrefix(enriched.ExceptionStackTrace, " ---> System.Net.Internals.SocketExceptionFactory"))
}

func TestParse_ResourceId_ResourceGroup(t *testing.T) {
	enriched := Parse(microsoftInsightsLog)
	assert.Equal(t, "/subscriptions/00000000-0000-0000-0000-000000000009/resourcegroups/dns/providers/microsoft.network/dnszones/example.dev/txt/@", enriched.ResourceID)
	assert.Equal(t, "/subscriptions/00000000-0000-0000-0000-000000000009/resourcegroups/dns", enriched.ResourceGroup)
}

func TestParse_TurboCache(t *testing.T) {
	enriched := Parse(`{"severity":"INFO","level":30,"time":1728314132247,"pid":7,"hostname":"remote-cache-0","reqId":"Jqbyb5psTOSlYycP47IzBw-97566","res":{"statusCode":200},"responseTime":0.7599979937076569,"message":"request completed"}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-07 15:15:32.247 +0000 UTC", enriched.Time.String())
}

func TestParse_Github_Runner(t *testing.T) {
	enriched := Parse(`[WORKER 2024-10-07 15:15:43Z INFO HostContext] Well known directory 'Work': '/home/runner/_work'`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-07 15:15:43 +0000 UTC", enriched.Time.String())
}

func TestParse_Envoy_OK(t *testing.T) {
	enriched := Parse(`{"user_agent":"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148","authority":"entitylegacyadapter-live-ne.api.row.example.net","bytes_received":516,"downstream_remote_address":"203.0.113.4:22694","@timestamp":"2024-10-07T15:59:12.289Z","x_forwarded_for":"203.0.113.16,203.0.113.16,203.0.113.4","downstream_local_address":"172.19.8.8:8443","protocol":"HTTP/2","requested_server_name":"entitylegacyadapter-live-ne.api.row.example.net","response_flags":"-","upstream_service_time":"0","request_id":"00000000-0000-0000-0000-000000000016","method":"POST","duration":1,"upstream_local_address":"172.19.8.8:43540","upstream_cluster":"search-entitylegacyadapter-green_service_5000","upstream_host":"172.19.8.53:5000","path":"/api/interaction","bytes_sent":0,"response_code":200}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "00000000000000000000000000000016", enriched.TraceID)
}

func TestParse_Envoy_Fail(t *testing.T) {
	enriched := Parse(`{"downstream_remote_address":"172.19.11.52:34206","grpc_status_number":7,"requested_server_name":"entity-live-ne.api.row.example.net","downstream_local_address":"172.19.9.4:8443","user_agent":"grpc-dotnet/2.63.0 (.NET 8.0.8; CLR 8.0.8; net8.0; linux; arm64) Acme-Feed-Posts-Source-Offer/20240926.1","bytes_received":402,"upstream_cluster":"entity-service-green_service_5000","@timestamp":"2024-10-07T16:06:54.717Z","path":"/entity.v1.EntityIdMapperService/Map","grpc_status":"PermissionDenied","protocol":"HTTP/2","duration":0,"response_flags":"UAEX","response_code":200,"x_forwarded_for":"172.19.11.52","request_id":"d735f59cd49fc25425279bd09798ece8","bytes_sent":0,"method":"POST","authority":"entity-live-ne.api.row.example.net"}`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "d735f59cd49fc25425279bd09798ece8", enriched.TraceID)
}

func TestParse_PlainText(t *testing.T) {
	var plainTextLog = `INFO: Any empty folders will not be processed, because source and/or destination doesn't have full folder support`
	enriched := Parse(plainTextLog)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "0001-01-01 00:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_LaunchDarkly(t *testing.T) {
	var launchDarkly1 = `2024-10-07 13:48:24.929 +00:00 [LaunchDarkly.Sdk.Evaluation] INFO: Unknown feature flag "clips-enable-go-to-profile"; returning default value`
	var launchDarkly2 = `2024-10-07 14:42:57.625 +00:00 [LaunchDarkly.Sdk.Events] WARN: Error (System.Net.Http.HttpRequestException: An error occurred while sending the request. (caused by:`
	enriched1 := Parse(launchDarkly1)
	enriched2 := Parse(launchDarkly2)
	assert.Equal(t, "2024-10-07 13:48:24.929 +0000 UTC", enriched1.Time.String())
	assert.Equal(t, "2024-10-07 14:42:57.625 +0000 UTC", enriched2.Time.String())
	assert.Equal(t, "info", enriched1.Severity)
	assert.Equal(t, "warn", enriched2.Severity)
}

func TestParse_Vector(t *testing.T) {
	enriched := Parse(`2024-10-08T06:42:37.720009Z ERROR sink{component_kind="sink" component_id=loki_sink component_type=loki}:request{request_id=586}: vector_common::internal_event::component_events_dropped: Events dropped intentional=false count=274 reason="Service call failed. No retries or retries exhausted." internal_log_rate_limit=true"`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:42:37.720009 +0000 UTC", enriched.Time.String())
}

func TestParse_TurborepoRemoteCache(t *testing.T) {
	enriched := Parse(`{"severity":"INFO","level":30,"time":1728368183944,"pid":7,"hostname":"remote-cache-0","reqId":"Jqbyb5psTOSlYycP47IzBw-138328","res":{"statusCode":200},"responseTime":0.2516399919986725,"message":"request completed"}`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:16:23.944 +0000 UTC", enriched.Time.String())
}

func TestParse_NgAlert(t *testing.T) {
	enriched := Parse(`logger=ngalert.sender.router rule_uid=XXYfpoNVk org_id=1 t=2024-10-08T14:42:46.051254789Z level=info msg="Sending alerts to local notifier" count=3"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 14:42:46.051254789 +0000 UTC", enriched.Time.String())
}

func TestParse_Promtail(t *testing.T) {
	enriched := Parse(`ts=2024-10-08T14:43:38.589263678Z caller=log.go:168 level=info msg="Waiting for /var/log/host/gh-diag/cbuild/pages/00000000-0000-0000-0000-000000000017_00000000-0000-0000-0000-000000000018_1.log to appear..."`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 14:43:38.589263678 +0000 UTC", enriched.Time.String())
}

func TestParse_NginxErr(t *testing.T) {
	enriched := Parse(`2024/10/08 14:52:47 [error] 1394450#1394450: unexpected DNS response for oauth2-proxy.ingress.svc.cluster.local`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2024-10-08 14:52:47 +0000 UTC", enriched.Time.String())
}

func TestParse_EnvoyInfo(t *testing.T) {
	enriched := Parse(`[2024-10-08 14:50:33.337][1][info][upstream] [source/common/upstream/cds_api_helper.cc:71] cds: added/updated 0 cluster(s), skipped 60 unmodified cluster(s)`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 14:50:33.337 +0000 UTC", enriched.Time.String())
}

func TestParse_CloseChannels(t *testing.T) {
	enriched := Parse(`2024-10-08 14:55:10.587 [info] <0.7545.176> Closing all channels from connection '172.19.4.4:38958 -> 172.19.5.30:5672' because it has been closed`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 14:55:10.587 +0000 UTC", enriched.Time.String())
}

func TestParse_SkippingService(t *testing.T) {
	enriched := Parse(`I1008 15:00:59.214583       1 utils.go:135] "Skipping service due to cluster IP" service="client-domain-reactions/domain-service-live" clusterIP="`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 15:00:59.214583 +0000 UTC"[4:], enriched.Time.String()[4:]) // Skipping year due to braindead klog format
}

func TestParse_Cloudflared(t *testing.T) {
	enriched := Parse(`2024-10-08T06:31:22Z WRN Your version 2024.4.1 is outdated. We recommend upgrading it to 2024.9.1`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:31:22 +0000 UTC", enriched.Time.String())
}

func TestParse_NginxIngress(t *testing.T) {
	enriched := Parse(`203.0.113.11 - - [08/Oct/2024:06:42:27 -0700] "POST /api/completions HTTP/1.1" 200 658 "-" "RestSharp/110.2.0.0" 650 0.023 [base-search-service-search-service-5000] [] 10.244.1.16:5000 658 0.023 200 134828790ba4a09d748ed1526be8de50`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 13:42:27 +0000 UTC", enriched.Time.String())
}

func TestParse_DashboardMetricsScraper(t *testing.T) {
	enriched := Parse(`10.244.2.51 - - [08/Oct/2024:06:43:18 +0000] "GET /healthz HTTP/1.1" 404 13 "" "dashboard/v2.7.0"`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:43:18 +0000 UTC", enriched.Time.String())
}

func TestParse_KubernetesMetricsScraper(t *testing.T) {
	enriched := Parse(`172.19.7.15 - - [08/Oct/2024:06:44:25 +0000] "GET /healthz HTTP/1.1" 200 13 "" "dashboard/v0.0.0 (linux/arm64) kubernetes/$Format"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:44:25 +0000 UTC", enriched.Time.String())
}

func TestParse_Registry(t *testing.T) {
	enriched := Parse(`172.19.6.253 - - [08/Oct/2024:06:43:06 +0000] "HEAD /v2/gha-script-base-client/blobs/sha256:42a07e277b07d2f6211f0666218223c018d1cfb9731d05c4d7549cf96f8857c9 HTTP/1.1" 200 0 "" "buildkit/v0.16"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:43:06 +0000 UTC", enriched.Time.String())
}

func TestParse_MetricsScraper(t *testing.T) {
	enriched := Parse(`10.244.5.1 - - [08/Oct/2024:06:55:21 +0000] "GET / HTTP/1.1" 200 6 "" "kube-probe/1.27"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:55:21 +0000 UTC", enriched.Time.String())
}

func TestParse_Kubernetes_Event(t *testing.T) {
	enriched := Parse(`name=domain-service-684dd55c5c-hmjc5 kind=Pod objectAPIversion=v1 objectRV=184488308 eventRV=188743881 sourcecomponent=kubelet sourcehost=aks-system-00000000-vmss000000 reason=Unhealthy type=Warning count=64853 msg="(combined from similar events): Liveness probe errored: rpc error: code = Unknown desc = failed to exec in container: failed to start exec \"428178d2be79d3602ca62ca6cca774a337aeeb933210abe15b9d80f148a1379f\": OCI runtime exec failed: exec failed: unable to start container process: exec: \"/liveness/liveness_check\": stat /liveness/liveness_check: no such file or directory: unknown""`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "0001-01-01 00:00:00 +0000 UTC", enriched.Time.String())
}

func TestParse_MsLog(t *testing.T) {
	enriched := Parse(`[08/10/2024 17:00:08 INF Microsoft.Hosting.Lifetime 17  ] Application is shutting down..."`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 17:00:08 +0000 UTC", enriched.Time.String())
}

func TestParse_NginxUnprivileged(t *testing.T) {
	enriched := Parse(`172.19.8.33 - - [08/Oct/2024:06:45:43 +0000]  204 "POST /loki/api/v1/push HTTP/1.1" 0 "-" "canary-push/k218-659f542" "-"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:45:43 +0000 UTC", enriched.Time.String())
}

func TestParse_MS(t *testing.T) {
	enriched := Parse(`[08/10/2024 06:00:07 ERR Acme.Entity.CasinoAvailability.Service.BlobContainerService 14  ] New data retrieved, uploading file entity-casinoavailability/v1/release/casino-availability.json.br"`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:00:07 +0000 UTC", enriched.Time.String())
}

func TestParse_ExternalDns(t *testing.T) {
	enriched := Parse(`time="2024-10-09T08:03:05Z" level=debug msg="Skipping endpoint test-userid-service-tc2.api.qa.example.dev 300 IN A  203.0.113.15 [] because owner id does not match, found: \"acme-qa-we\", required: \"dev-we\""`)
	assert.Equal(t, "debug", enriched.Severity)
	assert.Equal(t, "2024-10-09 08:03:05 +0000 UTC", enriched.Time.String())
}

func TestParse_DevDocs(t *testing.T) {
	enriched := Parse(`[09/10/2024 08:19:42 INFO devdocshub.storage 9] Refresh loop finished devdocs`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-09 08:19:42 +0000 UTC", enriched.Time.String())
}

func TestParse_LowCoder(t *testing.T) {
	enriched := Parse(`2024-10-09 08:18:10.250 INFO org.lowcoder.runner.task.IoHeartBeatTask#lambda$ping$0:34    [lettuce-epollEventLoop-9-1]: schedule ping executed, result: true`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-09 08:18:10.25 +0000 UTC", enriched.Time.String())
}

func TestParse_WatchLoop(t *testing.T) {
	enriched := Parse(`2024-10-09 08:43:27 starting watch loop"`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-09 08:43:27 +0000 UTC", enriched.Time.String())
}

func TestParse_OpenPolicyAgent(t *testing.T) {
	enriched := Parse(`2024/10/08 06:54:03 http: TLS handshake error from 172.19.10.25:47598: EOF`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-08 06:54:03 +0000 UTC", enriched.Time.String())
}

func TestParse_AzureCNS(t *testing.T) {
	enriched := Parse(`2024/10/08 06:56:51 [1] [releaseIPConfigs] Releasing pod with key aab53256-eth0"`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-08 06:56:51 +0000 UTC", enriched.Time.String())
}

func TestParse_Configmap_Reload(t *testing.T) {
	enriched := Parse(`2024/10/08 06:36:55 Watching directory: "/etc/alloy"`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-08 06:36:55 +0000 UTC", enriched.Time.String())
}

func TestParse_Azdo_Agent(t *testing.T) {
	enriched := Parse(`2024-10-08 06:32:14Z: Job Deploy acme-qa completed with result: Succeeded`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-08 06:32:14 +0000 UTC", enriched.Time.String())
}

func TestParse_Github_Agent(t *testing.T) {
	enriched := Parse(`2024-10-08 06:34:30Z: Running job: Test packages`)
	assert.Empty(t, enriched.Severity)
	assert.Equal(t, "2024-10-08 06:34:30 +0000 UTC", enriched.Time.String())
}

func TestParse_Oauth2Proxy(t *testing.T) {
	enriched := Parse(`244.2.33:35634 - d131ad61e0daeb93e02b0f6b9f6a8260 - foo@bar.com [2024/10/08 06:46:40] oauth2-proxy.ingress.svc.cluster.local GET - "/oauth2/auth" HTTP/1.1 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36" 202 0 0.000`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:46:40 +0000 UTC", enriched.Time.String())
}

func TestParse_Oauth2Proxy_Fail(t *testing.T) {
	enriched := Parse(`172.19.5.6:48444 - 9d3111704c7e2e31616778934f522c10 - - [2024/10/08 06:47:55] oauth2-proxy.ingress.svc.cluster.local GET - "/oauth2/auth" HTTP/1.1 "Azure Traffic Manager Endpoint Monitor" 401 13 0.00`)
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:47:55 +0000 UTC", enriched.Time.String())
}

func TestParse_HttpEcho(t *testing.T) {
	enriched := Parse(`2024/10/08 06:38:47 blackbox-ping-we.api.afr.example.net 172.19.0.7:54380 "GET / HTTP/1.1" 200 12 "Blackbox Exporter/" 6.68µs"`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2024-10-08 06:38:47 +0000 UTC", enriched.Time.String())
}

func TestParse_GoMicro(t *testing.T) {
	enriched := Parse(`2024/11/05 14:13:11.400089 Cost for acme-infrastructure: 677.652104`)
	assert.Equal(t, "2024-11-05 14:13:11.400089 +0000 UTC", enriched.Time.String())
}

func TestParse_Envoy_ERROR(t *testing.T) {
	enriched := Parse(`{"upstream_local_address":"172.19.5.94:33042","duration":2001,"path":"/healthz/running","method":"GET","bytes_received":0,"protocol":"HTTP/1.1","downstream_remote_address":"172.19.10.17:45998","downstream_local_address":"172.19.5.94:8443","response_flags":"ERROR","response_code":0,"requested_server_name":"feed-master.api.example.dev","x_forwarded_for":"172.19.10.17","request_id":"00000000-0000-0000-0000-000000000019","upstream_cluster":"feed-proxy-master_base-feed-proxy_80","@timestamp":"2024-11-25T14:57:23.461Z","bytes_sent":0,"upstream_host":"172.19.3.36:5000","authority":"feed-master.api.example.dev"}`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Envoy_HTTP_Downstream_Reset(t *testing.T) {
	enriched := Parse(`{"x_forwarded_for":"203.0.113.13,203.0.113.13,203.0.113.19","response_code":0,"@timestamp":"2025-03-11T11:03:05.461Z","method":"POST","user_agent":"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36","bytes_sent":0,"requested_server_name":"graphql-live-we.api.afr.example.net","upstream_host":"172.19.1.58:5001","downstream_local_address":"172.19.17.17:8443","request_id":"00000000-0000-0000-0000-000000000020","path":"/graphql?nogeoredirect=1","duration":10,"bytes_received":1962,"protocol":"HTTP/2","upstream_local_address":"172.19.17.17:53620","response_flags":"DR","upstream_cluster":"base-infra-graphql-live_gateway_5001","authority":"graphql-live-we.api.afr.example.net","downstream_remote_address":"203.0.113.19:61866"}`)
	assert.Equal(t, "2025-03-11 11:03:05.461 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Envoy_HTTP_Downstream_Disconnect(t *testing.T) {
	enriched := Parse(`{"method":"POST","x_forwarded_for":"172.19.18.38","downstream_local_address":"172.19.9.125:8443","downstream_remote_address":"172.19.18.38:40336","bytes_sent":0,"@timestamp":"2024-11-25T15:02:08.288Z","path":"/offer.v1.OfferService/SubscribeChangedEvents","bytes_received":32,"request_id":"0f6d15d387356faad94cd12dca767dd3","upstream_local_address":"172.19.9.125:34028","response_code":0,"upstream_host":"172.19.18.120:5000","upstream_cluster":"offer-service-master_basebook-core-mapper_5000","response_flags":"DC","requested_server_name":"offer-master.api.example.dev","user_agent":"grpc-dotnet/2.65.0 (.NET 8.0.11; CLR 8.0.11; net8.0; linux; arm64) Acme-Offer-Domain/20241122.1","protocol":"HTTP/2","authority":"offer-master.api.example.dev","duration":12009}`)
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_MemcachedExporter(t *testing.T) {
	enriched := Parse(`time=2025-01-09T10:53:50.011Z level=INFO source=tls_config.go:350 msg="TLS is disabled." http2=false address=[::]:9150`)
	assert.Equal(t, "2025-01-09 10:53:50.011 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_ACR(t *testing.T) {
	enriched := Parse(`{ "time": "2025-01-30T14:19:15.1931730Z", "category": "ContainerRegistryRepositoryEvents", "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000009/RESOURCEGROUPS/DOCKER/PROVIDERS/MICROSOFT.CONTAINERREGISTRY/REGISTRIES/EXAMPLE", "operationName": "Pull", "identity": "user@example.com", "location": "westeurope", "resultType": "HttpStatusCode", "resultDescription": "404", "durationMs": "38.212784", "callerIpAddress": "203.0.113.18", "correlationId": "00000000-0000-0000-0000-000000000021", "properties": {"tag":"sha256:2a871364028e4fcc58cb139239390bc242fa7acee3aaa22ab200422d7682084c","digest":"<nil>","mediaType":"<nil>","repository":"tipster-service","artifactType":"acr.docker","tenantId":"00000000-0000-0000-0000-000000000011","loginServer":"example.azurecr.io","userAgent":"acr-cleanup azsdk-go-azcontainerregistry/v0.2.2 (go1.23.5; linux)"}, "RegionStamp": "weu-3"}`)
	assert.Equal(t, "2025-01-30 14:19:15.193173 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Envoy_TCP(t *testing.T) {
	enriched := Parse(`{"upstream_host":"172.19.6.110:5672","@timestamp":"2025-03-11T10:24:28.592Z","response_flags":"-","duration":252,"upstream_cluster":"base-baseintegration-xapiproxy_rabbitmq-internal_5672","bytes_received":184,"bytes_sent":8,"downstream_local_address":"172.19.6.88:8443","downstream_remote_address":"203.0.113.8:38663","upstream_local_address":"172.19.6.88:57520","response_code":0,"requested_server_name":"xapi-mq-internal-we.row-uat.example.net"}`)
	assert.Equal(t, "2025-03-11 10:24:28.592 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestAnsiColor(t *testing.T) {
	line := "\x1b[90m2025-04-02T12:23:03.274996485Z\x1b[0m \x1b[31;32;33mWRN\x1b[0m ETL: did not find allocations for asset key: /kafka/kafka-cluster-kafka-lb-bootstrap"
	enriched := Parse(line)
	assert.Equal(t, "2025-04-02 12:23:03.274996485 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
	assert.Equal(t, line, enriched.Body)
}

func TestKafka(t *testing.T) {
	enriched := Parse(`%4|1744173504.870|FAIL|rdkafka#producer-1| [thrd:sasl_plaintext://kafka-cluster-kafka-bootstrap.kafka.svc.cluste]: sasl_plaintext://kafka-cluster-kafka-bootstrap.kafka.svc.cluster.local:9098/bootstrap: Connection setup timed out in state CONNECT (after 30029ms in state CONNECT)`)
	assert.Equal(t, "2025-04-09 04:38:24.869999885 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Mirrormaker(t *testing.T) {
	enriched := Parse(`2025-05-06 06:08:24,950 INFO 172.25.1.8 - - [06/May/2025:06:08:24 +0000] "GET / HTTP/1.1" 200 91 "-" "kube-probe/1.31" 1 (org.apache.kafka.connect.runtime.rest.RestServer) [qtp1239462179-7686]`)
	assert.Equal(t, "2025-05-06 06:08:24.95 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Mirrormaker_NoMillis(t *testing.T) {
	enriched := Parse(`2025-05-06 06:10:14 INFO  AbstractOperator:546 - Reconciliation #1916(timer) KafkaMirrorMaker2(offer-popularity-service/offer-popularity): reconciled`)
	assert.Equal(t, "2025-05-06 06:10:14 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestKafka_Metrics_Error(t *testing.T) {
	for i, tt := range []struct {
		line string
		time string
	}{
		{
			`E0506 04:53:43.045705      10 kafka_exporter.go:443] Cannot get oldest offset of topic __consumer_offsets partition 49: kafka server: Tried to send a message to a replica that is not the leader for some partition. Your metadata is out of date`,
			`2025-05-06 04:53:43.045705 +0000 UTC`,
		},
		{
			`E0506 04:51:50.809526      10 kafka_exporter.go:431] Cannot get current offset of topic offer-popularity-mm-offsets partition 0: kafka server: In the middle of a leadership election, there is currently no leader for this partition and hence it is unavailable for writes`,
			`2025-05-06 04:51:50.809526 +0000 UTC`,
		},
		{
			`E0507 04:18:50.119187      12 kafka_exporter.go:431] Cannot get current offset of topic __consumer_offsets partition 42: kafka server: Tried to send a message to a replica that is not the leader for some partition. Your metadata is out of date`,
			`2025-05-07 04:18:50.119187 +0000 UTC`,
		},
		{
			`E0507 04:18:35.902986      12 kafka_exporter.go:422] Cannot get leader of topic __consumer_offsets partition 21: kafka server: In the middle of a leadership election, there is currently no leader for this partition and hence it is unavailable for writes`,
			`2025-05-07 04:18:35.902986 +0000 UTC`,
		},
	} {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			enriched := Parse(tt.line)
			assert.Equal(t, "error", enriched.Severity)
			assert.Equal(t, tt.time[4:], enriched.Time.String()[4:]) // Skipping year due to braindead klog format
		})
	}
}

func TestParse_Kubeaud(t *testing.T) {
	enriched := Parse(`{ "category": "kube-audit-admin", "operationName": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read", "properties": {"containerID":"f8a16dab6ad97c3d34deb82c5ac2eb5cc8ec68bfb2ff4b5a835dd98c6bd7aa5c","log":"{\"kind\":\"Event\",\"apiVersion\":\"audit.k8s.io\/v1\",\"level\":\"RequestResponse\",\"auditID\":\"00000000-0000-0000-0000-000000000024\",\"stage\":\"ResponseComplete\",\"requestURI\":\"\/api\/v1\/namespaces\/entity-service-blue\/pods\/shard-sport2-58ff578d97-gsxxc\/eviction\",\"verb\":\"create\",\"user\":{\"username\":\"aksService\",\"groups\":[\"system:masters\",\"system:authenticated\"]},\"sourceIPs\":[\"172.31.16.220\"],\"userAgent\":\"cluster-autoscaler\/v0.0.0 (linux\/amd64) kubernetes\/$Format\",\"objectRef\":{\"resource\":\"pods\",\"namespace\":\"entity-service-blue\",\"name\":\"shard-sport2-58ff578d97-gsxxc\",\"apiVersion\":\"v1\",\"subresource\":\"eviction\"},\"responseStatus\":{\"metadata\":{},\"status\":\"Failure\",\"message\":\"Cannot evict pod as it would violate the pod's disruption budget.\",\"reason\":\"TooManyRequests\",\"details\":{\"causes\":[{\"reason\":\"DisruptionBudget\",\"message\":\"The disruption budget service needs 16 healthy pods and has 16 currently\"}]},\"code\":429},\"requestObject\":{\"kind\":\"Eviction\",\"apiVersion\":\"policy\/v1beta1\",\"metadata\":{\"name\":\"shard-sport2-58ff578d97-gsxxc\",\"namespace\":\"entity-service-blue\",\"creationTimestamp\":null},\"deleteOptions\":{\"gracePeriodSeconds\":30}},\"responseObject\":{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"Cannot evict pod as it would violate the pod's disruption budget.\",\"reason\":\"TooManyRequests\",\"details\":{\"causes\":[{\"reason\":\"DisruptionBudget\",\"message\":\"The disruption budget service needs 16 healthy pods and has 16 currently\"}]},\"code\":429},\"requestReceivedTimestamp\":\"2025-05-15T12:24:35.363709Z\",\"stageTimestamp\":\"2025-05-15T12:24:35.385521Z\",\"annotations\":{\"authorization.k8s.io\/decision\":\"allow\",\"authorization.k8s.io\/reason\":\"\"}}\n","pod":"kube-apiserver-64f9df5bf5-n82p5","stream":"stdout"}, "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000025/RESOURCEGROUPS/ROW-PROD-AKS/PROVIDERS/MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/ROW-PROD-WE", "serviceBuild": "na", "time": "2025-05-15T12:24:35.385717298Z"}`)
	assert.Equal(t, "2025-05-15 12:24:35.385717298 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Clusterautoscaler(t *testing.T) {
	enriched := Parse(`{ "category": "cluster-autoscaler", "operationName": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read", "properties": {"log":"F0515 16:14:42.957346       1 azure_cloud_provider.go:208] Failed to create Azure Manager: Retriable: false, RetryAfter: 0s, HTTPStatusCode: 400, RawError: azure.BearerAuthorizer#WithAuthorization: Failed to refresh the Token for request to https:\/\/management.azure.com\/subscriptions\/00000000-0000-0000-0000-000000000026\/resourceGroups\/row-uat-ne-node\/providers\/Microsoft.Compute\/virtualMachineScaleSets?api-version=2022-03-01: StatusCode=400 -- Original Error: adal: Refresh request failed. Status Code = '400'. Response body: {\"error\":\"invalid_request\",\"error_description\":\"Multiple user assigned identities exist, please specify the clientId \/ resourceId of the identity in the token request\"} Endpoint http:\/\/169.254.169.254\/metadata\/identity\/oauth2\/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.core.windows.net%2F\n","pod":"cluster-autoscaler-5984cbcb9d-gzt9p","stream":"stderr","containerID":"232b497a37f713c11e8a46ab9415065ee89a908d169483b9c994facd52f68a0c"}, "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000026/RESOURCEGROUPS/ROW-UAT-AKS/PROVIDERS/MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/ROW-UAT-NE", "serviceBuild": "na", "time": "2025-05-15T16:14:42.970100063Z"}`)
	assert.Equal(t, "2025-05-15 16:14:42.970100063 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "fatal", enriched.Severity)
}

func TestParse_Jobs(t *testing.T) {
	enriched := Parse(`{ "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000027/RESOURCEGROUPS/ACME-DATAANALYTICS-PROD/PROVIDERS/MICROSOFT.DATABRICKS/WORKSPACES/BASE-PROD-ACME", "operationVersion": "1.0.0", "identity": "{\"email\":\"System-User\",\"subjectName\":null}", "operationName": "Microsoft.Databricks/jobs/runSucceeded", "time": "2025-05-15T15:58:35Z", "category": "jobs", "properties": {"sourceIPAddress":null,"logId":"00000000-0000-0000-0000-000000000028","serviceName":"jobs","userAgent":null,"response":"{\"statusCode\":200}","sessionId":null,"actionName":"runSucceeded","requestId":"00000000-0000-0000-0000-000000000029","requestParams":"{\"runCreatorUserName\":\"00000000-0000-0000-0000-000000000030\",\"orgId\":\"7887781966444145\",\"clusterId\":\"0515-155604-z497szkq\",\"idInJob\":\"236466838801020\",\"jobClusterType\":\"new\",\"jobId\":\"708062954842468\",\"jobTerminalState\":\"Succeeded\",\"taskKey\":\"Acme-Data-DataBricks-Popularity-userPlacementsV3\",\"jobRunId\":\"236466838801020\",\"jobTriggerType\":\"cron\",\"jobTaskType\":\"notebook\",\"runId\":\"236466838801020\"}"}, "Host": "0515-010532-v1hfphej-10-139-124-2"}`)
	assert.Equal(t, "2025-05-15 15:58:35 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Github_File(t *testing.T) {
	enriched := Parse(`[2025-05-25 15:43:20Z INFO RSAFileKeyManager] Loading RSA key parameters from file /home/runner/.credentials_rsaparams`)
	assert.Equal(t, "2025-05-25 15:43:20 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Promxy(t *testing.T) {
	enriched := Parse(`172.24.1.19 - - [25/May/2025 15:45:56] "GET /-/healthy HTTP/1.1 200 13" 0.000043 `)
	assert.Equal(t, "2025-05-25 15:45:56 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Azure_CNI(t *testing.T) {
	enriched := Parse(`ts=1748239806.3691056 level=info msg="successfully wrote files" sources=azure-vnet,azure-vnet-telemetry outputs=/opt/cni/bin/azure-vnet,/opt/cni/bin/azure-vnet-telemetry cmd=deploy`)
	assert.Equal(t, "2025-05-26 06:10:06.3691056 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Grafana(t *testing.T) {
	enriched := Parse(`logger=tsdb.loki endpoint=queryData pluginId=loki dsName=Loki3 dsUID=loki3 uname=xx@yy.se fromAlert=false t=2025-05-26T07:13:16.063240127Z level=a@1 level=info msg="Response received from loki" duration=817.484533ms stage=databaseRequest statusCode=200 contentLength= start=2025-05-23T07:13:09.027Z end=2025-05-24T07:13:09.027Z step=5m0s query="{deployment_environment=~\"osr-prod\", platform_product_name=~\"acme-socialposts|acme-share\", source_type=\"otel_pod_logs\"} | severity_text =~ "error|warn|fatal" !~ "[hH]ealth [cC]heck" | label_format level=severity_text" queryType=range direction=backward maxLines=803 supportingQueryType=none lokiHost=loki-query-frontend.monitoring-loki3.svc.cluster.local:3100 lokiPath=/loki/api/v1/query_range status=ok`)
	assert.Equal(t, "2025-05-26 07:13:16.063240127 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Tigera_Operator(t *testing.T) {
	enriched := Parse(`2025/05/27 07:46:50 [INFO] Active operator: proceeding`)
	assert.Equal(t, "2025-05-27 07:46:50 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Redis(t *testing.T) {
	for i, tt := range []struct {
		line  string
		level string
		ts    string
	}{
		{
			`1:C 27 May 2025 07:37:41.634 * oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo`,
			"info",
			"2025-05-27 07:37:41.634 +0000 UTC",
		},
		{
			`1:C 27 May 2025 07:19:58.546 # Warning: no config file specified, using the default config. In order to specify a config file use redis-server /path/to/redis.conf`,
			"warn",
			"2025-05-27 07:19:58.546 +0000 UTC",
		},
		{
			`1234:M 27 May 2025 07:19:58.546 . Debug test message`,
			"debug",
			"2025-05-27 07:19:58.546 +0000 UTC",
		},
		{
			`1234:M 27 May 2025 07:19:58 - Trace test message`,
			"debug",
			"2025-05-27 07:19:58 +0000 UTC",
		},
	} {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			enriched := Parse(tt.line)
			assert.Equal(t, tt.level, enriched.Severity)
			assert.Equal(t, tt.ts, enriched.Time.String())
		})
	}
}

func TestParse_Dotnet_Multiple(t *testing.T) {
	enriched := Parse(`{"@t":"2025-05-28T12:54:07.1658134Z","@m":"Generating graph visualization for branch \"\", level Domains","@mt":"Generating graph visualization for branch {Branch}, level {Level}","@i":"b3e299c1","@l":"Information","TraceId":"cec729eec68efbf17c1dd3c113ba661d","SpanId":"c71eb1efd719a7c2","Branch":"","Level":"Domains","SourceContext":"GraphQLFederation.Services.MetadataRequests","RequestId":"0HNCTSJFN6B6M:0000039F","RequestPath":"/auth/viz","ConnectionId":"0HNCTSJFN6B6M","ThreadId":45,"@sn":"Acme-GraphQL-Gateway","@sv":"20250515.1","@sp":"acme-graphql"}`)
	assert.Equal(t, "2025-05-28 12:54:07.1658134 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Grafana_Json(t *testing.T) {
	enriched := Parse(`{"@level":"debug","@message":"Instantiating new gRPC client","@timestamp":"2025-06-03T09:55:05.756019Z","logger":"tsdb.tempo"}`)
	assert.Equal(t, "2025-06-03 09:55:05.756019 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "debug", enriched.Severity)
}

func TestOauth2_Proxy_Warn(t *testing.T) {
	enriched := Parse(`[2025/06/03 08:40:06] [session_store.go:163] WARNING: Multiple cookies are required for this session as it exceeds the 4kb cookie limit. Please use server side session storage (eg. Redis) instead. oauth2 proxy`)
	assert.Equal(t, "2025-06-03 08:40:06 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Azure_StoraRead(t *testing.T) {
	enriched := Parse(`{ "time": "2025-06-30T17:40:58.9025305Z", "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000034/resourceGroups/deploy-base-entity/providers/Microsoft.Storage/storageAccounts/exampleentities/blobServices/default", "category": "StorageRead", "operationName": "GetBlobProperties", "operationVersion": "2022-11-02", "schemaVersion": "1.0", "statusCode": 304, "statusText": "ConditionNotMet", "durationMs": 8, "callerIpAddress": "172.24.1.10:38072", "correlationId": "00000000-0000-0000-0000-000000000035", "identity": {"type":"SAS","tokenHash":"key1(0),SasSignature(0)"}, "location": "westeurope", "properties": {"accountName":"exampleentities","serviceType":"blob","objectKey":"/exampleentities/entity-service/entity-staticentitydata/v2/release/entities/cs-sp-badminton/entities.json.br","conditionsUsed":"If-None-Match=Monday, 12-May-25 06:18:23 GMT","metricResponseType":"ClientOtherError","serverLatencyMs":8,"requestHeaderSize":393,"responseHeaderSize":146,"tlsVersion":"TLS 1.3","sourceAccessTier":"Invalid"}, "uri": "https://exampleentities.blob.core.windows.net:443/entity-service/entity-staticentitydata/v2/release/entities/cs-sp-badminton/entities.json.br?se=2100-01-01&sp=rlf&sv=2022-11-02&ss=b&srt=sco&sig=XXXXX", "protocol": "HTTPS", "resourceType": "Microsoft.Storage/storageAccounts/blobServices"}`)
	assert.Equal(t, "2025-06-30 17:40:58.9025305 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Azure_AuditEvent(t *testing.T) {
	enriched := Parse(`{ "time": "2025-06-30T17:33:25.0331812Z", "category": "AuditEvent", "operationName": "SecretGet", "resultType": "Success", "correlationId": "00000000-0000-0000-0000-000000000036", "callerIpAddress": "203.0.113.10", "identity": {"claim":{"oid":"00000000-0000-0000-0000-000000000037","appid":"00000000-0000-0000-0000-000000000038","appidacr":"1","iss":"https://sts.windows.net/00000000-0000-0000-0000-000000000011/","xms_az_nwperimid":[],"idtyp":"app","uti":"REDACTED","iat":"1751304503","exp":"1751308403","aud":"00000000-0000-0000-0000-000000000039","nbf":"1751304503"}}, "properties": {"id":"https://acme-secrets-dev.vault.azure.net/secrets/jwt-token-feed-external-api-service/6e6212e131ea47c88a52f387cd07d6e9","clientInfo":"AZURECLI/2.74.0 (DEB) azsdk-python-core/1.31.0 Python/3.12.10 (Linux-5.15.0-1084-azure-aarch64-with-glibc2.39)","httpStatusCode":200,"requestUri":"https://acme-secrets-dev.vault.azure.net/secrets/jwt-token-feed-external-api-service/?api-version=7.4","isAccessPolicyMatch":true,"tlsVersion":"TLS1_3"}, "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000009/RESOURCEGROUPS/SECRETS/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/ACME-SECRETS-DEV", "operationVersion": "7.4", "resultSignature": "OK", "durationMs": "41"}`)
	assert.Equal(t, "2025-06-30 17:33:25.0331812 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Cilium_Logfmt_no_Timestamp(t *testing.T) {
	enriched := Parse(`level=info msg=Started duration=7.950957ms`)
	assert.Equal(t, "info", enriched.Severity)
}

func TestRedpanda_Console(t *testing.T) {
	enriched := Parse(`[2025-07-14 06:54:10,329] INFO 172.19.0.225 - - [14/Jul/2025:06:54:10 +0000] "GET /subjects HTTP/1.1" 200 71 "-" "redpanda-console" 2 (io.confluent.rest-utils.requests)`)
	assert.Equal(t, "info", enriched.Severity)
	assert.Equal(t, "2025-07-14 06:54:10.329 +0000 UTC", enriched.Time.String())
}

func TestGo_Panic(t *testing.T) {
	enriched := Parse(`panic: runtime error: invalid memory address or nil pointer dereference`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestNet_Unhandled_Exception(t *testing.T) {
	enriched := Parse(`Unhandled exception. System.AggregateException: One or more errors occurred. (Resource temporarily unavailable (checkpointsrowprod.blob.core.windows.net:443)) (The operation was canceled.)`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestPython_Traceback_Multi(t *testing.T) {
	enriched := Parse(`Traceback (most recent call last):
  File "/usr/local/lib/python3.13/site-packages/azure/kusto/data/client.py", line 360, in _execute
    response.raise_for_status()
    ~~~~~~~~~~~~~~~~~~~~~~~~~^^`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestNet_Unhandled_Exception_Multiline(t *testing.T) {
	enriched := Parse(
		`Unhandled exception. System.Net.Sockets.SocketException (00000005, 0xFFFDFFFF): Name or service not known
   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName, Boolean justAddresses, AddressFamily addressFamily, Nullable1 startingTimestamp)
   at System.Net.Dns.<>c.<GetHostEntryOrAddressesCoreAsync>b__33_0(Object s, Int64 startingTimestamp)
   at System.Net.Dns.<>c__DisplayClass39_01.<RunAsync>b__0(Task <p0>, Object <p1>)
   at System.Threading.Tasks.ContinuationResultTaskFromTask1.InnerInvoke()
   at System.Threading.ExecutionContext.RunFromThreadPoolDispatchLoop(Thread threadPoolThread, ExecutionContext executionContext, ContextCallback callback, Object state)
--- End of stack trace from previous location ---`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "System.Net.Sockets.SocketException", enriched.ExceptionType)
	assert.Equal(t, "Name or service not known", enriched.ExceptionMessage)
	assert.Equal(t, `   at System.Net.Dns.GetHostEntryOrAddressesCore(String hostName, Boolean justAddresses, AddressFamily addressFamily, Nullable1 startingTimestamp)
   at System.Net.Dns.<>c.<GetHostEntryOrAddressesCoreAsync>b__33_0(Object s, Int64 startingTimestamp)
   at System.Net.Dns.<>c__DisplayClass39_01.<RunAsync>b__0(Task <p0>, Object <p1>)
   at System.Threading.Tasks.ContinuationResultTaskFromTask1.InnerInvoke()
   at System.Threading.ExecutionContext.RunFromThreadPoolDispatchLoop(Thread threadPoolThread, ExecutionContext executionContext, ContextCallback callback, Object state)
--- End of stack trace from previous location ---`, enriched.ExceptionStackTrace)
}

func TestNet_Unhandled_Exception_Multiline_2(t *testing.T) {
	enriched := Parse(
		`Unhandled exception. System.Net.Sockets.SocketException (00000005, 0xFFFDFFFF): Name or service not known
Blablabla
   at System.IdentityModel.Xyz(String hostName, Boolean justAddresses, AddressFamily addressFamily, Nullable1 startingTimestamp)
   at System.Net.Dns.<>c.<GetHostEntryOrAddressesCoreAsync>b__33_0(Object s, Int64 startingTimestamp)
   at System.Net.Dns.<>c__DisplayClass39_01.<RunAsync>b__0(Task <p0>, Object <p1>)`)
	assert.Equal(t, "error", enriched.Severity)
	assert.Equal(t, "System.Net.Sockets.SocketException", enriched.ExceptionType)
	assert.Equal(t, "Name or service not known", enriched.ExceptionMessage)
	assert.Equal(t, `Blablabla
   at System.IdentityModel.Xyz(String hostName, Boolean justAddresses, AddressFamily addressFamily, Nullable1 startingTimestamp)
   at System.Net.Dns.<>c.<GetHostEntryOrAddressesCoreAsync>b__33_0(Object s, Int64 startingTimestamp)
   at System.Net.Dns.<>c__DisplayClass39_01.<RunAsync>b__0(Task <p0>, Object <p1>)`, enriched.ExceptionStackTrace)
}

func TestEnvoy_TraceId(t *testing.T) {
	enriched := Parse(`{"@l":"Info","Status":200,"InputLocation":"tz","InputGeoLocation":"TZ","InputBrand":"acme","InputOperator":"osiris","InputIntegrator":"synapse","InputAcceptLanguage":"sw-TZ","TraceID":"00000000-0000-0000-0000-000000000040","X-Forwarded-Host":"www.acme.co.tz","ResultLocation":"tz","ResultGeoLocation":"TZ","ResultBrand":"acme","ResultOperator":"osiris","ResultIntegrator":"synapse","ResultAcceptLanguage":"sw-TZ","@t":"2025-08-18T10:14:56.031933323Z","@m":"Auth"}`)
	assert.Equal(t, "00000000000000000000000000000040", enriched.TraceID)
}

func TestParse_Faro_Event(t *testing.T) {
	enriched := Parse(`timestamp="2025-09-25 06:11:46.397 +0000 UTC" kind=event event_name=visibility_changed event_domain=browser event_data_ctx.account.productId=23699 event_data_ctx.account.sessionGuid=00000000-0000-0000-0000-000000000001 event_data_ctx.account.sessionId=1700000000 event_data_ctx.account.status=4 event_data_ctx.account.userId=10000001 event_data_ctx.app.formFactor=desktop event_data_ctx.app.infoInstance=00000000-0000-0000-0000-000000000002 event_data_ctx.app.infoRevision=1 event_data_ctx.app.subbrand=base event_data_ctx.betting.betslip.id=00000000-0000-0000-0000-000000000003 event_data_ctx.betting.betslip.ref=00000000-0000-0000-0000-000000000003:0 event_data_ctx.metrics.userEngagementDuration=0 event_data_ctx.page.href=https://acme.es/es/es/base/my-bets/active event_data_ctx.profile.id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 event_data_ctx.visit.visitor.id=00000000-0000-0000-0000-000000000004 event_data_ctx.visit.visitor.startTime=2025-09-25T06:08:24.763Z event_data_state=HIDDEN sdk_version=1.3.9 app_name=Acme-Client app_version=20250924.6 user_id=10000001 session_attr_cf_colo=MAD session_attr_cf_ray=98485db8187dcbca session_attr_client_brand=acme session_attr_client_id=00000000-0000-0000-0000-000000000005 session_attr_client_ip=203.0.113.14 session_attr_client_jurisdiction=es session_attr_client_locale=es session_attr_client_location=es session_attr_ff_casino_in_game_menu_ab_flag=true session_attr_ff_casino_lobby_swimlanes_orientation_ab_flag=true session_attr_profile_id=up-aaaaaaaaaaaaaaaaaaaaaaaa1 session_attr_visit_id=00000000-0000-0000-0000-000000000006 session_attr_visitor_id=00000000-0000-0000-0000-000000000004 session_attr_visitor_location=ES page_url=https://acme.es/es/es/base/my-bets/active browser_name=Chrome browser_version=140 browser_os="Windows 10" browser_mobile=false browser_userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"`)
	assert.Equal(t, "2025-09-25 06:11:46.397 +0000 UTC", enriched.Time.String())
}

func TestParse_Faro_Level(t *testing.T) {
	enriched := Parse(`timestamp="2025-09-25 08:08:09.256 +0000 UTC" kind=log message="[AF] on conversion CUID set to: \"00000000-0000-0000-0000-000000000041\"" level=warn sdk_version=1.3.9 app_name=Acme-Client app_version=20250923.14 session_attr_cf_colo=LHR session_attr_cf_ray=9849083502fc2d9c session_attr_client_brand=acme session_attr_client_id=00000000-0000-0000-0000-000000000042 session_attr_client_ip=203.0.113.3 session_attr_client_jurisdiction=gb session_attr_client_locale=en session_attr_client_location=gb session_attr_ff_casino_lobby_swimlanes_orientation_ab_flag=true session_attr_ff_f_registration_sheet_ab_flag=false session_attr_visit_id=00000000-0000-0000-0000-000000000043 session_attr_visitor_id=00000000-0000-0000-0000-000000000044 session_attr_visitor_location=GB session_attr_wrapper_name=AcmeBaseAndroid session_attr_wrapper_type=SpinSport_Android session_attr_wrapper_version=14.20250910.2 page_url="https://acme.com/gb/en/base?wrapperName=AcmeBaseAndroid&wrapperType=SpinSport_Android&wrapperVersion=14.20250910.2&wrapperAlias=acme.com&deviceId=544c6b915cf4a95e&wrapperStore=googlePlay" browser_name="Chrome WebView" browser_version=140 browser_os="Android unknown" browser_mobile=true browser_userAgent="Mozilla/5.0 (Linux; Android 15; SM-S928B Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/140.0.7339.51 Mobile Safari/537.36"`)
	assert.Equal(t, "2025-09-25 08:08:09.256 +0000 UTC", enriched.Time.String())
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_Faro_Time(t *testing.T) {
	enriched := Parse("timestamp=\"2025-09-29 11:08:03.4 +0000 UTC\" kind=event event_name=external_integration_loading event_domain=browser event_data_ctx.app.formFactor=desktop event_data_ctx.app.infoInstance=00000000-0000-0000-0000-000000000045 event_data_ctx.app.infoRevision=1 event_data_ctx.app.subbrand=base event_data_ctx.betting.betslip.id=00000000-0000-0000-0000-000000000046 event_data_ctx.betting.betslip.ref=00000000-0000-0000-0000-000000000046:0 event_data_ctx.metrics.userEngagementDuration=62882 event_data_ctx.page.href=https://acme.es/es/es/base/event/15850125 event_data_ctx.view.uri=page:base_event/15850125/main-markets event_data_ctx.visit.visitor.id=00000000-0000-0000-0000-000000000047 event_data_ctx.visit.visitor.startTime=2025-09-29T11:06:59.654Z event_data_integrationName=gizmo15850125 event_data_integratorName=gizmo event_data_launchMethod=gizmo event_data_source.address=https://external.acme.es/cdn/gizmo/LaunchGizmo.html event_data_source.method=GET sdk_version=1.3.9 app_name=Acme-Client app_version=20250925.4 session_attr_cf_colo=MAD session_attr_cf_ray=986b0a114874cbe8 session_attr_client_brand=acme session_attr_client_id=00000000-0000-0000-0000-000000000048 session_attr_client_ip=203.0.113.17 session_attr_client_jurisdiction=es session_attr_client_locale=es session_attr_client_location=es session_attr_ff_casino_in_game_menu_ab_flag=true session_attr_ff_casino_lobby_swimlanes_orientation_ab_flag=false session_attr_visit_id=00000000-0000-0000-0000-000000000049 session_attr_visitor_id=00000000-0000-0000-0000-000000000047 session_attr_visitor_location=ES page_url=https://acme.es/es/es/base/event/15850125 browser_name=Chrome browser_version=140 browser_os=\"Windows 10\" browser_mobile=false browser_userAgent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\"")
	assert.Equal(t, "2025-09-29 11:08:03.4 +0000 UTC", enriched.Time.String())
}

func TestParse_Fluentbit(t *testing.T) {
	for i, test := range []struct {
		line, level, time string
	}{
		{line: `[2025/10/29 08:04:54.111110831] [ info] [input:tail:tail.0] inotify_fs_add(): inode=6289740 watch_fd=34 name=/var/log/containers/scaledjob-transcription-4t92r-cpp7w_social-transcription-master_faster-whisper-data-3a28f2691009bc17caa726eeccc03a51a232eaa1e75ddd3add0506df62addd94.log`, level: "info", time: "2025-10-29 08:04:54.111110831 +0000 UTC"},
		{line: `[2025/10/29 10:31:06.699133606] [ info] [http_server] listen iface=0.0.0.0 tcp_port=2020`, level: "info", time: "2025-10-29 10:31:06.699133606 +0000 UTC"},
		{line: `[2025/10/29 10:31:06.746296815] [error] [/src/fluent-bit/plugins/in_tail/tail_fs_inotify.c:147 errno=2] No such file or directory`, level: "error", time: "2025-10-29 10:31:06.746296815 +0000 UTC"},
	} {
		t.Run(fmt.Sprintf("Test %d", i), func(t *testing.T) {
			enriched := Parse(test.line)
			assert.Equal(t, test.level, enriched.Severity, "test %d failed", i)
			assert.Equal(t, test.time, enriched.Time.String(), "test %d failed", i)
		})
	}
}

func TestNet_Unhandled_Exception_Java(t *testing.T) {
	enriched := Parse(
		`org.apache.kafka.common.errors.InterruptException: java.lang.InterruptedException
	at org.apache.kafka.clients.consumer.internals.ConsumerNetworkClient.maybeThrowInterruptException(ConsumerNetworkClient.java:537)
	at org.apache.kafka.clients.consumer.internals.ConsumerNetworkClient.poll(ConsumerNetworkClient.java:298)`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestNet_Unhandled_Exception_Java_Single_Nomatch(t *testing.T) {
	enriched := Parse(
		`org.apache.kafka.common.errors.InterruptException: java.lang.InterruptedException`)
	assert.Empty(t, enriched.Severity)
}

// https://github.com/dotnet/runtime/issues/53914
func TestNet_Connection_processing_ended_abnormally_KeepWarn(t *testing.T) {
	enriched := Parse(`{"@t":"2026-05-12T14:13:14.6091318Z","@m":"Connection processing ended abnormally.","@mt":"Connection processing ended abnormally.","@i":"21e125cb","@l":"Warning","@x":"System.InvalidOperationException: Reading is already in progress.\n   at System.IO.Pipelines.ThrowHelper.ThrowInvalidOperationException_AlreadyReading()\n   at System.IO.Pipelines.Pipe.GetReadResult(ReadResult& result)\n   at System.IO.Pipelines.Pipe.ReadAsync(CancellationToken token)\n   at Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.HttpProtocol.ProcessRequests[TContext](IHttpApplication1 application)\n   at Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http.HttpProtocol.ProcessRequestsAsync[TContext](IHttpApplication1 application)","SourceContext":"Microsoft.AspNetCore.Server.Kestrel","ConnectionId":"0HNLFQL89MBB3","ThreadId":15,"@sn":"Acme-Infra-UserSession","@sv":"20260427.2","@sp":"acme-infrastructure"}`)
	assert.Equal(t, "warn", enriched.Severity)
}

// Genuine memcached socket failures share the "socket read" message but carry a
// SocketException/IOException - they must stay errors.
func TestMemcached_Socket_Error_Stays_Error(t *testing.T) {
	enriched := Parse(`{"@t":"2026-05-19T01:36:17.5997060Z","@m":"An exception happened during socket read","@mt":"An exception happened during socket read","@i":"31db5775","@l":"Error","@x":"System.IO.IOException: Unable to read data from the transport connection: Connection reset by peer.\n ---> System.Net.Sockets.SocketException (104): Connection reset by peer\n   at Aer.Memcached.Client.ConnectionPool.PooledSocket.ReadAsync(Memory1 buffer, Int32 count, CancellationToken token)","TraceId":"af10f94b53d159a5911bfdb2dfcda263","SpanId":"940f4cfcc0f2a537","SourceContext":"Aer.Memcached.Client.CommandExecutor","RequestId":"0HNLL8N6KONFE:00001CA7","RequestPath":"/mapper.v1.MapperService/RefreshProfileMetadata","ConnectionId":"0HNLL8N6KONFE","ThreadId":25,"@sn":"Acme-Infra-IdMapper-Service","@sv":"20260512.1","@sp":"acme-infrastructure"}`)
	assert.Equal(t, "error", enriched.Severity)
}

// Regression: a Go standard logger line whose "[configuration]" tag is extracted
// as the level must not be enriched to fatal.
func TestParse_Configuration_Tag_Not_Fatal(t *testing.T) {
	enriched := Parse(`2026/06/16 14:20:46 [configuration] invalid IPv6PrefixClamp value 0; must be between 120 to 128, defaulting to /120`)
	assert.NotEqual(t, "fatal", enriched.Severity)
}

// A genuine client.go failure (non-cancellation error) must stay error: the
// downgrade requires the "context canceled" err, so it does not over-match.
func TestParse_LokiClientDoFailure_StaysError(t *testing.T) {
	enriched := Parse(`level=error ts=2026-06-29T13:42:09.790718438Z caller=client.go:522 index-store=tsdb-2020-01-01 msg="client do failed for instance 172.19.13.12:9095" err="rpc error: code = Unavailable desc = connection refused"`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_Properties_Response(t *testing.T) {
	// properties.response carries JSON-as-string with an HTTP status; the
	// failing context escalates a 4xx to error.
	enriched := Parse(`{"properties":{"response":"{\"statusCode\":404}"}}`)
	assert.Equal(t, "error", enriched.Severity)

	enriched = Parse(`{"properties":{"response":"{\"statusCode\":200}"}}`)
	assert.Equal(t, "info", enriched.Severity)
}

func TestParse_Properties_HTTPStatusCode(t *testing.T) {
	// properties.httpStatusCode is a deferred response code in a tolerant
	// context: a 4xx maps to warn, not error.
	enriched := Parse(`{"properties":{"httpStatusCode":404}}`)
	assert.Equal(t, "warn", enriched.Severity)
}

func TestParse_ResponseStatus_Code(t *testing.T) {
	// responseStatus.code is applied in a failing context.
	enriched := Parse(`{"responseStatus":{"code":429}}`)
	assert.Equal(t, "error", enriched.Severity)
}

func TestParse_GrpcStatus_OutOfRange(t *testing.T) {
	// A gRPC status above 16 is not a valid code and sets no severity.
	enriched := Parse(`{"grpc_status_number":99}`)
	assert.Empty(t, enriched.Severity)
}

func TestParse_Properties_Log_TraceAndSpan(t *testing.T) {
	// Trace/span IDs lift from a nested properties.log payload.
	enriched := Parse(`{"properties":{"log":"{\"traceID\":\"00000000000000000000000000000001\",\"spanID\":\"0000000000000001\"}"}}`)
	assert.Equal(t, "00000000000000000000000000000001", enriched.TraceID)
	assert.Equal(t, "0000000000000001", enriched.SpanID)
}

func TestParse_GrpcStatus_OK(t *testing.T) {
	// gRPC status 0 with no other severity signal is informational.
	enriched := Parse(`{"grpc_status_number":0}`)
	assert.Equal(t, "info", enriched.Severity)
}

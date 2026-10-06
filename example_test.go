// SPDX-License-Identifier: MIT

package enrich_test

import (
	"fmt"
	"time"

	"github.com/JohanLindvall/enrich"
)

// One call reads all three lines, with no per-source configuration: a Pino
// JSON line (a numeric level and an epoch-millisecond time), a logfmt line,
// and an nginx access line whose 503 is the only severity signal it carries.
//
// This is the README's opening example and the program behind its Go
// Playground link; change the three together.
func ExampleParse() {
	for _, line := range []string{
		`{"level":50,"time":1788264000000,"msg":"timeout","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}`,
		`ts=2026-09-01T12:00:01Z level=warn msg=retrying trace_id=4bf92f3577b34da6a3ce929d0e0e4736`,
		`203.0.113.7 - - [01/Sep/2026:12:00:02 +0000] "GET /api HTTP/1.1" 503 19 "-" "curl/8.5.0"`,
	} {
		r := enrich.Parse(line)
		fmt.Printf("%-7s %s %-5s status=%-3d trace=%s\n",
			r.Format, r.Time.Format(time.RFC3339), r.Severity, r.HTTPStatusCode, r.TraceID)
	}
	// Output:
	// json    2026-09-01T12:00:00Z error status=0   trace=4bf92f3577b34da6a3ce929d0e0e4736
	// logfmt  2026-09-01T12:00:01Z warn  status=0   trace=4bf92f3577b34da6a3ce929d0e0e4736
	// pattern 2026-09-01T12:00:02Z warn  status=503 trace=
}

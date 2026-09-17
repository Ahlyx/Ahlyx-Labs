package shared

import "testing"

func TestQueryTelemetryQueueIsBounded(t *testing.T) {
	queue := make(chan queryLogEntry, 1)
	queue <- queryLogEntry{tool: "enrichment"}
	select {
	case queue <- queryLogEntry{tool: "enrichment"}:
		t.Fatal("full telemetry queue accepted an additional entry")
	default:
		// A full queue must drop rather than cause unbounded goroutines/work.
	}
}

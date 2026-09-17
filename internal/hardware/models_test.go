package hardware

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicTelemetryModelsExcludeHostLayout(t *testing.T) {
	data, err := json.Marshal(struct {
		System  SystemInfo  `json:"system"`
		Disk    DiskInfo    `json:"disk"`
		Network NetworkInfo `json:"network"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hostname", "ip_address", "subnet_mask", "interfaces", "mountpoint", "filesystem", "os_version"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("public telemetry model contains %q: %s", forbidden, data)
		}
	}
}

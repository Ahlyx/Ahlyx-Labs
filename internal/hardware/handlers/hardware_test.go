package handlers

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestSystemTelemetryUsesGenericOSWithoutHostIdentity(t *testing.T) {
	recorder := httptest.NewRecorder()
	HandleSystem(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/hardware/system", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("system status = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"host_os":"`+runtime.GOOS+`"`) {
		t.Fatalf("system response missing generic OS %q: %s", runtime.GOOS, body)
	}
	for _, forbidden := range []string{"hostname", "ip_address", "mountpoint", "interfaces", "os_version"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("system response exposes %q: %s", forbidden, body)
		}
	}
}

func TestFmtDataSizeUsesTebibytesForLargeCounters(t *testing.T) {
	if got := fmtDataSize(220 * 1024 * 1024 * 1024 * 1024); got != "220.0 TiB" {
		t.Fatalf("fmtDataSize large counter = %q", got)
	}
	if got := fmtDataSize(2 * 1024 * 1024 * 1024); got != "2.0 GiB" {
		t.Fatalf("fmtDataSize small counter = %q", got)
	}
}

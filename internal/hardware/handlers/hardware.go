package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	gopsnet "github.com/shirou/gopsutil/v3/net"

	"github.com/Ahlyx/Ahlyx-Labs/internal/hardware"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func fmtGB(bytes uint64) string { return fmt.Sprintf("%.2f GB", float64(bytes)/1073741824) }
func fmtDataSize(bytes uint64) string {
	const gib = uint64(1024 * 1024 * 1024)
	const tib = gib * 1024
	if bytes >= tib {
		return fmt.Sprintf("%.1f TiB", float64(bytes)/float64(tib))
	}
	return fmt.Sprintf("%.1f GiB", float64(bytes)/float64(gib))
}
func fmtMB(bytes uint64) string { return fmt.Sprintf("%.2f MB", float64(bytes)/1048576) }
func fmtPct(pct float64) string { return fmt.Sprintf("%.1f%%", pct) }
func fmtOps(n uint64) string    { return fmt.Sprintf("%d", n) }
func fmtMHz(mhz float64) string { return fmt.Sprintf("%.2f MHz", mhz) }

// ---------------------------------------------------------------------------
// HandleSystem — GET /api/v1/hardware/system
// ---------------------------------------------------------------------------

func HandleSystem(w http.ResponseWriter, r *http.Request) {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "64bit"
	}

	response := hardware.SystemInfo{
		HostOS:       runtime.GOOS,
		Architecture: arch,
	}
	// Runtime identity is useful portfolio telemetry even when gopsutil cannot
	// read optional host metadata in a constrained container.
	if info, err := host.Info(); err == nil {
		response.Platform = info.Platform
		response.Uptime = info.Uptime
	}
	writeJSON(w, http.StatusOK, response)
}

// ---------------------------------------------------------------------------
// HandleCPU — GET /api/v1/hardware/cpu
// ---------------------------------------------------------------------------

func HandleCPU(w http.ResponseWriter, r *http.Request) {
	physical, err := cpu.Counts(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hardware telemetry unavailable")
		return
	}
	logical, err := cpu.Counts(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hardware telemetry unavailable")
		return
	}

	// cpu.Percent with a 200 ms interval gives a non-zero reading without a
	// long block; percpu=false returns one aggregate value.
	percents, err := cpu.Percent(200*time.Millisecond, false)
	usage := "0.0%"
	if err == nil && len(percents) > 0 {
		usage = fmtPct(percents[0])
	}

	// Clock speed from the first reported CPU.
	speed := "0.00 MHz"
	if cpus, err := cpu.Info(); err == nil && len(cpus) > 0 {
		speed = fmtMHz(cpus[0].Mhz)
	}

	writeJSON(w, http.StatusOK, hardware.CPUInfo{
		PhysicalCores: physical,
		TotalCores:    logical,
		CurrentSpeed:  speed,
		CPUUsage:      usage,
	})
}

// ---------------------------------------------------------------------------
// HandleRAM — GET /api/v1/hardware/ram
// ---------------------------------------------------------------------------

func HandleRAM(w http.ResponseWriter, r *http.Request) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hardware telemetry unavailable")
		return
	}
	sw, err := mem.SwapMemory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hardware telemetry unavailable")
		return
	}

	writeJSON(w, http.StatusOK, hardware.RAMInfo{
		Total:     fmtGB(vm.Total),
		Used:      fmtGB(vm.Used),
		Available: fmtGB(vm.Available),
		Usage:     fmtPct(vm.UsedPercent),
		SwapTotal: fmtGB(sw.Total),
		SwapUsed:  fmtGB(sw.Used),
		SwapUsage: fmtPct(sw.UsedPercent),
	})
}

// ---------------------------------------------------------------------------
// HandleDisk — GET /api/v1/hardware/disk
// ---------------------------------------------------------------------------

func HandleDisk(w http.ResponseWriter, r *http.Request) {
	usage, err := disk.Usage("/")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hardware telemetry unavailable")
		return
	}

	// Aggregate disk I/O counters across all devices.
	var totalRead, totalWritten, readOps, writeOps uint64
	if counters, err := disk.IOCounters(); err == nil {
		for _, c := range counters {
			totalRead += c.ReadBytes
			totalWritten += c.WriteBytes
			readOps += c.ReadCount
			writeOps += c.WriteCount
		}
	}

	writeJSON(w, http.StatusOK, hardware.DiskInfo{
		Total:        fmtGB(usage.Total),
		Used:         fmtGB(usage.Used),
		Free:         fmtGB(usage.Free),
		Usage:        fmtPct(usage.UsedPercent),
		TotalRead:    fmtDataSize(totalRead),
		TotalWritten: fmtDataSize(totalWritten),
		ReadOps:      fmtOps(readOps),
		WriteOps:     fmtOps(writeOps),
	})
}

// ---------------------------------------------------------------------------
// HandleNetwork — GET /api/v1/hardware/network
// ---------------------------------------------------------------------------

func HandleNetwork(w http.ResponseWriter, r *http.Request) {
	// Aggregate I/O across all interfaces.
	var bytesSent, bytesRecv, pktsSent, pktsRecv uint64
	if counters, err := gopsnet.IOCounters(false); err == nil && len(counters) > 0 {
		bytesSent = counters[0].BytesSent
		bytesRecv = counters[0].BytesRecv
		pktsSent = counters[0].PacketsSent
		pktsRecv = counters[0].PacketsRecv
	}

	writeJSON(w, http.StatusOK, hardware.NetworkInfo{
		BytesSent:       fmtMB(bytesSent),
		BytesReceived:   fmtMB(bytesRecv),
		PacketsSent:     pktsSent,
		PacketsReceived: pktsRecv,
	})
}

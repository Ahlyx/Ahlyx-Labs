package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

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

func fmtGB(bytes uint64) string  { return fmt.Sprintf("%.2f GB", float64(bytes)/1073741824) }
func fmtMB(bytes uint64) string  { return fmt.Sprintf("%.2f MB", float64(bytes)/1048576) }
func fmtPct(pct float64) string  { return fmt.Sprintf("%.1f%%", pct) }
func fmtOps(n uint64) string     { return fmt.Sprintf("%d", n) }
func fmtMHz(mhz float64) string  { return fmt.Sprintf("%.2f MHz", mhz) }

// ---------------------------------------------------------------------------
// HandleSystem — GET /api/v1/hardware/system
// ---------------------------------------------------------------------------

func HandleSystem(w http.ResponseWriter, r *http.Request) {
	info, err := host.Info()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read host info: "+err.Error())
		return
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "64bit"
	}

	// Processor name: prefer the first CPU's model name; fall back to arch.
	processor := arch
	if cpus, err := cpu.Info(); err == nil && len(cpus) > 0 {
		processor = cpus[0].ModelName
	}

	writeJSON(w, http.StatusOK, hardware.SystemInfo{
		OS:           info.OS,
		OSVersion:    info.PlatformVersion,
		Architecture: arch,
		Hostname:     info.Hostname,
		Processor:    processor,
	})
}

// ---------------------------------------------------------------------------
// HandleCPU — GET /api/v1/hardware/cpu
// ---------------------------------------------------------------------------

func HandleCPU(w http.ResponseWriter, r *http.Request) {
	physical, err := cpu.Counts(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read CPU count: "+err.Error())
		return
	}
	logical, err := cpu.Counts(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read CPU count: "+err.Error())
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
		writeError(w, http.StatusInternalServerError, "failed to read memory: "+err.Error())
		return
	}
	sw, err := mem.SwapMemory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read swap: "+err.Error())
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
	parts, err := disk.Partitions(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read partitions: "+err.Error())
		return
	}

	partitions := make([]hardware.Partition, 0, len(parts))
	for _, p := range parts {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		partitions = append(partitions, hardware.Partition{
			Mountpoint: p.Mountpoint,
			Filesystem: p.Fstype,
			Total:      fmtGB(usage.Total),
			Used:       fmtGB(usage.Used),
			Free:       fmtGB(usage.Free),
			Usage:      fmtPct(usage.UsedPercent),
		})
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
		Partitions:   partitions,
		TotalRead:    fmtGB(totalRead),
		TotalWritten: fmtGB(totalWritten),
		ReadOps:      fmtOps(readOps),
		WriteOps:     fmtOps(writeOps),
	})
}

// ---------------------------------------------------------------------------
// HandleNetwork — GET /api/v1/hardware/network
// ---------------------------------------------------------------------------

func HandleNetwork(w http.ResponseWriter, r *http.Request) {
	ifaces, err := gopsnet.Interfaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read interfaces: "+err.Error())
		return
	}

	interfaces := make([]hardware.NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		for _, addr := range iface.Addrs {
			ip, ipNet, err := net.ParseCIDR(addr.Addr)
			if err != nil {
				continue
			}
			// Skip loopback and link-local.
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			mask := subnetMaskString(ipNet.Mask)
			interfaces = append(interfaces, hardware.NetworkInterface{
				Interface:  iface.Name,
				IPAddress:  ip.String(),
				SubnetMask: mask,
			})
		}
	}

	// Aggregate I/O across all interfaces.
	var bytesSent, bytesRecv, pktsSent, pktsRecv uint64
	if counters, err := gopsnet.IOCounters(false); err == nil && len(counters) > 0 {
		bytesSent = counters[0].BytesSent
		bytesRecv = counters[0].BytesRecv
		pktsSent = counters[0].PacketsSent
		pktsRecv = counters[0].PacketsRecv
	}

	writeJSON(w, http.StatusOK, hardware.NetworkInfo{
		Interfaces:      interfaces,
		BytesSent:       fmtMB(bytesSent),
		BytesReceived:   fmtMB(bytesRecv),
		PacketsSent:     pktsSent,
		PacketsReceived: pktsRecv,
	})
}

// subnetMaskString converts a net.IPMask to dotted-decimal notation.
func subnetMaskString(mask net.IPMask) string {
	parts := make([]string, len(mask))
	for i, b := range mask {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return strings.Join(parts, ".")
}

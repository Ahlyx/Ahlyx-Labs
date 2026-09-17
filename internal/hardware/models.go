package hardware

// SystemInfo holds generic runtime telemetry without host identity or patch data.
type SystemInfo struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Uptime       uint64 `json:"uptime_seconds"`
}

// CPUInfo holds processor speed and utilisation data.
type CPUInfo struct {
	PhysicalCores int    `json:"physical_cores"`
	TotalCores    int    `json:"total_cores"`
	CurrentSpeed  string `json:"current_speed"`
	CPUUsage      string `json:"cpu_usage"`
}

// RAMInfo holds memory utilisation data.
type RAMInfo struct {
	Total     string `json:"total"`
	Used      string `json:"used"`
	Available string `json:"available"`
	Usage     string `json:"usage"`
	SwapTotal string `json:"swap_total"`
	SwapUsed  string `json:"swap_used"`
	SwapUsage string `json:"swap_usage"`
}

// DiskInfo holds aggregate disk capacity and I/O only.
type DiskInfo struct {
	Total        string `json:"total"`
	Used         string `json:"used"`
	Free         string `json:"free"`
	Usage        string `json:"usage"`
	TotalRead    string `json:"total_read"`
	TotalWritten string `json:"total_written"`
	ReadOps      string `json:"read_ops"`
	WriteOps     string `json:"write_ops"`
}

// NetworkInfo holds aggregate network I/O without interface inventory.
type NetworkInfo struct {
	BytesSent       string `json:"bytes_sent"`
	BytesReceived   string `json:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
}

package hardware

// SystemInfo holds OS and hardware identity data.
type SystemInfo struct {
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	Processor    string `json:"processor"`
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

// Partition holds usage data for a single disk partition.
type Partition struct {
	Mountpoint string `json:"mountpoint"`
	Filesystem string `json:"filesystem"`
	Total      string `json:"total"`
	Used       string `json:"used"`
	Free       string `json:"free"`
	Usage      string `json:"usage"`
}

// DiskInfo holds aggregate disk I/O and per-partition data.
type DiskInfo struct {
	Partitions   []Partition `json:"partitions"`
	TotalRead    string      `json:"total_read"`
	TotalWritten string      `json:"total_written"`
	ReadOps      string      `json:"read_ops"`
	WriteOps     string      `json:"write_ops"`
}

// NetworkInterface holds address data for one network interface.
type NetworkInterface struct {
	Interface  string `json:"interface"`
	IPAddress  string `json:"ip_address"`
	SubnetMask string `json:"subnet_mask"`
}

// NetworkInfo holds aggregate network I/O and per-interface data.
type NetworkInfo struct {
	Interfaces      []NetworkInterface `json:"interfaces"`
	BytesSent       string             `json:"bytes_sent"`
	BytesReceived   string             `json:"bytes_received"`
	PacketsSent     uint64             `json:"packets_sent"`
	PacketsReceived uint64             `json:"packets_received"`
}

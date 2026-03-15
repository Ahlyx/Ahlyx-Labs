package scanner

// Port describes a single open TCP port found during a scan.
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	OTFlag  bool   `json:"ot_flag"`
}

// Host represents a responsive host with its open ports.
// MAC is always nil in the Go TCP-only scanner (no ARP).
type Host struct {
	IP    string  `json:"ip"`
	MAC   *string `json:"mac"`
	Ports []Port  `json:"ports"`
}

// ScanResponse is the top-level JSON envelope for /api/v1/scanner/scan.
type ScanResponse struct {
	Subnet     string `json:"subnet"`
	HostsFound int    `json:"hosts_found"`
	ScanType   string `json:"scan_type"`
	Hosts      []Host `json:"hosts"`
}

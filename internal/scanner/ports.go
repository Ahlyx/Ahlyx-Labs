package scanner

// OTPorts maps OT/ICS port numbers to their protocol names.
// Preserved exactly from the Python version.
var OTPorts = map[int]string{
	502:   "Modbus",
	102:   "S7comm (Siemens PLC)",
	20000: "DNP3",
	44818: "EtherNet/IP (Rockwell PLC)",
	47808: "BACnet",
	4840:  "OPC-UA",
	1962:  "PCWorx (Phoenix Contact)",
	2222:  "EtherNet/IP alt",
	9600:  "OMRON FINS",
}

// commonTCPPorts lists the standard IT ports always included in a scan.
var commonTCPPorts = []int{21, 22, 23, 80, 443, 8080, 8443}

// CommonPorts is the combined slice of standard IT ports and all OT ports.
// Built once at init time; order is IT ports first, then OT ports.
var CommonPorts []int

func init() {
	CommonPorts = make([]int, 0, len(commonTCPPorts)+len(OTPorts))
	CommonPorts = append(CommonPorts, commonTCPPorts...)
	for port := range OTPorts {
		CommonPorts = append(CommonPorts, port)
	}
}

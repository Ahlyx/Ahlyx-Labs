package scanner

// OTPorts maps OT/ICS port numbers to their protocol names.
var OTPorts = map[int]string{
	102:   "S7comm (Siemens S7 PLCs)",
	502:   "Modbus",
	1089:  "FF Annunciation",
	1090:  "Foundation Fieldbus",
	1091:  "FF System Management",
	1962:  "PCWorx (Phoenix Contact)",
	2222:  "EtherNet/IP",
	4000:  "Emerson DeltaV",
	4840:  "OPC-UA",
	9600:  "OMRON FINS",
	18245: "GE SRTP",
	20000: "DNP3",
	44818: "EtherNet/IP",
	47808: "BACnet",
}

// commonTCPPorts lists the standard IT ports always included in a scan.
var commonTCPPorts = []int{
	21, 22, 23, 25, 53,
	80, 110, 135, 139, 143,
	443, 445, 512, 513, 514,
	1433, 1521, 3306, 3389, 5432,
	5900, 6379, 8080, 8443, 9200,
	27017,
}

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

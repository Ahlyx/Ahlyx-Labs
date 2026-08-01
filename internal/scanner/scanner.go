package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	dialTimeout = 500 * time.Millisecond
	workerCount = 50
	maxSubnetBits = 24 // reject subnets larger than /24
)

// ErrSubnetTooLarge is returned when the CIDR prefix is shorter than /24.
var ErrSubnetTooLarge = errors.New("subnet too large: maximum allowed prefix length is /24")

// ErrOutOfScope is returned when the target is not within a private,
// loopback, or link-local range. The scanner only ever authorizes the
// caller to test their own network, never arbitrary internet hosts.
var ErrOutOfScope = errors.New("out of scope: only private (RFC1918), loopback, and link-local targets are allowed")

// inScopeBlocks are the only ranges the scanner is permitted to touch.
var inScopeBlocks = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

// InScope reports whether ip falls within an authorized range.
func InScope(ip net.IP) bool {
	for _, block := range inScopeBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Scan accepts a CIDR range or single IP string and returns scan results.
// For a CIDR, all host addresses (network and broadcast excluded) are scanned.
// For a single IP, that address alone is scanned.
func Scan(input string) (ScanResponse, error) {
	ips, subnet, err := resolveTargets(input)
	if err != nil {
		return ScanResponse{}, err
	}

	hosts := scanHosts(ips)

	return ScanResponse{
		Subnet:     subnet,
		HostsFound: len(hosts),
		ScanType:   "tcp",
		Hosts:      hosts,
	}, nil
}

// resolveTargets parses the input into a canonical subnet string and a list
// of IP addresses to scan.
func resolveTargets(input string) ([]net.IP, string, error) {
	// Try CIDR first.
	if _, network, err := net.ParseCIDR(input); err == nil {
		ones, _ := network.Mask.Size()
		if ones < maxSubnetBits {
			return nil, "", ErrSubnetTooLarge
		}
		if !InScope(network.IP) {
			return nil, "", ErrOutOfScope
		}
		ips := enumerateHosts(network)
		return ips, input, nil
	}

	// Fall back to single IP.
	ip := net.ParseIP(input)
	if ip == nil {
		return nil, "", fmt.Errorf("invalid input: %q is not a valid IP address or CIDR range", input)
	}
	if !InScope(ip) {
		return nil, "", ErrOutOfScope
	}
	return []net.IP{ip}, input, nil
}

// enumerateHosts returns all usable host addresses in network, excluding the
// network address and broadcast address.
func enumerateHosts(network *net.IPNet) []net.IP {
	// Work in 4-byte IPv4 form for arithmetic.
	ip4 := network.IP.To4()
	if ip4 == nil {
		// IPv6 — scan the single network address as a best-effort fallback.
		return []net.IP{network.IP}
	}

	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(network.Mask))
	broadcast := start | ^mask

	var hosts []net.IP
	for addr := start + 1; addr < broadcast; addr++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, addr)
		hosts = append(hosts, net.IP(b))
	}
	return hosts
}

// scanHosts scans all ports in CommonPorts for each IP in parallel using a
// bounded worker pool of workerCount goroutines.
func scanHosts(ips []net.IP) []Host {
	type task struct {
		ip   string
		port int
	}

	type portResult struct {
		ip   string
		port Port
	}

	tasks := make(chan task, len(ips)*len(CommonPorts))
	results := make(chan portResult, len(ips)*len(CommonPorts))

	// Spawn worker pool.
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				addr := net.JoinHostPort(t.ip, fmt.Sprintf("%d", t.port))
				conn, err := net.DialTimeout("tcp", addr, dialTimeout)
				if err != nil {
					continue
				}
				conn.Close()

				service, isOT := portMeta(t.port)
				results <- portResult{
					ip: t.ip,
					port: Port{
						Port:    t.port,
						Service: service,
						OTFlag:  isOT,
					},
				}
			}
		}()
	}

	// Enqueue all tasks.
	for _, ip := range ips {
		ipStr := ip.String()
		for _, port := range CommonPorts {
			tasks <- task{ip: ipStr, port: port}
		}
	}
	close(tasks)

	// Close results once all workers finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results into a per-IP map.
	hostMap := make(map[string][]Port)
	for r := range results {
		hostMap[r.ip] = append(hostMap[r.ip], r.port)
	}

	// Build ordered Host slice — only include IPs with at least one open port.
	var hosts []Host
	for _, ip := range ips {
		ipStr := ip.String()
		ports, ok := hostMap[ipStr]
		if !ok {
			continue
		}
		hosts = append(hosts, Host{
			IP:    ipStr,
			MAC:   nil,
			Ports: ports,
		})
	}
	return hosts
}

// portMeta returns the service name and OT flag for a port number.
func portMeta(port int) (string, bool) {
	if name, ok := OTPorts[port]; ok {
		return name, true
	}
	switch port {
	case 21:
		return "FTP", false
	case 22:
		return "SSH", false
	case 23:
		return "Telnet", false
	case 80:
		return "HTTP", false
	case 443:
		return "HTTPS", false
	case 8080:
		return "HTTP-Alt", false
	case 8443:
		return "HTTPS-Alt", false
	}
	return fmt.Sprintf("port/%d", port), false
}

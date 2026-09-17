package services

import (
	"context"
	"fmt"
	"net"
)

// HostResolver makes the target-resolution policy testable without making
// real DNS requests. A target is usable only when every answer is public.
type HostResolver func(context.Context, string) ([]net.IP, error)

func resolvePublicTarget(ctx context.Context, host string, resolver HostResolver) ([]net.IP, error) {
	ips, err := resolver(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("target resolution failed")
	}
	for _, ip := range ips {
		if !isPublicInternetIP(ip) {
			return nil, fmt.Errorf("target resolution contains a non-public address")
		}
	}
	return ips, nil
}

func defaultHostResolver(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP)
	}
	return ips, nil
}

func isPublicInternetIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}

	// These ranges are not covered by net.IP.IsPrivate but must never be a
	// public server-side connection target.
	for _, cidr := range specialUseCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

var specialUseCIDRs = mustCIDRs(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
	"240.0.0.0/4", "255.255.255.255/32", "::/128", "100::/64",
	"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustCIDRs(values ...string) []*net.IPNet {
	blocks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, block, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

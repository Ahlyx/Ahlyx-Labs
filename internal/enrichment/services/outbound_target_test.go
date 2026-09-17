package services

import (
	"context"
	"net"
	"testing"
)

func TestResolvePublicTargetRejectsSpecialUseAndMixedAnswers(t *testing.T) {
	tests := [][]string{
		{"127.0.0.1"}, {"169.254.169.254"}, {"10.0.0.1"}, {"100.64.0.1"},
		{"192.0.2.1"}, {"::1"}, {"fc00::1"}, {"fe80::1"},
		{"8.8.8.8", "10.0.0.1"},
	}
	for _, answers := range tests {
		_, err := resolvePublicTarget(context.Background(), "example.test", func(context.Context, string) ([]net.IP, error) {
			ips := make([]net.IP, 0, len(answers))
			for _, answer := range answers {
				ips = append(ips, net.ParseIP(answer))
			}
			return ips, nil
		})
		if err == nil {
			t.Errorf("answers %v were accepted", answers)
		}
	}
}

func TestResolvePublicTargetReturnsVettedAddressForPinnedDial(t *testing.T) {
	addresses, err := resolvePublicTarget(context.Background(), "example.test", func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	})
	if err != nil {
		t.Fatalf("resolvePublicTarget() error = %v", err)
	}
	if len(addresses) != 1 || addresses[0].String() != "8.8.8.8" {
		t.Fatalf("vetted addresses = %v", addresses)
	}
}

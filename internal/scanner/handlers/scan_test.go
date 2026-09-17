package handlers

import (
	"net"
	"testing"
)

func TestValidateControlledTargetDeniesSpecialUseTargets(t *testing.T) {
	_, allow, err := net.ParseCIDR("10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1",
		"::1", "fc00::1", "fe80::1", "10.43.0.1", "10.42.0.0/23",
	} {
		if err := validateControlledTarget(target, []*net.IPNet{allow}); err == nil {
			t.Errorf("validateControlledTarget(%q) succeeded; want rejection", target)
		}
	}
}

func TestValidateControlledTargetAllowsConfiguredPrivateTarget(t *testing.T) {
	_, allow, err := net.ParseCIDR("10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"10.42.0.10", "10.42.0.0/24"} {
		if err := validateControlledTarget(target, []*net.IPNet{allow}); err != nil {
			t.Errorf("validateControlledTarget(%q) error = %v", target, err)
		}
	}
}

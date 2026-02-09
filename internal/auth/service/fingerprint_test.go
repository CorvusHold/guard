package service

import (
	"testing"
)

func TestComputeFingerprint_Deterministic(t *testing.T) {
	fp1 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	fp2 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	if fp1 != fp2 {
		t.Errorf("fingerprint should be deterministic: %s != %s", fp1, fp2)
	}
}

func TestComputeFingerprint_DifferentUA(t *testing.T) {
	fp1 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	fp2 := ComputeFingerprint("Chrome/120", "192.168.1.100", "en-US")
	if fp1 == fp2 {
		t.Error("different user agents should produce different fingerprints")
	}
}

func TestComputeFingerprint_SameSubnet(t *testing.T) {
	// IPs in the same /24 subnet should produce the same fingerprint
	fp1 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	fp2 := ComputeFingerprint("Mozilla/5.0", "192.168.1.200", "en-US")
	if fp1 != fp2 {
		t.Errorf("IPs in same /24 should match: %s != %s", fp1, fp2)
	}
}

func TestComputeFingerprint_DifferentSubnet(t *testing.T) {
	fp1 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	fp2 := ComputeFingerprint("Mozilla/5.0", "10.0.0.100", "en-US")
	if fp1 == fp2 {
		t.Error("IPs in different subnets should produce different fingerprints")
	}
}

func TestComputeFingerprint_DifferentLanguage(t *testing.T) {
	fp1 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "en-US")
	fp2 := ComputeFingerprint("Mozilla/5.0", "192.168.1.100", "fr-FR")
	if fp1 == fp2 {
		t.Error("different accept-language should produce different fingerprints")
	}
}

func TestComputeFingerprint_EmptyInputs(t *testing.T) {
	fp := ComputeFingerprint("", "", "")
	if fp == "" {
		t.Error("fingerprint should not be empty even with empty inputs")
	}
	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("expected 64 char hex hash, got %d chars", len(fp))
	}
}

func TestComputeFingerprint_IPv6SamePrefix(t *testing.T) {
	fp1 := ComputeFingerprint("Mozilla/5.0", "2001:db8:85a3::8a2e:370:7334", "en-US")
	fp2 := ComputeFingerprint("Mozilla/5.0", "2001:db8:85a3::1111:2222:3333", "en-US")
	if fp1 != fp2 {
		t.Errorf("IPv6 in same /48 should match: %s != %s", fp1, fp2)
	}
}

func TestExtractSubnet_IPv4_Consistent(t *testing.T) {
	// IPs in the same /24 should produce the same subnet
	s1 := extractSubnet("192.168.1.100")
	s2 := extractSubnet("192.168.1.200")
	if s1 != s2 {
		t.Errorf("same /24 should produce same subnet: %q vs %q", s1, s2)
	}
	// Different /24 should differ
	s3 := extractSubnet("10.0.0.1")
	if s1 == s3 {
		t.Error("different /24 should produce different subnet")
	}
}

func TestExtractSubnet_InvalidIP(t *testing.T) {
	subnet := extractSubnet("not-an-ip")
	if subnet != "not-an-ip" {
		t.Errorf("invalid IP should be returned as-is, got %s", subnet)
	}
}

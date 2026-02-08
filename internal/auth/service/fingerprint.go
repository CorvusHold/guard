package service

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

// ComputeFingerprint generates a stable fingerprint hash from request metadata.
// Uses User-Agent + IP subnet (first 3 octets for IPv4, first 48 bits for IPv6) + Accept-Language.
func ComputeFingerprint(userAgent, ip, acceptLanguage string) string {
	subnet := extractSubnet(ip)
	data := strings.Join([]string{userAgent, subnet, acceptLanguage}, "|")
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func extractSubnet(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		// Use first 3 octets for IPv4 (/24 subnet)
		return net.IP(v4[:3]).String()
	}
	// Use first 6 bytes for IPv6 (/48 subnet)
	if len(parsed) >= 6 {
		return net.IP(parsed[:6]).String()
	}
	return ip
}

package guard

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

// ecdsaVerify verifies an ECDSA signature (DER or raw r||s format) over a SHA-256 hash.
func ecdsaVerify(pub *ecdsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)

	// ES256 signatures are 64 bytes: r (32 bytes) || s (32 bytes)
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, hash[:], r, s)
	}

	// Try DER-encoded signature
	r, s, err := parseDERSignature(sig)
	if err != nil {
		return false
	}
	return ecdsa.Verify(pub, hash[:], r, s)
}

// hmacVerify verifies an HMAC-SHA256 signature.
func hmacVerify(secret, message, sig []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig)
}

// parseDERSignature parses a DER-encoded ECDSA signature into r and s.
func parseDERSignature(sig []byte) (*big.Int, *big.Int, error) {
	// Minimal DER parser for SEQUENCE { INTEGER r, INTEGER s }
	if len(sig) < 6 || sig[0] != 0x30 {
		return nil, nil, ErrTokenMalform
	}

	idx := 2 // skip SEQUENCE tag and length

	// Parse r
	if idx >= len(sig) || sig[idx] != 0x02 {
		return nil, nil, ErrTokenMalform
	}
	idx++
	rLen := int(sig[idx])
	idx++
	if idx+rLen > len(sig) {
		return nil, nil, ErrTokenMalform
	}
	r := new(big.Int).SetBytes(sig[idx : idx+rLen])
	idx += rLen

	// Parse s
	if idx >= len(sig) || sig[idx] != 0x02 {
		return nil, nil, ErrTokenMalform
	}
	idx++
	sLen := int(sig[idx])
	idx++
	if idx+sLen > len(sig) {
		return nil, nil, ErrTokenMalform
	}
	s := new(big.Int).SetBytes(sig[idx : idx+sLen])

	return r, s, nil
}

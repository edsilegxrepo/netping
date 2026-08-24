package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonHashPartsCount = 6
	maxDecodedHashLen   = 1024
)

// VerifyKey checks whether a plaintext API key matches a standard Argon2id hash string in constant time.
func VerifyKey(key string, encodedHash string) bool {
	if key == "" || encodedHash == "" {
		return false
	}

	keyBytes := []byte(key)
	defer ZeroBytes(keyBytes)

	parts := strings.Split(encodedHash, "$")
	if len(parts) != argonHashPartsCount || parts[1] != "argon2id" {
		return false
	}

	var version int
	var memory uint32
	var iterations uint32
	var parallelism uint8

	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false
	}

	salt, err := decodeB64(parts[4])
	if err != nil {
		return false
	}
	defer ZeroBytes(salt)

	decodedHash, err := decodeB64(parts[5])
	if err != nil {
		return false
	}
	defer ZeroBytes(decodedHash)

	if len(decodedHash) > maxDecodedHashLen || len(decodedHash) == 0 {
		return false
	}

	calculatedHash := argon2.IDKey(keyBytes, salt, iterations, memory, parallelism, uint32(len(decodedHash)))
	defer ZeroBytes(calculatedHash)

	return subtle.ConstantTimeCompare(decodedHash, calculatedHash) == 1
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}
	return b, nil
}

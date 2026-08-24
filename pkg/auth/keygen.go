// Package auth provides cryptographically secure token generation, OWASP-standard Argon2id
// key derivation, zero-downtime hot-reloading keystore management, and HTTP authentication middleware.
//
// Objectives:
//   - Generate high-entropy (256-bit) API keys with `np_live_` prefix.
//   - Provide OWASP-compliant Argon2id key hashing with in-memory plaintext scrubbing.
//   - Protect daemon endpoints against timing attacks and denial-of-service attempts.
//
// Core Components:
//   - Key Generation & Hashing: GenerateAPIKey, HashKey, ZeroBytes.
//   - Keystore: Dynamic hot-reloading JSON keystore persistence with 0600 file permissions.
//   - Verifier: Constant-time Argon2id comparison with 30s in-memory LRU verification cache.
//   - Middleware: RequireAuth, ExtractAPIKey, and CORSMiddleware.
//
// Data Flow:
//
//	CLI (--generate-api-key) -> CSPRNG Entropy -> Hex Token -> Argon2id Hash -> Keystore File (0600)
//	HTTP Request -> Authorization/X-API-Key Header -> In-Memory Cache / Argon2id -> Constant-Time Match.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// OWASP-recommended Argon2id parameters
	ArgonMemory      uint32 = 64 * 1024 // 64 MB
	ArgonIterations  uint32 = 3
	ArgonParallelism uint8  = 4
	ArgonSaltLen     int    = 16
	ArgonKeyLen      uint32 = 32
	KeyPrefix               = "np_live_"
)

// ZeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateAPIKey generates a cryptographically secure 256-bit API key token and its Argon2id hash.
// Returns (rawKey, hashString, error).
func GenerateAPIKey() (string, string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", fmt.Errorf("failed generating random entropy: %w", err)
	}
	defer ZeroBytes(entropy)

	rawKey := KeyPrefix + hex.EncodeToString(entropy)

	hashStr, err := HashKey(rawKey)
	if err != nil {
		return "", "", fmt.Errorf("failed hashing api key: %w", err)
	}

	return rawKey, hashStr, nil
}

// HashKey computes the standard OWASP Argon2id hash string for an API key.
func HashKey(key string) (string, error) {
	keyBytes := []byte(key)
	defer ZeroBytes(keyBytes)

	salt := make([]byte, ArgonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed generating random salt: %w", err)
	}
	defer ZeroBytes(salt)

	hash := argon2.IDKey(keyBytes, salt, ArgonIterations, ArgonMemory, ArgonParallelism, ArgonKeyLen)
	defer ZeroBytes(hash)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, ArgonMemory, ArgonIterations, ArgonParallelism, b64Salt, b64Hash)

	return encoded, nil
}

// GenerateKeyID returns an incremental timestamp-based identifier for keystore entries.
func GenerateKeyID() string {
	return fmt.Sprintf("key_%d", time.Now().UnixNano())
}

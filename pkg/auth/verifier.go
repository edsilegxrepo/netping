package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonHashPartsCount = 6
	maxDecodedHashLen   = 1024
	verifyCacheTTL      = 30 * time.Second
	maxCacheEntries     = 10000
)

type verifyCacheEntry struct {
	valid     bool
	expiresAt time.Time
}

var (
	verifyCacheMu sync.RWMutex
	verifyCache   = make(map[[32]byte]verifyCacheEntry)
)

// ClearVerifyCache clears the internal verification cache (useful in tests and key revocation).
func ClearVerifyCache() {
	verifyCacheMu.Lock()
	defer verifyCacheMu.Unlock()
	verifyCache = make(map[[32]byte]verifyCacheEntry)
}

// VerifyKey checks whether a plaintext API key matches a standard Argon2id hash string in constant time.
// Verified results are cached for 30s to provide high-throughput performance without CPU exhaustion.
func VerifyKey(key, encodedHash string) bool {
	if key == "" || encodedHash == "" {
		return false
	}

	// 1. Fast path: in-memory verification cache
	cacheKey := sha256.Sum256([]byte(key + "\x00" + encodedHash))
	now := time.Now()

	verifyCacheMu.RLock()
	entry, found := verifyCache[cacheKey]
	verifyCacheMu.RUnlock()

	if found && now.Before(entry.expiresAt) {
		return entry.valid
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

	// #nosec G115 -- bounded by maxDecodedHashLen check above
	calculatedHash := argon2.IDKey(keyBytes, salt, iterations, memory, parallelism, uint32(len(decodedHash)))
	defer ZeroBytes(calculatedHash)

	match := subtle.ConstantTimeCompare(decodedHash, calculatedHash) == 1

	verifyCacheMu.Lock()
	if len(verifyCache) >= maxCacheEntries {
		pruneExpiredVerifyCache(now)
	}
	verifyCache[cacheKey] = verifyCacheEntry{
		valid:     match,
		expiresAt: now.Add(verifyCacheTTL),
	}
	verifyCacheMu.Unlock()

	return match
}

func pruneExpiredVerifyCache(now time.Time) {
	for k, v := range verifyCache {
		if now.After(v.expiresAt) {
			delete(verifyCache, k)
		}
	}
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

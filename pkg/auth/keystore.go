package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KeyEntry represents an individual API key record in the keystore.
type KeyEntry struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Hash      string    `json:"hash"`
	Note      string    `json:"note,omitempty"`
}

// KeystoreSchema represents the on-disk format of the keystore file.
type KeystoreSchema struct {
	Version   string     `json:"version"`
	UpdatedAt time.Time  `json:"updated_at"`
	Keys      []KeyEntry `json:"keys"`
}

// Keystore manages in-memory authorized key hashes and disk persistence.
type Keystore struct {
	mu          sync.RWMutex
	filePath    string
	lastModTime time.Time
	keys        []KeyEntry
	inlineKeys  []string
}

// NewKeystore creates a new Keystore instance associated with an optional file path and inline key hashes.
func NewKeystore(filePath string, inlineKeys ...string) (*Keystore, error) {
	ks := &Keystore{
		filePath:   filePath,
		inlineKeys: inlineKeys,
		keys:       make([]KeyEntry, 0),
	}

	if filePath != "" {
		if err := ks.Reload(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load keystore from %q: %w", filePath, err)
		}
	}

	return ks, nil
}

// AddKey atomically appends a new key entry to the keystore and persists it to disk.
func (ks *Keystore) AddKey(entry KeyEntry) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if entry.ID == "" {
		entry.ID = GenerateKeyID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	ks.keys = append(ks.keys, entry)

	if ks.filePath != "" {
		return ks.saveLocked()
	}
	return nil
}

// SaveKeyToStorePath creates or updates a keystore file at storePath with a new key hash.
func SaveKeyToStorePath(storePath string, rawKey string, hash string) error {
	cleanPath := filepath.Clean(storePath)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed creating directory %q: %w", dir, err)
		}
	}

	ks, err := NewKeystore(cleanPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if ks == nil {
		ks = &Keystore{filePath: cleanPath}
	}

	return ks.AddKey(KeyEntry{
		ID:        GenerateKeyID(),
		CreatedAt: time.Now().UTC(),
		Hash:      hash,
	})
}

// Reload re-reads the keystore file from disk if modified.
func (ks *Keystore) Reload() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.filePath == "" {
		return nil
	}

	info, err := os.Stat(ks.filePath)
	if err != nil {
		return err
	}

	if !info.ModTime().After(ks.lastModTime) && len(ks.keys) > 0 {
		return nil // File not modified
	}

	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		return fmt.Errorf("reading keystore file: %w", err)
	}

	var schema KeystoreSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("parsing keystore JSON: %w", err)
	}

	ks.keys = schema.Keys
	ks.lastModTime = info.ModTime()
	return nil
}

// ValidateKey checks if the provided key matches any active key hash in the keystore or inline keys.
func (ks *Keystore) ValidateKey(rawKey string) bool {
	if rawKey == "" {
		return false
	}

	// Auto hot-reload if file modified
	if ks.filePath != "" {
		if info, err := os.Stat(ks.filePath); err == nil && info.ModTime().After(ks.lastModTime) {
			_ = ks.Reload()
		}
	}

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Check against keystore entries
	for _, entry := range ks.keys {
		if VerifyKey(rawKey, entry.Hash) {
			return true
		}
	}

	// Check against inline hashes (e.g. from environment variable or CLI flag)
	for _, hash := range ks.inlineKeys {
		if VerifyKey(rawKey, hash) {
			return true
		}
	}

	return false
}

// KeyCount returns the total number of configured key hashes.
func (ks *Keystore) KeyCount() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.keys) + len(ks.inlineKeys)
}

func (ks *Keystore) saveLocked() error {
	cleanPath := filepath.Clean(ks.filePath)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating parent directory: %w", err)
		}
	}

	schema := KeystoreSchema{
		Version:   "1.0",
		UpdatedAt: time.Now().UTC(),
		Keys:      ks.keys,
	}

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling keystore: %w", err)
	}

	tmpFile := cleanPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("writing temp keystore: %w", err)
	}

	if err := os.Rename(tmpFile, cleanPath); err != nil {
		_ = os.Remove(tmpFile)
		// Fallback for Windows if destination exists
		_ = os.Remove(cleanPath)
		if err := os.WriteFile(cleanPath, data, 0600); err != nil {
			return fmt.Errorf("writing keystore file: %w", err)
		}
	}

	if info, err := os.Stat(cleanPath); err == nil {
		ks.lastModTime = info.ModTime()
	}

	return nil
}

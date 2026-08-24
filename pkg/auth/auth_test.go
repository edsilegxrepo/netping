package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndVerifyAPIKey(t *testing.T) {
	rawKey, hashStr, err := GenerateAPIKey()
	require.NoError(t, err)
	assert.NotEmpty(t, rawKey)
	assert.NotEmpty(t, hashStr)
	assert.Contains(t, rawKey, "np_live_")
	assert.Contains(t, hashStr, "$argon2id$")

	// Valid key matches
	assert.True(t, VerifyKey(rawKey, hashStr))

	// Invalid key fails
	assert.False(t, VerifyKey("np_live_invalidkey123456", hashStr))
	assert.False(t, VerifyKey("", hashStr))
	assert.False(t, VerifyKey(rawKey, ""))
}

func TestKeystoreFileLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "sub", "netping_keys.json")

	rawKey, hashStr, err := GenerateAPIKey()
	require.NoError(t, err)

	err = SaveKeyToStorePath(storePath, rawKey, hashStr)
	require.NoError(t, err)

	// File exists
	_, err = os.Stat(storePath)
	require.NoError(t, err)

	// Load keystore
	ks, err := NewKeystore(storePath)
	require.NoError(t, err)
	assert.Equal(t, 1, ks.KeyCount())
	assert.True(t, ks.ValidateKey(rawKey))
	assert.False(t, ks.ValidateKey("np_live_wrongkey"))

	// Add second key
	rawKey2, hashStr2, err := GenerateAPIKey()
	require.NoError(t, err)
	err = ks.AddKey(KeyEntry{
		ID:   "second_key",
		Hash: hashStr2,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, ks.KeyCount())
	assert.True(t, ks.ValidateKey(rawKey))
	assert.True(t, ks.ValidateKey(rawKey2))
}

func TestInlineKeystore(t *testing.T) {
	rawKey, hashStr, err := GenerateAPIKey()
	require.NoError(t, err)

	ks, err := NewKeystore("", hashStr)
	require.NoError(t, err)
	assert.Equal(t, 1, ks.KeyCount())
	assert.True(t, ks.ValidateKey(rawKey))
	assert.False(t, ks.ValidateKey("np_live_wrong"))
}

func TestAuthMiddleware(t *testing.T) {
	rawKey, hashStr, err := GenerateAPIKey()
	require.NoError(t, err)

	ks, err := NewKeystore("", hashStr)
	require.NoError(t, err)

	handlerCalled := false
	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}

	protected := RequireAuth(ks, dummyHandler)

	// 1. Missing header -> 401
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", nil)
	rec := httptest.NewRecorder()
	protected(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, handlerCalled)

	// 2. Invalid header -> 401
	req = httptest.NewRequest(http.MethodPost, "/api/v1/trigger", nil)
	req.Header.Set("X-API-Key", "np_live_bogus")
	rec = httptest.NewRecorder()
	protected(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, handlerCalled)

	// 3. Valid X-API-Key -> 200
	req = httptest.NewRequest(http.MethodPost, "/api/v1/trigger", nil)
	req.Header.Set("X-API-Key", rawKey)
	rec = httptest.NewRecorder()
	protected(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, handlerCalled)

	// 4. Valid Authorization: Bearer -> 200
	handlerCalled = false
	req = httptest.NewRequest(http.MethodPost, "/api/v1/trigger", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rec = httptest.NewRecorder()
	protected(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, handlerCalled)

	// 5. Preflight OPTIONS -> 204 No Content
	handlerCalled = false
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/trigger", nil)
	rec = httptest.NewRecorder()
	protected(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.False(t, handlerCalled)
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestZeroBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroBytes(buf)
	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d should be 0", i)
	}
}

func TestVerifyKey_CorruptedHashesAndEdges(t *testing.T) {
	rawKey, hashStr, err := GenerateAPIKey()
	require.NoError(t, err)

	// Valid hash verification
	assert.True(t, VerifyKey(rawKey, hashStr))

	// Invalid format / missing parts
	assert.False(t, VerifyKey(rawKey, "invalid_hash_string"))
	assert.False(t, VerifyKey(rawKey, "$argon2i$v=19$m=65536,t=3,p=4$salt$hash")) // not argon2id
	assert.False(t, VerifyKey(rawKey, "$argon2id$v=99$m=65536,t=3,p=4$salt$hash")) // invalid version
	assert.False(t, VerifyKey(rawKey, "$argon2id$v=19$badparams$salt$hash"))         // bad params format
	assert.False(t, VerifyKey(rawKey, "$argon2id$v=19$m=65536,t=3,p=4$bad#salt$hash")) // bad salt base64
	assert.False(t, VerifyKey(rawKey, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bad#hash")) // bad hash base64
	assert.False(t, VerifyKey("", hashStr))
	assert.False(t, VerifyKey(rawKey, ""))
}

func TestGenerateKeyID(t *testing.T) {
	id1 := GenerateKeyID()
	time.Sleep(1 * time.Millisecond)
	id2 := GenerateKeyID()
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.True(t, len(id1) > 5)
}

func TestExtractAPIKey_Variations(t *testing.T) {
	// 1. X-API-Key header
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-API-Key", "test_key_1")
	assert.Equal(t, "test_key_1", ExtractAPIKey(req1))

	// 2. Authorization: Bearer <key>
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer test_key_2")
	assert.Equal(t, "test_key_2", ExtractAPIKey(req2))

	// 3. Authorization: apikey <key>
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "apikey test_key_3")
	assert.Equal(t, "test_key_3", ExtractAPIKey(req3))

	// 4. Raw Authorization header
	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	req4.Header.Set("Authorization", "test_key_4")
	assert.Equal(t, "test_key_4", ExtractAPIKey(req4))

	// 5. Empty
	req5 := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Empty(t, ExtractAPIKey(req5))
}

func TestCORSMiddleware(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	cors := CORSMiddleware(handler)

	// Preflight OPTIONS
	reqOpt := httptest.NewRequest(http.MethodOptions, "/test", nil)
	wOpt := httptest.NewRecorder()
	cors.ServeHTTP(wOpt, reqOpt)
	assert.Equal(t, http.StatusNoContent, wOpt.Code)
	assert.Equal(t, "*", wOpt.Header().Get("Access-Control-Allow-Origin"))
	assert.False(t, called)

	// Standard GET
	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	wGet := httptest.NewRecorder()
	cors.ServeHTTP(wGet, reqGet)
	assert.Equal(t, http.StatusOK, wGet.Code)
	assert.Equal(t, "*", wGet.Header().Get("Access-Control-Allow-Origin"))
	assert.True(t, called)
}

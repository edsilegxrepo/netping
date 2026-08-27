package probers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKMS_HashiCorpVaultUnsealed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/sys/health", r.URL.Path)
		resp := hashicorpVaultHealth{
			Initialized:   true,
			Sealed:        false,
			Standby:       false,
			Version:       "1.16.2",
			ClusterName:   "vault-prod-east",
			ClusterID:     "e8b23c91-4d1a-4288-bc19-123456789abc",
			ServerTimeUTC: time.Now().Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.KMS,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL + "/v1/sys/health",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vault: HashiCorp Vault")
	assert.Contains(t, res.Diagnostics, "Version: v1.16.2")
	assert.Contains(t, res.Diagnostics, "Cluster: vault-prod-east")
	assert.Contains(t, res.Diagnostics, "Sealed: false (Unsealed)")
	assert.Contains(t, res.Diagnostics, "Role: Active Primary Leader")
}

func TestKMS_HashiCorpVaultSealedAlert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := hashicorpVaultHealth{
			Initialized: true,
			Sealed:      true,
			Standby:     true,
			Version:     "1.15.4",
			ClusterName: "vault-locked-cluster",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable) // 503 when sealed
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.VAULT,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL + "/v1/sys/health",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusServiceUnavailable, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "CRITICAL ALERT: Vault is SEALED/Locked")
	assert.Contains(t, res.Diagnostics, "Role: Standby Node")
}

func TestKMS_AzureKeyVaultChallenge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47", resource="https://vault.azure.net"`)
		w.Header().Set("x-ms-keyvault-region", "eastus2")
		w.Header().Set("x-ms-keyvault-service-version", "1.9.1245.0")
		w.Header().Set("x-ms-request-id", "req-test-12345")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"Unauthorized"}}`))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := NewKMSing(KMSOptions{
		Type:     KMSTypeAzure,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL,
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusUnauthorized, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vault: Azure Key Vault")
	assert.Contains(t, res.Diagnostics, "TenantID: 72f988bf-86f1-41af-91ab-2d7cd011db47")
	assert.Contains(t, res.Diagnostics, "Region: eastus2")
	assert.Contains(t, res.Diagnostics, "ServiceVer: 1.9.1245.0")
	assert.Contains(t, res.Diagnostics, "ReqID: req-test-12345")
}

func TestKMS_CyberArkHealth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := cyberarkHealthDoc{
			ComponentHealth:  "OK",
			ComponentVersion: "14.0.0.12",
			IsVaultConnected: true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := NewKMSing(KMSOptions{
		Type:     KMSTypeCyberArk,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL + "/PasswordVault/api/Health",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vault: CyberArk")
	assert.Contains(t, res.Diagnostics, "Health: OK")
	assert.Contains(t, res.Diagnostics, "Version: 14.0.0.12")
	assert.Contains(t, res.Diagnostics, "VaultLink: Connected")
}

func TestKMS_AWSKMS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amzn-RequestId", "aws-req-98765")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"MissingAction"}`))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := NewKMSing(KMSOptions{
		Type:     KMSTypeAWS,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL,
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusBadRequest, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vault: AWS Key Management Service (AWS KMS)")
	assert.Contains(t, res.Diagnostics, "AmznReqID: aws-req-98765")
}

func TestKMS_GCPKMS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-request-id", "gcp-req-123456")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404}}`))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := NewKMSing(KMSOptions{
		Type:     KMSTypeGCP,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL,
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusNotFound, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Vault: Google Cloud Key Management Service (GCP KMS)")
	assert.Contains(t, res.Diagnostics, "GCPReqID: gcp-req-123456")
}

func TestKMS_BuildTargetURL_ProviderAutoDetection(t *testing.T) {
	// 1. Invalid / malformed URL
	p1 := NewKMSing(KMSOptions{
		URI: "http://[invalid-ipv6-bracket",
	})
	_, _, err1 := p1.buildTargetURL()
	assert.Error(t, err1)

	// 2. Azure Key Vault auto-detection
	p2 := NewKMSing(KMSOptions{
		Hostname: "mykeyvault.vault.azure.net",
		Port:     443,
	})
	url2, type2, err2 := p2.buildTargetURL()
	assert.NoError(t, err2)
	assert.Equal(t, KMSTypeAzure, type2)
	assert.Equal(t, "https://mykeyvault.vault.azure.net:443/", url2.String())

	// 3. AWS KMS auto-detection
	p3 := NewKMSing(KMSOptions{
		Hostname: "kms.eu-west-1.amazonaws.com",
		Port:     443,
	})
	url3, type3, err3 := p3.buildTargetURL()
	assert.NoError(t, err3)
	assert.Equal(t, KMSTypeAWS, type3)
	assert.Equal(t, "https://kms.eu-west-1.amazonaws.com:443/", url3.String())

	// 4. GCP KMS auto-detection
	p4 := NewKMSing(KMSOptions{
		Hostname: "cloudkms.googleapis.com",
		Port:     443,
	})
	url4, type4, err4 := p4.buildTargetURL()
	assert.NoError(t, err4)
	assert.Equal(t, KMSTypeGCP, type4)
	assert.Equal(t, "https://cloudkms.googleapis.com:443/", url4.String())

	// 5. CyberArk auto-detection from hostname
	p5 := NewKMSing(KMSOptions{
		Hostname: "cyberark-vault.internal",
		Port:     443,
	})
	url5, type5, err5 := p5.buildTargetURL()
	assert.NoError(t, err5)
	assert.Equal(t, KMSTypeCyberArk, type5)
	assert.Equal(t, "https://cyberark-vault.internal:443/PasswordVault/api/Health", url5.String())

	// 6. HashiCorp default on port 8200
	p6 := NewKMSing(KMSOptions{
		Hostname: "vault.corp.local",
		Port:     8200,
	})
	url6, type6, err6 := p6.buildTargetURL()
	assert.NoError(t, err6)
	assert.Equal(t, KMSTypeHashiCorp, type6)
	assert.Equal(t, "http://vault.corp.local:8200/v1/sys/health", url6.String())

	// 7. URI without scheme
	p7 := NewKMSing(KMSOptions{
		URI: "myvault.vault.azure.net:443/keys",
	})
	url7, type7, err7 := p7.buildTargetURL()
	assert.NoError(t, err7)
	assert.Equal(t, KMSTypeAzure, type7)
	assert.Equal(t, "https://myvault.vault.azure.net:443/keys", url7.String())
}

func TestKMS_HashiCorp_RoleBranches(t *testing.T) {
	p := NewKMSing(KMSOptions{
		Type: KMSTypeHashiCorp,
	})

	// 1. Standby node (429)
	body429, _ := json.Marshal(hashicorpVaultHealth{
		Initialized:   true,
		Sealed:        false,
		Standby:       true,
		Version:       "1.15.0",
		ServerTimeUTC: time.Now().Unix(),
	})
	resp429 := &http.Response{StatusCode: 429, Header: http.Header{}}
	diag429 := p.parseDiagnostics(KMSTypeHashiCorp, resp429, body429, nil)
	assert.Contains(t, diag429, "Role: Standby Node")

	// 2. Active Primary Leader with Clock Skew (200)
	body200, _ := json.Marshal(hashicorpVaultHealth{
		Initialized:   true,
		Sealed:        false,
		Standby:       false,
		Version:       "1.15.0",
		ServerTimeUTC: time.Now().Unix() - 10, // 10s skew
	})
	resp200 := &http.Response{StatusCode: 200, Header: http.Header{}}
	diag200 := p.parseDiagnostics(KMSTypeHashiCorp, resp200, body200, nil)
	assert.Contains(t, diag200, "Role: Active Primary Leader")
	assert.Contains(t, diag200, "ClockSkew:")

	// 3. Sealed Node (503)
	body503, _ := json.Marshal(hashicorpVaultHealth{
		Initialized: true,
		Sealed:      true,
		Version:     "1.15.0",
	})
	resp503 := &http.Response{StatusCode: 503, Header: http.Header{}}
	diag503 := p.parseDiagnostics(KMSTypeHashiCorp, resp503, body503, nil)
	assert.Contains(t, diag503, "[CRITICAL ALERT: Vault is SEALED/Locked]")
}

func TestKMS_Errors_And_UnhandledStatus(t *testing.T) {
	// 1. HTTP 500
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	p1 := NewKMSing(KMSOptions{
		Type:    KMSTypeHashiCorp,
		URI:     ts500.URL,
		Timeout: 1 * time.Second,
	})
	res1 := p1.Ping(context.Background())
	assert.Error(t, res1.Err)
	assert.Contains(t, res1.Err.Error(), "500")

	// 2. Dial connection error
	p2 := NewKMSing(KMSOptions{
		Type:     KMSTypeAWS,
		Hostname: "127.0.0.1",
		Port:     1,
		Timeout:  100 * time.Millisecond,
	})
	res2 := p2.Ping(context.Background())
	assert.Error(t, res2.Err)
}

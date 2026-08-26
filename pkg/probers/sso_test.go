package probers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
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

// generateTestCertificate generates a base64 encoded DER X.509 certificate with given validity window.
func generateTestCertificate(cn string, notBefore, notAfter time.Time) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ""
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Netping Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(derBytes)
}

func TestSSO_OIDC_Discovery_And_JWKS(t *testing.T) {
	// Generate valid cert expiring in 120 days
	validCertB64 := generateTestCertificate("accounts.example.com", time.Now().Add(-24*time.Hour), time.Now().Add(120*24*time.Hour))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "key-2026-01",
					"alg": "RS256",
					"x5c": []string{validCertB64},
				},
			},
		})
	}))
	defer jwksServer.Close()

	oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                "https://accounts.example.com",
			"authorization_endpoint":                "https://accounts.example.com/oauth2/v2/auth",
			"token_endpoint":                        "https://accounts.example.com/oauth2/v2/token",
			"userinfo_endpoint":                     "https://accounts.example.com/oauth2/v2/userinfo",
			"jwks_uri":                              jwksServer.URL,
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
		})
	}))
	defer oidcServer.Close()

	u, err := url.Parse(oidcServer.URL)
	require.NoError(t, err)
	portNum, _ := strconv.Atoi(u.Port())

	pinger := NewSSOing(SSOOptions{
		Type:     SSOTypeOIDC,
		Hostname: u.Hostname(),
		Port:     uint16(portNum),
		URI:      oidcServer.URL + "/.well-known/openid-configuration",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Protocol: OIDC (OpenID Connect 1.0)")
	assert.Contains(t, res.Diagnostics, "Issuer: https://accounts.example.com")
	assert.Contains(t, res.Diagnostics, "TokenEndpoint: https://accounts.example.com/oauth2/v2/token")
	assert.Contains(t, res.Diagnostics, "SigningAlgs: [RS256, ES256]")
	assert.Contains(t, res.Diagnostics, "Scopes: [openid, profile, email]")
	assert.Contains(t, res.Diagnostics, "JWKS: 1 active keys")
	assert.Contains(t, res.Diagnostics, "expires in 119 days")
}

func TestSSO_OIDC_Expired_And_Warning_JWKS(t *testing.T) {
	// 1. Expired cert (expired 10 days ago)
	expiredCertB64 := generateTestCertificate("expired.example.com", time.Now().Add(-40*24*time.Hour), time.Now().Add(-10*24*time.Hour))

	jwksExpiredServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "expired-key",
					"x5c": []string{expiredCertB64},
				},
			},
		})
	}))
	defer jwksExpiredServer.Close()

	oidcExpiredServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   "https://expired.example.com",
			"jwks_uri": jwksExpiredServer.URL,
		})
	}))
	defer oidcExpiredServer.Close()

	uExp, _ := url.Parse(oidcExpiredServer.URL)
	portExp, _ := strconv.Atoi(uExp.Port())

	pingerExp := NewSSOing(SSOOptions{
		Type:     SSOTypeOIDC,
		Hostname: uExp.Hostname(),
		Port:     uint16(portExp),
		URI:      oidcExpiredServer.URL,
		Timeout:  2 * time.Second,
	})

	resExp := pingerExp.Ping(context.Background())
	assert.NoError(t, resExp.Err)
	assert.Contains(t, resExp.Diagnostics, "[CRITICAL: Cert Expired")

	// 2. Warning cert (expires in 15 days)
	warningCertB64 := generateTestCertificate("warning.example.com", time.Now().Add(-10*24*time.Hour), time.Now().Add(15*24*time.Hour))

	jwksWarnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "warn-key",
					"x5c": []string{warningCertB64},
				},
			},
		})
	}))
	defer jwksWarnServer.Close()

	oidcWarnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   "https://warning.example.com",
			"jwks_uri": jwksWarnServer.URL,
		})
	}))
	defer oidcWarnServer.Close()

	uWarn, _ := url.Parse(oidcWarnServer.URL)
	portWarn, _ := strconv.Atoi(uWarn.Port())

	pingerWarn := NewSSOing(SSOOptions{
		Type:     SSOTypeOIDC,
		Hostname: uWarn.Hostname(),
		Port:     uint16(portWarn),
		URI:      oidcWarnServer.URL,
		Timeout:  2 * time.Second,
	})

	resWarn := pingerWarn.Ping(context.Background())
	assert.NoError(t, resWarn.Err)
	assert.Contains(t, resWarn.Diagnostics, "[WARNING: Nearest Cert Expires in")
}

func TestSSO_SAML2_Metadata_ValidCert(t *testing.T) {
	validCertB64 := generateTestCertificate("sso.corp.example.com", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	samlXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://sso.corp.example.com/idp" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>%s</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>%s</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sso.corp.example.com/idp/sso"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sso.corp.example.com/idp/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`, validCertB64, validCertB64)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
		_, _ = w.Write([]byte(samlXML))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	portNum, _ := strconv.Atoi(u.Port())

	pinger := NewSSOing(SSOOptions{
		Type:     SSOTypeSAML,
		Hostname: u.Hostname(),
		Port:     uint16(portNum),
		URI:      server.URL + "/FederationMetadata/2007-06/FederationMetadata.xml",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Protocol: SAML 2.0 Metadata")
	assert.Contains(t, res.Diagnostics, "EntityID: https://sso.corp.example.com/idp")
	assert.Contains(t, res.Diagnostics, "Bindings: [HTTP-Redirect, HTTP-POST]")
	assert.Contains(t, res.Diagnostics, "NameID: [emailAddress, persistent]")
	assert.Contains(t, res.Diagnostics, "SigningCert: CN=sso.corp.example.com")
	assert.Contains(t, res.Diagnostics, "EncryptionCert: Present")
}

func TestSSO_SAML2_Metadata_ExpiringSoon_And_Expired(t *testing.T) {
	// 1. Expiring in 10 days
	warnCertB64 := generateTestCertificate("sso.expiring.com", time.Now().Add(-100*24*time.Hour), time.Now().Add(10*24*time.Hour))
	samlWarnXML := fmt.Sprintf(`<EntityDescriptor entityID="https://sso.expiring.com" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor>
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data><X509Certificate>%s</X509Certificate></X509Data>
            </KeyInfo>
        </KeyDescriptor>
    </IDPSSODescriptor>
</EntityDescriptor>`, warnCertB64)

	warnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(samlWarnXML))
	}))
	defer warnServer.Close()

	uWarn, _ := url.Parse(warnServer.URL)
	portWarn, _ := strconv.Atoi(uWarn.Port())

	pingerWarn := NewSSOing(SSOOptions{
		Type:     SSOTypeSAML,
		Hostname: uWarn.Hostname(),
		Port:     uint16(portWarn),
		URI:      warnServer.URL,
		Timeout:  2 * time.Second,
	})

	resWarn := pingerWarn.Ping(context.Background())
	assert.NoError(t, resWarn.Err)
	assert.Contains(t, resWarn.Diagnostics, "[WARNING: 9 days left]")

	// 2. Expired 5 days ago
	expiredCertB64 := generateTestCertificate("sso.expired.com", time.Now().Add(-100*24*time.Hour), time.Now().Add(-5*24*time.Hour))
	samlExpXML := fmt.Sprintf(`<EntityDescriptor entityID="https://sso.expired.com" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor>
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data><X509Certificate>%s</X509Certificate></X509Data>
            </KeyInfo>
        </KeyDescriptor>
    </IDPSSODescriptor>
</EntityDescriptor>`, expiredCertB64)

	expServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(samlExpXML))
	}))
	defer expServer.Close()

	uExp, _ := url.Parse(expServer.URL)
	portExp, _ := strconv.Atoi(uExp.Port())

	pingerExp := NewSSOing(SSOOptions{
		Type:     SSOTypeSAML,
		Hostname: uExp.Hostname(),
		Port:     uint16(portExp),
		URI:      expServer.URL,
		Timeout:  2 * time.Second,
	})

	resExp := pingerExp.Ping(context.Background())
	assert.NoError(t, resExp.Err)
	assert.Contains(t, resExp.Diagnostics, "[CRITICAL: EXPIRED on")
}

func TestSSO_OAuth2_AuthorizationServer(t *testing.T) {
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                "https://auth.api.example.com",
			"token_endpoint":                        "https://auth.api.example.com/oauth/token",
			"revocation_endpoint":                   "https://auth.api.example.com/oauth/revoke",
			"introspection_endpoint":                "https://auth.api.example.com/oauth/introspect",
			"grant_types_supported":                 []string{"client_credentials", "authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "private_key_jwt"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	}))
	defer oauthServer.Close()

	u, _ := url.Parse(oauthServer.URL)
	portNum, _ := strconv.Atoi(u.Port())

	pinger := NewSSOing(SSOOptions{
		Type:     SSOTypeOAuth2,
		Hostname: u.Hostname(),
		Port:     uint16(portNum),
		URI:      oauthServer.URL + "/.well-known/oauth-authorization-server",
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Protocol: OAuth 2.0 (RFC 8414)")
	assert.Contains(t, res.Diagnostics, "Issuer: https://auth.api.example.com")
	assert.Contains(t, res.Diagnostics, "TokenEndpoint: https://auth.api.example.com/oauth/token")
	assert.Contains(t, res.Diagnostics, "Grants: [client_credentials, authorization_code, refresh_token]")
	assert.Contains(t, res.Diagnostics, "AuthMethods: [client_secret_basic, private_key_jwt]")
	assert.Contains(t, res.Diagnostics, "PKCE: [S256]")
	assert.Contains(t, res.Diagnostics, "Introspection: Enabled")
}

func TestSSO_OAuth2_Missing_S256(t *testing.T) {
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                           "https://insecure.auth.example.com",
			"token_endpoint":                   "https://insecure.auth.example.com/oauth/token",
			"code_challenge_methods_supported": []string{"plain"},
		})
	}))
	defer oauthServer.Close()

	u, _ := url.Parse(oauthServer.URL)
	portNum, _ := strconv.Atoi(u.Port())

	pinger := NewSSOing(SSOOptions{
		Type:     SSOTypeOAuth2,
		Hostname: u.Hostname(),
		Port:     uint16(portNum),
		URI:      oauthServer.URL,
		Timeout:  2 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "PKCE: [plain only - S256 missing]")
}

func TestSSO_AutoDetection(t *testing.T) {
	// Auto detect SAML via path
	pingerSAML := NewSSOing(SSOOptions{
		Type:     SSOTypeAuto,
		Hostname: "sso.corp.example.com",
		URI:      "https://sso.corp.example.com/metadata.xml",
	})
	uSAML, sTypeSAML, err := pingerSAML.buildTargetURL()
	require.NoError(t, err)
	assert.Equal(t, SSOTypeSAML, sTypeSAML)
	assert.Equal(t, "/metadata.xml", uSAML.Path)

	// Auto detect OAuth via path
	pingerOAuth := NewSSOing(SSOOptions{
		Type:     SSOTypeAuto,
		Hostname: "auth.corp.example.com",
		URI:      "https://auth.corp.example.com/oauth/token",
	})
	uOAuth, sTypeOAuth, err := pingerOAuth.buildTargetURL()
	require.NoError(t, err)
	assert.Equal(t, SSOTypeOAuth2, sTypeOAuth)
	assert.Equal(t, "/oauth/token", uOAuth.Path)

	// Auto detect OIDC default
	pingerOIDC := NewSSOing(SSOOptions{
		Type:     SSOTypeAuto,
		Hostname: "accounts.google.com",
	})
	uOIDC, sTypeOIDC, err := pingerOIDC.buildTargetURL()
	require.NoError(t, err)
	assert.Equal(t, SSOTypeOIDC, sTypeOIDC)
	assert.Equal(t, "/.well-known/openid-configuration", uOIDC.Path)
}

func TestSSO_ErrorHandling_And_Non200(t *testing.T) {
	// 500 Internal Server Error
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("500 internal server error"))
	}))
	defer errServer.Close()

	u, _ := url.Parse(errServer.URL)
	portNum, _ := strconv.Atoi(u.Port())

	pinger := NewSSOing(SSOOptions{
		Type:     SSOTypeOIDC,
		Hostname: u.Hostname(),
		Port:     uint16(portNum),
		URI:      errServer.URL,
		Timeout:  1 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.Error(t, res.Err)
	assert.Equal(t, http.StatusInternalServerError, res.HTTPStatus)
	assert.Contains(t, res.Err.Error(), "non-success HTTP status 500")

	// Missing target host
	emptyPinger := NewSSOing(SSOOptions{})
	resEmpty := emptyPinger.Ping(context.Background())
	assert.Error(t, resEmpty.Err)
	assert.Contains(t, resEmpty.Err.Error(), "no target host or uri specified")
}

func TestSSO_Factory_Integration(t *testing.T) {
	pingerOIDC := BuildPinger(FactoryOptions{
		Protocol: consts.OIDC,
		Hostname: "accounts.google.com",
		Port:     443,
	})
	assert.IsType(t, &SSOing{}, pingerOIDC)

	pingerSAML := BuildPinger(FactoryOptions{
		Protocol: consts.SAML,
		Hostname: "login.microsoftonline.com",
		Port:     443,
	})
	assert.IsType(t, &SSOing{}, pingerSAML)

	pingerOAuth2 := BuildPinger(FactoryOptions{
		Protocol: consts.OAUTH2,
		Hostname: "auth.example.com",
		Port:     443,
	})
	assert.IsType(t, &SSOing{}, pingerOAuth2)

	pingerSSO := BuildPinger(FactoryOptions{
		Protocol: consts.SSO,
		Hostname: "federation.example.com",
		Port:     443,
	})
	assert.IsType(t, &SSOing{}, pingerSSO)
}

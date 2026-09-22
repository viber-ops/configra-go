package configra

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type replacedDefaultTransport struct{}

func (replacedDefaultTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unrelated application transport")
}

func TestClientDoesNotDependOnGlobalTransportType(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = replacedDefaultTransport{}
	t.Cleanup(func() { http.DefaultTransport = previous })
	client, err := NewClient(ClientOptions{BaseURL: "https://configra.example.com", Token: testToken()})
	if err != nil || client == nil {
		t.Fatalf("NewClient with valid options = %v", err)
	}
	client.CloseIdleConnections()
}

func TestClientEnforcesConfiguredContentLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("ETag", `"one"`)
		if strings.Contains(request.URL.Path, "/configs/") {
			response.Header().Set("Content-Type", "application/json")
			io.WriteString(response, `{"format":"yaml","content":"value: too-long-for-limit","config_revision":1,"vault_revisions":{}}`)
		} else {
			response.Header().Set("Content-Type", "text/plain")
			response.Header().Set("Content-Disposition", `attachment; filename="value.txt"`)
			io.WriteString(response, "too-long-for-limit")
		}
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server), MaxContentBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.ReadResolvedConfig(context.Background(), "a", "app", ""); err == nil {
		t.Fatal("accepted Config larger than configured limit")
	}
	if _, err := client.ReadFile(context.Background(), "a", "platform", "app", "file", ""); err == nil {
		t.Fatal("accepted File larger than configured limit")
	}
	for _, limit := range []int64{-1, maxContentBytes + 1} {
		if _, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), MaxContentBytes: limit}); err == nil {
			t.Fatal("accepted invalid content limit")
		}
	}
}

func TestClientReadsResolvedConfigAndFileOverHTTPS(t *testing.T) {
	token := testToken()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		if request.Header.Get("If-None-Match") != `"old"` {
			t.Errorf("If-None-Match = %q", request.Header.Get("If-None-Match"))
		}
		response.Header().Set("Cache-Control", "no-store")
		switch request.URL.Path {
		case "/v1/environments/a/configs/payment":
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("ETag", `"cfg-7-vault-mysql-4"`)
			_, _ = io.WriteString(response, `{"format":"yaml","content":"database:\n  password: resolved-secret-sentinel\n","config_revision":7,"vault_revisions":{"platform.mysql":4}}`)
		case "/v1/environments/a/vault-items/platform/mysql/fields/tls_cert/content":
			response.Header().Set("Content-Type", "application/x-pem-file")
			response.Header().Set("Content-Disposition", `attachment; filename="server.pem"`)
			response.Header().Set("ETag", `"vault-mysql-4"`)
			_, _ = response.Write([]byte("private-file-sentinel"))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: token, TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resolved, err := client.ReadResolvedConfig(context.Background(), "a", "payment", `"old"`)
	if err != nil {
		t.Fatalf("ReadResolvedConfig: %v", err)
	}
	if resolved.Format != "yaml" || resolved.ConfigRevision != 7 || resolved.VaultRevisions["platform.mysql"] != 4 ||
		resolved.ETag != `"cfg-7-vault-mysql-4"` || !strings.Contains(resolved.Content, "resolved-secret-sentinel") {
		t.Fatalf("Resolved Config = %#v", resolved)
	}

	file, err := client.ReadFile(context.Background(), "a", "platform", "mysql", "tls_cert", `"old"`)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(file.Bytes) != "private-file-sentinel" || file.Filename != "server.pem" ||
		file.ContentType != "application/x-pem-file" || file.ETag != `"vault-mysql-4"` {
		t.Fatalf("File = %#v", file)
	}
}

func TestClientReadsMaximumResolvedConfigAfterJSONEscaping(t *testing.T) {
	content := "value: |\n" + strings.Repeat("  x\n", (maxContentBytes-len("value: |\n"))/len("  x\n"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("ETag", `"maximum"`)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"format": "yaml", "content": content, "config_revision": 1, "vault_revisions": map[string]uint64{},
		})
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resolved, err := client.ReadResolvedConfig(context.Background(), "a", "payment", "")
	if err != nil {
		t.Fatalf("ReadResolvedConfig: %v", err)
	}
	if resolved.Content != content {
		t.Fatalf("Resolved Config content length = %d, want %d", len(resolved.Content), len(content))
	}
}

func TestClientReturnsNotModifiedAndStableAPIErrorWithoutResponseValues(t *testing.T) {
	token := testToken()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/environments/a/configs/not-modified":
			response.Header().Set("ETag", `"same"`)
			response.WriteHeader(http.StatusNotModified)
		case "/v1/environments/a/configs/api-error":
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(response, `{"error":{"code":"environment_forbidden","request_id":"0123456789abcdef01234567"}}`)
		default:
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"format":"yaml","content":"malformed-secret-sentinel","config_revision":0,"vault_revisions":{}}`)
		}
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: token, TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.ReadResolvedConfig(context.Background(), "a", "not-modified", `"same"`)
	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("not-modified error = %v", err)
	}

	_, err = client.ReadResolvedConfig(context.Background(), "a", "api-error", "")
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusForbidden ||
		apiError.Code != "environment_forbidden" || apiError.RequestID != "0123456789abcdef01234567" {
		t.Fatalf("API error = %#v, %v", apiError, err)
	}

	_, err = client.ReadResolvedConfig(context.Background(), "a", "malformed", "")
	if err == nil || strings.Contains(err.Error(), "malformed-secret-sentinel") {
		t.Fatalf("malformed response error = %v", err)
	}
}

func TestClientRejectsUnsafeConfigurationResourceKeysAndRedirects(t *testing.T) {
	for name, options := range map[string]ClientOptions{
		"plain HTTP":         {BaseURL: "http://configra.example.com", Token: testToken()},
		"credential in URL":  {BaseURL: "https://user:secret-sentinel@configra.example.com", Token: testToken()},
		"base URL path":      {BaseURL: "https://configra.example.com/api", Token: testToken()},
		"missing hostname":   {BaseURL: "https://:443", Token: testToken()},
		"missing Token":      {BaseURL: "https://configra.example.com"},
		"disabled TLS check": {BaseURL: "https://configra.example.com", Token: testToken(), TLSConfig: &tls.Config{InsecureSkipVerify: true}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(options); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatalf("NewClient error = %v", err)
			}
		})
	}

	targetRequests := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetRequests++ }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client, err := NewClient(ClientOptions{BaseURL: redirect.URL, Token: testToken(), TLSConfig: trustServer(redirect)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ReadResolvedConfig(context.Background(), "../a", "payment", ""); err == nil {
		t.Fatal("invalid Environment key was accepted")
	}
	if _, err := client.ReadResolvedConfig(context.Background(), "a", "payment", ""); err == nil {
		t.Fatal("redirect was accepted")
	}
	if targetRequests != 0 {
		t.Fatalf("redirect target received %d requests", targetRequests)
	}
}

func TestClientBoundsFileAndErrorResponsesWithoutLeakingBodies(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "/configs/") {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write(bytes.Repeat([]byte("error-body-secret-sentinel"), maxErrorBytes))
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("Content-Disposition", `attachment; filename="large.bin"`)
		response.Header().Set("ETag", `"large"`)
		_, _ = response.Write(bytes.Repeat([]byte("x"), maxContentBytes+1))
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ReadResolvedConfig(context.Background(), "a", "payment", ""); err == nil || strings.Contains(err.Error(), "error-body-secret-sentinel") {
		t.Fatalf("oversized API error = %v", err)
	}
	if _, err := client.ReadFile(context.Background(), "a", "platform", "mysql", "tls_cert", ""); err == nil {
		t.Fatal("oversized File response succeeded")
	}
}

func TestClientRotatesRuntimeCertificateAfterClosingIdleConnections(t *testing.T) {
	first := testClientCertificate(t, 1)
	second := testClientCertificate(t, 2)
	serials := make(chan int64, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		serials <- request.TLS.PeerCertificates[0].SerialNumber.Int64()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("ETag", `"revision-1"`)
		_, _ = io.WriteString(response, `{"format":"json","content":"{}","config_revision":1,"vault_revisions":{}}`)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	var certificate atomic.Pointer[tls.Certificate]
	certificate.Store(&first)
	tlsConfig := trustServer(server)
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return certificate.Load(), nil
	}
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: tlsConfig})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ReadResolvedConfig(context.Background(), "a", "payment", ""); err != nil {
		t.Fatalf("ReadResolvedConfig: %v", err)
	}
	if serial := <-serials; serial != 1 {
		t.Fatalf("initial Client Certificate serial = %d, want 1", serial)
	}

	certificate.Store(&second)
	client.CloseIdleConnections()
	if _, err := client.ReadResolvedConfig(context.Background(), "a", "payment", ""); err != nil {
		t.Fatalf("ReadResolvedConfig after rotation: %v", err)
	}
	if serial := <-serials; serial != 2 {
		t.Fatalf("rotated Client Certificate serial = %d, want 2", serial)
	}
}

func testClientCertificate(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Client Certificate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create Client Certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

func trustServer(server *httptest.Server) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &tls.Config{RootCAs: roots}
}

func testToken() string {
	return fmt.Sprintf("cfg_token1_%s", base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
}

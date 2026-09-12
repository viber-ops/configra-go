package configra

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSFilesReadThroughVerifiedMTLS(t *testing.T) {
	certificate := testClientCertificate(t, 42)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken() || r.TLS.PeerCertificates[0].SerialNumber.Int64() != 42 {
			t.Error("unexpected client identity")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"one"`)
		io.WriteString(w, `{"format":"yaml","content":"port: 8080","config_revision":1,"vault_revisions":{}}`)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	directory := writeTestTLSFiles(t, certificate)
	serverCA := writeTestTLSFile(t, directory, "server-ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	for _, combined := range []bool{true, false} {
		options := ClientOptions{BaseURL: server.URL, Token: testToken(), ClientCertificateFile: filepath.Join(directory, "client.pem"), ServerCAFile: serverCA}
		if !combined {
			options.ClientCertificateFile = filepath.Join(directory, "client.crt")
			options.ClientKeyFile = filepath.Join(directory, "client.key")
		}
		client, err := NewClient(options)
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		if _, err := client.ReadResolvedConfig(context.Background(), "development", "payment", ""); err != nil {
			t.Fatalf("verified mTLS read failed: %v", err)
		}
	}
}

func TestTLSFilesDoNotDisableServerVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted server received a request") }))
	defer server.Close()
	directory := writeTestTLSFiles(t, testClientCertificate(t, 1))
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), ClientCertificateFile: filepath.Join(directory, "client.pem")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.ReadResolvedConfig(context.Background(), "development", "payment", ""); err == nil {
		t.Fatal("untrusted server was accepted without server CA")
	}
}

func TestTLSFilesRejectInvalidInputsWithoutLeaking(t *testing.T) {
	directory := writeTestTLSFiles(t, testClientCertificate(t, 1))
	malformed := writeTestTLSFile(t, directory, "malformed", []byte("private-error-sentinel"))
	oversized := writeTestTLSFile(t, directory, "oversized", []byte(strings.Repeat("x", 1<<20+1)))
	for name, options := range map[string]ClientOptions{
		"certificate":             {ClientCertificateFile: malformed},
		"key":                     {ClientCertificateFile: filepath.Join(directory, "client.crt"), ClientKeyFile: malformed},
		"CA":                      {ServerCAFile: malformed},
		"missing":                 {ClientCertificateFile: filepath.Join(directory, "missing")},
		"missing CA":              {ServerCAFile: filepath.Join(directory, "missing")},
		"certificate without key": {ClientCertificateFile: filepath.Join(directory, "client.crt")},
		"key without certificate": {ClientKeyFile: filepath.Join(directory, "client.key")},
		"mixed":                   {ClientCertificateFile: filepath.Join(directory, "client.pem"), TLSConfig: &tls.Config{}},
		"oversized certificate":   {ClientCertificateFile: oversized},
		"oversized key":           {ClientCertificateFile: filepath.Join(directory, "client.crt"), ClientKeyFile: oversized},
		"oversized CA":            {ServerCAFile: oversized},
	} {
		t.Run(name, func(t *testing.T) {
			options.BaseURL, options.Token = "https://configra.example.com", testToken()
			_, err := NewClient(options)
			if err == nil || strings.Contains(err.Error(), "private-error-sentinel") || strings.Contains(err.Error(), directory) {
				t.Fatalf("invalid value-free error: %v", err)
			}
		})
	}
}

func writeTestTLSFiles(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	directory := t.TempDir()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	writeTestTLSFile(t, directory, "client.crt", certPEM)
	writeTestTLSFile(t, directory, "client.key", keyPEM)
	writeTestTLSFile(t, directory, "client.pem", append(append([]byte(nil), certPEM...), keyPEM...))
	return directory
}

func writeTestTLSFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTLSFilesRejectWrongCertificateRoleOrLifetime(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"CA instead of a client identity":       func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		"does not permit client authentication": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		},
		"not yet valid": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			certificate := testClientCertificate(t, 1)
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			change(leaf)
			der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			certificate.Certificate[0] = der
			directory := writeTestTLSFiles(t, certificate)
			_, err = NewClient(ClientOptions{BaseURL: "https://example.com", Token: testToken(), ClientCertificateFile: filepath.Join(directory, "client.pem")})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("certificate guidance = %v", err)
			}
		})
	}
}

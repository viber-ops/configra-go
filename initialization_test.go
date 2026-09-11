package configra

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializationPathsUseTheSameAuthenticatedClient(t *testing.T) {
	clearClientEnvironment(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken() {
			t.Error("wrong token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"one"`)
		io.WriteString(w, `{"format":"json","content":"{}","config_revision":1,"vault_revisions":{}}`)
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenFile := writeTestTLSFile(t, directory, "token", []byte(testToken()+"\n"))
	caFile := writeTestTLSFile(t, directory, "ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	settings := writeTestTLSFile(t, directory, "client.yaml", []byte(fmt.Sprintf("url: %s\ntoken_file: token\nserver_ca_file: ca.crt\ntimeout: 2s\n", server.URL)))
	// File initialization ignores unrelated ambient CONFIGRA_* settings.
	t.Setenv("CONFIGRA_URL", "http://invalid.example.com")
	fromFile, err := NewClientFromFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIGRA_URL", server.URL)
	t.Setenv("CONFIGRA_TOKEN_FILE", tokenFile)
	t.Setenv("CONFIGRA_SERVER_CA", caFile)
	fromEnv, err := NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	fromOptions, err := NewClient(ClientOptions{BaseURL: server.URL, TokenFile: tokenFile, ServerCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*Client{fromFile, fromEnv, fromOptions} {
		defer client.CloseIdleConnections()
		if _, err := client.ReadResolvedConfig(context.Background(), "development", "payment", ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSettingsFileFailsClosed(t *testing.T) {
	directory := t.TempDir()
	for name, value := range map[string]string{
		"unknown":            "url: https://example.com\nprivate-error-sentinel: secret-value\n",
		"multiple documents": "url: https://example.com\n---\ntoken: secret-value\n",
		"duplicate":          "url: https://example.com\nurl: https://another.example.com\n",
		"malformed":          "url: [",
		"oversized":          strings.Repeat("x", 64<<10+1),
		"missing token":      "url: https://example.com\n",
		"key without cert":   fmt.Sprintf("url: https://example.com\ntoken: %s\nkey_file: missing\n", testToken()),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestTLSFile(t, directory, "settings.yaml", []byte(value))
			_, err := NewClientFromFile(path)
			if err == nil || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "private-error-sentinel") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
	if _, err := NewClientFromFile(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing settings accepted")
	}
}

func TestEnvironmentInitializationRejectsInvalidAndMixedSources(t *testing.T) {
	clearClientEnvironment(t)
	t.Setenv("CONFIGRA_URL", "https://example.com")
	t.Setenv("CONFIGRA_TOKEN", testToken())
	t.Setenv("CONFIGRA_TIMEOUT", "private-error-sentinel")
	if _, err := NewClientFromEnv(); err == nil || strings.Contains(err.Error(), "private-error-sentinel") {
		t.Fatalf("timeout error: %v", err)
	}
	t.Setenv("CONFIGRA_TIMEOUT", "-1s")
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("negative timeout accepted")
	}
	t.Setenv("CONFIGRA_TIMEOUT", "")
	t.Setenv("CONFIGRA_TOKEN_FILE", "/not-read-when-ambiguous")
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("mixed token sources accepted")
	}
	t.Setenv("CONFIGRA_TOKEN", "")
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("missing token file accepted")
	}
}

func clearClientEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CONFIGRA_URL", "CONFIGRA_TOKEN", "CONFIGRA_TOKEN_FILE", "CONFIGRA_CLIENT_CERT", "CONFIGRA_CLIENT_KEY", "CONFIGRA_SERVER_CA", "CONFIGRA_TIMEOUT"} {
		t.Setenv(key, "")
	}
}

func TestInitializationErrorsIdentifyTheSourceAndRepair(t *testing.T) {
	clearClientEnvironment(t)
	_, err := NewClientFromEnv()
	if err == nil || !strings.Contains(err.Error(), "CONFIGRA_URL") || !strings.Contains(err.Error(), "HTTPS origin") {
		t.Fatalf("missing URL guidance = %v", err)
	}
	t.Setenv("CONFIGRA_URL", "https://example.com")
	_, err = NewClientFromEnv()
	if err == nil || !strings.Contains(err.Error(), "CONFIGRA_TOKEN") || !strings.Contains(err.Error(), "Administration") {
		t.Fatalf("missing Token guidance = %v", err)
	}
	path := writeTestTLSFile(t, t.TempDir(), "settings.yaml", []byte("url: https://example.com\ncert_path: private-error-sentinel\n"))
	_, err = NewClientFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "cert_file") || strings.Contains(err.Error(), "private-error-sentinel") {
		t.Fatalf("unknown field guidance = %v", err)
	}
	path = writeTestTLSFile(t, t.TempDir(), "settings.yaml", []byte("url: https://example.com\nurl: https://example.com\n"))
	_, err = NewClientFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "url") || !strings.Contains(err.Error(), "duplicated at line 2") {
		t.Fatalf("duplicate guidance = %v", err)
	}
}

package configra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteFileCarriesBytesAndOperationIdentityAndRedactsFailures(t *testing.T) {
	secret := []byte{0, 255, '\n', 'k', 'e', 'y'}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testToken() || request.Header.Get("Idempotency-Key") != "operator-upload-001" {
			t.Error("missing credential or operation identity")
		}
		if request.URL.Path != "/v1/environments/testing/vault-items/deployment/secrets/fields/key" || request.Method != "PUT" {
			t.Error("incorrect write route")
		}
		var body VaultFieldWrite
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.Type != "file" || body.ExpectedRevision != 1 || body.Value.File == nil || !bytes.Equal(body.Value.File.Bytes, secret) {
			t.Error("binary upload did not survive JSON encoding")
		}
		response.WriteHeader(403)
		_ = json.NewEncoder(response).Encode(map[string]any{"error": map[string]string{"code": "scope_forbidden", "request_id": "00112233445566778899aabb", "detail": "private-error-marker"}})
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	_, err = client.WriteFile(context.Background(), "testing", "deployment", "secrets", "key", FileWrite{
		RevisionWrite: RevisionWrite{OperationID: "operator-upload-001", ExpectedRevision: 1},
		Name:          "Key", File: VaultFile{Filename: "private.key", ContentType: "application/octet-stream", Bytes: secret},
	})
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != 403 || api.Code != "scope_forbidden" {
		t.Fatal("missing value-free API error")
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), testToken()) {
		t.Fatal("write error leaked a value")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.WriteConfig(canceled, "testing", "server", ConfigWrite{RevisionWrite: RevisionWrite{OperationID: "operator-config-001"}, Name: "server", Format: "yaml", Content: "private: secret"})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("write did not honor cancellation")
	}
}

func TestWriteClientRejectsMalformedSuccessWithoutReturningPrivateContent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			_, _ = response.Write([]byte(`{"environment_key":"foreign","config_key":"server","format":"yaml","content":"private-response-marker","revision":1}`))
		} else {
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result, err := client.ReadRawConfig(context.Background(), "testing", "server")
	if err == nil || result.Content != "" || strings.Contains(err.Error(), "private-response-marker") {
		t.Fatal("invalid response escaped validation/redaction")
	}
	if err := client.RevokeDeploymentCredential(context.Background(), "testing", "0123456789abcdef", "revoke-deployment-001"); err == nil {
		t.Fatal("empty reply claimed a successful revocation")
	}
}

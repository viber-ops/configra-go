package configra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientReadsIdentityMetadataAndPreservesThrottleDelay(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/environments/testing/identity" {
			fmt.Fprint(response, `{"public_id":"0123456789abcdef","kind":"read-only","environment":"testing","config_keys":[],"namespace_keys":null,"expires_at":null,"authentication":"token_only"}`)
			return
		}
		response.Header().Set("Retry-After", "12")
		response.WriteHeader(429)
		fmt.Fprint(response, `{"error":{"code":"write_rate_limited"}}`)
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.ReadIdentity(context.Background(), "testing")
	if err != nil || identity.Kind != "read-only" || identity.ConfigKeys == nil || identity.NamespaceKeys != nil {
		t.Fatal("identity lost scope semantics")
	}
	_, err = client.ReadResolvedConfig(context.Background(), "testing", "server", "")
	var api *APIError
	if !errors.As(err, &api) || api.RetryAfter != 12*time.Second {
		t.Fatalf("throttle metadata: %v", err)
	}
}

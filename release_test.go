package configra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestReleaseSnapshotRejectsWholeCandidateAndCopiesFileBytes(t *testing.T) {
	var generation atomic.Int32
	generation.Store(1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/environments/prod/configs/server/release" {
			t.Error("release consumer used independent current read")
			w.WriteHeader(404)
			return
		}
		n := generation.Load()
		w.Header().Set("ETag", fmt.Sprintf(`"release-%d"`, n))
		fmt.Fprintf(w, `{"manifest":{"environment":"prod","config_key":"server","release_key":"release_%d","config_revision":%d,"config_path":"server.yaml","files":[{"namespace":"ops","item":"app","field":"key","path":"key.pem","revision":%d}],"vault_revisions":{"ops.app":%d}},"generation":%d,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config":{"format":"yaml","content":"version: %d\n","config_revision":%d,"vault_revisions":{"ops.app":%d}},"files":[{"path":"key.pem","bytes":"cHJpdmF0ZQ=="}]}`, n, n, n, n, n, n, n, n)
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewViperHandler(ViperHandlerOptions{Client: client, Environment: "prod", Config: "server", UseRelease: true, Validate: func(_ context.Context, snapshot *Snapshot) error {
		if string(snapshot.Files()["key.pem"]) != "private" {
			t.Error("validator did not receive the complete release")
		}
		if snapshot.ReleaseGeneration() == 2 {
			return errors.New("private-validator-details")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := handler.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	files := first.Files()
	files["key.pem"][0] = 'X'
	delete(files, "key.pem")
	if string(first.Files()["key.pem"]) != "private" {
		t.Fatal("mutable file escaped Snapshot")
	}
	generation.Store(2)
	if changed, err := handler.Reload(context.Background()); changed || !errors.Is(err, ErrSnapshotRejected) || handler.Current() != first {
		t.Fatal("rejected candidate replaced part of the snapshot", err)
	}
	generation.Store(3)
	if changed, err := handler.Reload(context.Background()); !changed || err != nil || handler.Current().ReleaseKey() != "release_3" {
		t.Fatal("valid complete release was not installed", err)
	}
}

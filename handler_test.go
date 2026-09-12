package configra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSnapshotDecodeErrorsDoNotExposeValues(t *testing.T) {
	const secret = "snapshot-secret-must-not-appear-in-errors"
	state := &resolvedState{}
	state.set("yaml", "password: "+secret+"\n", 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewViperHandler(ViperHandlerOptions{Client: client, Environment: "a", Config: "payment"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := handler.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var target struct{ Password int }
	err = snapshot.Unmarshal(&target)
	if err == nil {
		t.Fatal("expected a decoding error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("decoding error disclosed a configuration value")
	}
}

func TestViperHandlerLoadsReloadsAndRetainsLastKnownGood(t *testing.T) {
	state := &resolvedState{}
	state.set("yaml", "database:\n  host: 10.0.0.1\n  port: 3306\n", 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	callbacks := 0
	var handler *ViperHandler
	handler, err = NewViperHandler(ViperHandlerOptions{
		Client:      client,
		Environment: "a",
		Config:      "payment",
		OnChange: func(_ context.Context, previous, current *Snapshot) error {
			callbacks++
			if previous.ConfigRevision() != 1 || current.ConfigRevision() != 2 || handler.Current() != current {
				t.Errorf("callback snapshots = %d -> %d, installed = %v", previous.ConfigRevision(), current.ConfigRevision(), handler.Current() == current)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	snapshot, err := handler.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var initial struct {
		Database struct {
			Host string
			Port int
		}
	}
	if err := snapshot.Unmarshal(&initial); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if initial.Database.Host != "10.0.0.1" || initial.Database.Port != 3306 || snapshot.ConfigRevision() != 1 || callbacks != 0 {
		t.Fatalf("initial Snapshot = %#v, revision %d, callbacks %d", initial, snapshot.ConfigRevision(), callbacks)
	}

	state.set("yaml", "database:\n  host: 10.0.0.2\n  port: 3307\n", 2, `"revision-2"`)
	changed, err := handler.Reload(context.Background())
	if err != nil || !changed || callbacks != 1 || handler.Current().ConfigRevision() != 2 {
		t.Fatalf("Reload = %v, %v; callbacks %d, current %d", changed, err, callbacks, handler.Current().ConfigRevision())
	}
	revisions := handler.Current().VaultRevisions()
	revisions["mysql"] = 999
	if handler.Current().VaultRevisions()["platform.mysql"] != 2 {
		t.Fatal("Vault Revisions escaped the immutable Snapshot")
	}

	changed, err = handler.Reload(context.Background())
	if err != nil || changed || callbacks != 1 {
		t.Fatalf("unchanged Reload = %v, %v; callbacks %d", changed, err, callbacks)
	}
	state.set("yaml", "database: [malformed-secret-sentinel", 3, `"revision-3"`)
	changed, err = handler.Reload(context.Background())
	if err == nil || changed || handler.Current().ConfigRevision() != 2 {
		t.Fatalf("invalid Reload = %v, %v; current %d", changed, err, handler.Current().ConfigRevision())
	}
}

func TestViperHandlerInstallsBeforeReportingCallbackFailure(t *testing.T) {
	state := &resolvedState{}
	state.set("json", `{"feature":{"enabled":false}}`, 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	callbackErr := errors.New("caller apply failed")
	handler, err := NewViperHandler(ViperHandlerOptions{
		Client:      client,
		Environment: "a",
		Config:      "payment",
		OnChange: func(context.Context, *Snapshot, *Snapshot) error {
			return callbackErr
		},
	})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	if _, err := handler.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	state.set("json", `{"feature":{"enabled":true}}`, 2, `"revision-2"`)
	changed, err := handler.Reload(context.Background())
	if !changed || !errors.Is(err, callbackErr) || handler.Current().ConfigRevision() != 2 {
		t.Fatalf("Reload = %v, %v; current %d", changed, err, handler.Current().ConfigRevision())
	}
	var current struct {
		Feature struct{ Enabled bool }
	}
	if err := handler.Current().Unmarshal(&current); err != nil || !current.Feature.Enabled {
		t.Fatalf("installed Snapshot = %#v, %v", current, err)
	}
}

func TestViperHandlerInvokesChangeCallbackOutsideReloadLock(t *testing.T) {
	state := &resolvedState{}
	state.set("yaml", "value: one\n", 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var handler *ViperHandler
	nested := make(chan error, 1)
	handler, err = NewViperHandler(ViperHandlerOptions{
		Client: client, Environment: "a", Config: "payment",
		OnChange: func(ctx context.Context, _, _ *Snapshot) error {
			changed, err := handler.Reload(ctx)
			if err == nil && changed {
				err = errors.New("nested Reload unexpectedly installed another Snapshot")
			}
			nested <- err
			return err
		},
	})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	if _, err := handler.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	state.set("yaml", "value: two\n", 2, `"revision-2"`)
	done := make(chan error, 1)
	go func() {
		changed, err := handler.Reload(context.Background())
		if err == nil && !changed {
			err = errors.New("outer Reload did not install the changed Snapshot")
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reload deadlocked while OnChange called Reload")
	}
	if err := <-nested; err != nil {
		t.Fatalf("nested Reload: %v", err)
	}
}

func TestViperHandlerRejectsOverlappingChangedReloadAndKeepsCallbacksSerial(t *testing.T) {
	state := &resolvedState{}
	state.set("yaml", "value: one\n", 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	callbacks := make(chan uint64, 2)
	releaseCallback := make(chan struct{}, 2)
	handler, err := NewViperHandler(ViperHandlerOptions{
		Client:      client,
		Environment: "a",
		Config:      "payment",
		OnChange: func(_ context.Context, _ *Snapshot, current *Snapshot) error {
			callbacks <- current.ConfigRevision()
			<-releaseCallback
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	if _, err := handler.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	state.set("yaml", "value: two\n", 2, `"revision-2"`)
	type reloadResult struct {
		changed bool
		err     error
	}
	first := make(chan reloadResult, 1)
	go func() {
		changed, err := handler.Reload(context.Background())
		first <- reloadResult{changed: changed, err: err}
	}()
	if revision := <-callbacks; revision != 2 {
		t.Fatalf("first Callback revision = %d, want 2", revision)
	}
	state.set("yaml", "value: three\n", 3, `"revision-3"`)
	second := make(chan reloadResult, 1)
	go func() {
		changed, err := handler.Reload(context.Background())
		second <- reloadResult{changed: changed, err: err}
	}()
	select {
	case result := <-second:
		if result.changed || !errors.Is(result.err, ErrReloadRunning) {
			t.Fatalf("overlapping changed Reload = %v, %v; want false and ErrReloadRunning", result.changed, result.err)
		}
	case revision := <-callbacks:
		releaseCallback <- struct{}{}
		releaseCallback <- struct{}{}
		t.Fatalf("overlapping Callback started at revision %d", revision)
	case <-time.After(time.Second):
		releaseCallback <- struct{}{}
		t.Fatal("overlapping changed Reload blocked instead of returning an error")
	}
	var value struct{ Value string }
	if err := handler.Current().Unmarshal(&value); err != nil || value.Value != "two" {
		t.Fatalf("Current during Callback = %#v, %v", value, err)
	}
	releaseCallback <- struct{}{}
	if result := <-first; !result.changed || result.err != nil {
		t.Fatalf("first Reload = %v, %v", result.changed, result.err)
	}

	third := make(chan reloadResult, 1)
	go func() {
		changed, err := handler.Reload(context.Background())
		third <- reloadResult{changed: changed, err: err}
	}()
	if revision := <-callbacks; revision != 3 {
		t.Fatalf("retried Callback revision = %d, want 3", revision)
	}
	releaseCallback <- struct{}{}
	if result := <-third; !result.changed || result.err != nil {
		t.Fatalf("retried Reload = %v, %v", result.changed, result.err)
	}
}

func TestViperHandlerWatchBacksOffRetainsSnapshotAndStopsWithContext(t *testing.T) {
	state := &resolvedState{}
	state.set("yaml", "value: one\n", 1, `"revision-1"`)
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	changes := make(chan uint64, 2)
	watchErrors := make(chan error, 1)
	handler, err := NewViperHandler(ViperHandlerOptions{
		Client:        client,
		Environment:   "a",
		Config:        "payment",
		WatchInterval: 5 * time.Second,
		OnChange: func(_ context.Context, _, current *Snapshot) error {
			changes <- current.ConfigRevision()
			return nil
		},
		OnError: func(err error) { watchErrors <- err },
	})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	if _, err := handler.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	waits := make(chan time.Duration, 4)
	ticks := make(chan struct{})
	handler.jitter = func(duration time.Duration) time.Duration { return duration }
	handler.wait = func(ctx context.Context, duration time.Duration) error {
		select {
		case waits <- duration:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-ticks:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.Watch(ctx) }()
	if delay := <-waits; delay != 5*time.Second {
		t.Fatalf("initial Watch delay = %s", delay)
	}
	if err := handler.Watch(context.Background()); !errors.Is(err, ErrWatchRunning) {
		t.Fatalf("second Watch error = %v", err)
	}

	state.set("yaml", "value: two\n", 2, `"revision-2"`)
	ticks <- struct{}{}
	if revision := <-changes; revision != 2 {
		t.Fatalf("changed revision = %d", revision)
	}
	if delay := <-waits; delay != 5*time.Second {
		t.Fatalf("post-success Watch delay = %s", delay)
	}
	state.set("yaml", "value: [malformed-secret-sentinel", 3, `"revision-3"`)
	ticks <- struct{}{}
	if err := <-watchErrors; err == nil {
		t.Fatal("invalid Watch response was not reported")
	}
	if handler.Current().ConfigRevision() != 2 {
		t.Fatalf("Current revision after failure = %d", handler.Current().ConfigRevision())
	}
	if delay := <-waits; delay != 10*time.Second {
		t.Fatalf("failure backoff = %s", delay)
	}
	state.set("yaml", "value: three\n", 3, `"revision-3"`)
	ticks <- struct{}{}
	if revision := <-changes; revision != 3 {
		t.Fatalf("recovered revision = %d", revision)
	}
	if delay := <-waits; delay != 5*time.Second {
		t.Fatalf("recovered Watch delay = %s", delay)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch cancellation = %v", err)
	}
}

func TestViperHandlerRejectsInvalidSetupAndColdStartFailure(t *testing.T) {
	if _, err := NewViperHandler(ViperHandlerOptions{WatchInterval: 4 * time.Second}); err == nil {
		t.Fatal("invalid Handler setup succeeded")
	}
	state := &resolvedState{status: http.StatusServiceUnavailable}
	server := httptest.NewTLSServer(state)
	defer server.Close()
	client, err := NewClient(ClientOptions{BaseURL: server.URL, Token: testToken(), TLSConfig: trustServer(server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	handler, err := NewViperHandler(ViperHandlerOptions{Client: client, Environment: "a", Config: "payment"})
	if err != nil {
		t.Fatalf("NewViperHandler: %v", err)
	}
	if _, err := handler.Load(context.Background()); err == nil || handler.Current() != nil {
		t.Fatalf("cold-start Load = %v, current %#v", err, handler.Current())
	}
	if _, err := handler.Reload(context.Background()); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Reload before Load error = %v", err)
	}
	state.set("yaml", "recovered: true\n", 1, `"revision-1"`)
	if _, err := handler.Load(context.Background()); err != nil || handler.Current().ConfigRevision() != 1 {
		t.Fatalf("recovered cold-start Load = %v, current %#v", err, handler.Current())
	}
}

type resolvedState struct {
	mu       sync.Mutex
	format   string
	content  string
	revision uint64
	etag     string
	status   int
}

func (state *resolvedState) set(format, content string, revision uint64, etag string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.format = format
	state.content = content
	state.revision = revision
	state.etag = etag
	state.status = http.StatusOK
}

func (state *resolvedState) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.status != 0 && state.status != http.StatusOK {
		response.WriteHeader(state.status)
		_, _ = response.Write([]byte(`{"error":{"code":"service_unavailable","request_id":"0123456789abcdef01234567"}}`))
		return
	}
	if request.Header.Get("If-None-Match") == state.etag {
		response.Header().Set("ETag", state.etag)
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("ETag", state.etag)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"format":          state.format,
		"content":         state.content,
		"config_revision": state.revision,
		"vault_revisions": map[string]uint64{"platform.mysql": state.revision},
	})
}

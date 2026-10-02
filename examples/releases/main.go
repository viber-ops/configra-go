// A release consumer validates Config + File members before installing state.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	configra "github.com/viber-ops/configra-go"
)

type applicationState struct {
	Port       int
	SigningKey []byte
}

func validated(snapshot *configra.Snapshot) (*applicationState, error) {
	var settings struct{ Port int }
	if snapshot.Unmarshal(&settings) != nil || settings.Port < 1 || settings.Port > 65535 {
		return nil, errors.New("invalid application port")
	}
	key := snapshot.Files()["secrets/signing.key"]
	if len(key) == 0 {
		return nil, errors.New("required signing key is missing")
	}
	return &applicationState{Port: settings.Port, SigningKey: key}, nil
}

func run(ctx context.Context) error {
	client, err := configra.NewClientFromEnv()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	var current atomic.Pointer[applicationState]
	handler, err := configra.NewViperHandler(configra.ViperHandlerOptions{
		Client: client, Environment: os.Getenv("CONFIGRA_ENVIRONMENT"), Config: os.Getenv("CONFIGRA_CONFIG"), UseRelease: true,
		Validate: func(ctx context.Context, candidate *configra.Snapshot) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := validated(candidate)
			return err
		},
		OnChange: func(_ context.Context, _, candidate *configra.Snapshot) error {
			state, err := validated(candidate)
			if err != nil {
				return err
			}
			current.Store(state)
			fmt.Printf("installed release=%s generation=%d\n", candidate.ReleaseKey(), candidate.ReleaseGeneration())
			return nil
		},
		OnError: func(error) { fmt.Fprintln(os.Stderr, "release refresh failed; keeping previous application state") },
	})
	if err != nil {
		return err
	}
	initial, err := handler.Load(ctx)
	if err != nil {
		return err
	}
	state, err := validated(initial)
	if err != nil {
		return err
	}
	current.Store(state)
	// Application handlers load current once per operation and use that complete
	// state. Neither the resolved document nor key bytes are printed.
	return handler.Watch(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "release consumer failed; check metadata and validation policy")
		os.Exit(1)
	}
}

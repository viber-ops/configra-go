// Read configuration without printing its potentially sensitive contents.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	configra "github.com/viber-ops/configra-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	client, err := configra.NewClientFromEnv()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.ReadResolvedConfig(ctx, "development", "payment", "")
	if err != nil {
		return err
	}
	// Parse result.Content into your application model here. Never log it by default.
	fmt.Printf("Loaded Config revision %d (%s)\n", result.ConfigRevision, result.Format)
	return nil
}

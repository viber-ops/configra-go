// Upload server.yaml and secret files, then save a read-only deployment identity.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	environment := flag.String("environment", "testing", "existing Environment key")
	namespace := flag.String("namespace", "deployment", "allowed Vault namespace key")
	authority := flag.String("authority", "", "administrator-provided managed CA ID")
	configFile := flag.String("config", "server.yaml", "YAML document to upload as Config server")
	output := flag.String("output", "deployment-identity", "new private directory for credentials")
	flag.Parse()
	if *authority == "" || flag.NArg() == 0 {
		return errors.New("provide -authority and secret file paths")
	}
	// Credentials come from CONFIGRA_TOKEN_FILE, CONFIGRA_CLIENT_CERT,
	// CONFIGRA_CLIENT_KEY and CONFIGRA_SERVER_CA, never command-line arguments.
	client, err := configra.NewClientFromEnv()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var vaultRevision uint64
	item, err := client.ReadVaultItem(ctx, *environment, *namespace, "secrets")
	if err == nil {
		vaultRevision = item.Revision
	} else if !notFound(err) {
		return err
	}
	fields := make([]configra.VaultField, 0, flag.NArg())
	values := make(map[string]configra.VaultValue, flag.NArg())
	defer func() {
		for _, value := range values {
			if value.File != nil {
				clear(value.File.Bytes)
			}
		}
	}()
	for index, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			return errors.New("cannot read a secret file")
		}
		key := fmt.Sprintf("file_%02d", index+1)
		fields = append(fields, configra.VaultField{Key: key, Name: fmt.Sprintf("File %d", index+1), Type: "file"})
		values[key] = configra.VaultValue{File: &configra.VaultFile{Filename: filepath.Base(path), ContentType: "application/octet-stream", Bytes: data}}
	}
	if _, err := client.WriteVaultItem(ctx, *environment, *namespace, "secrets", configra.VaultItemWrite{
		RevisionWrite: configra.RevisionWrite{OperationID: rand.Text(), ExpectedRevision: vaultRevision}, Fields: fields, Values: values,
	}); err != nil {
		return err
	}
	var configRevision uint64
	previous, err := client.ReadRawConfig(ctx, *environment, "server")
	if err == nil {
		configRevision = previous.Revision
	} else if !notFound(err) {
		return err
	}
	content, err := os.ReadFile(*configFile)
	if err != nil {
		return errors.New("cannot read Config YAML")
	}
	_, err = client.WriteConfig(ctx, *environment, "server", configra.ConfigWrite{
		RevisionWrite: configra.RevisionWrite{OperationID: rand.Text(), ExpectedRevision: configRevision},
		Name:          "server.yaml", Format: "yaml", Content: string(content),
	})
	clear(content)
	if err != nil {
		return err
	}
	// Reserve the directory before issuing one-time credentials; never overwrite.
	if err := os.Mkdir(*output, 0700); err != nil {
		return errors.New("credential output directory must be new")
	}
	credential, err := client.IssueDeploymentCredential(ctx, *environment, configra.DeploymentCredentialIssue{
		OperationID: rand.Text(), DisplayName: "deployment-host", AuthorityID: *authority, ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		return err
	}
	bundle, err := base64.StdEncoding.DecodeString(credential.Certificate.ExportBundle)
	if err != nil || credential.Token.Token == "" {
		return errors.New("one-time credentials were not returned")
	}
	defer clear(bundle)
	if err := os.WriteFile(filepath.Join(*output, "token"), []byte(credential.Token.Token), 0600); err != nil {
		return errors.New("cannot save deployment Token")
	}
	if err := os.WriteFile(filepath.Join(*output, "client.zip"), bundle, 0600); err != nil {
		return errors.New("cannot save deployment certificate bundle")
	}
	fmt.Printf("Deployment credential %s saved; keep the Token and private key off logs.\n", credential.Token.PublicID)
	return nil
}

func notFound(err error) bool {
	var api *configra.APIError
	return errors.As(err, &api) && api.StatusCode == 404
}

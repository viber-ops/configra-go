package configra

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"
)

// NewClientFromEnv reads only CONFIGRA_* connection settings, then calls NewClient.
// Required: CONFIGRA_URL and either CONFIGRA_TOKEN or CONFIGRA_TOKEN_FILE.
// Optional: CONFIGRA_CLIENT_CERT, CONFIGRA_CLIENT_KEY, CONFIGRA_SERVER_CA,
// CONFIGRA_TIMEOUT (a Go duration such as "10s"). It never searches for files.
func NewClientFromEnv() (*Client, error) {
	options := ClientOptions{
		BaseURL: os.Getenv("CONFIGRA_URL"), Token: os.Getenv("CONFIGRA_TOKEN"),
		TokenFile:             os.Getenv("CONFIGRA_TOKEN_FILE"),
		ClientCertificateFile: os.Getenv("CONFIGRA_CLIENT_CERT"),
		ClientKeyFile:         os.Getenv("CONFIGRA_CLIENT_KEY"),
		ServerCAFile:          os.Getenv("CONFIGRA_SERVER_CA"),
	}
	if value := os.Getenv("CONFIGRA_TIMEOUT"); value != "" {
		var err error
		options.Timeout, err = time.ParseDuration(value)
		if err != nil {
			return nil, initializationSource(invalidInitialization("timeout", "is not a duration", "Use a value such as 10s or omit it for the default."), "environment")
		}
	}
	client, err := NewClient(options)
	return client, initializationSource(err, "environment")
}

// NewClientFromFile reads one strict YAML connection-settings document, then
// calls NewClient. Relative credential paths are relative to this file, not cwd.
// It does not merge environment variables or expand shell syntax. Files are read
// once; use TLSConfig.GetClientCertificate for advanced live identity rotation.
func NewClientFromFile(path string) (*Client, error) {
	data, err := readCredential(path, 64<<10)
	if err != nil {
		return nil, credentialReadError("settings file", err)
	}
	defer clear(data)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var options ClientOptions
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, invalidInitialization("settings file", "is not valid YAML", "Provide one mapping of connection settings; file contents are not included in diagnostics.")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalidInitialization("settings file", "contains more than one YAML document", "Keep a single connection-settings mapping in this file.")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, invalidInitialization("settings file", "must be a YAML mapping", "Start with url: https://configra-api.example.com and supply a Token source.")
	}
	fields := map[string]any{
		"url": &options.BaseURL, "token": &options.Token, "token_file": &options.TokenFile,
		"cert_file": &options.ClientCertificateFile, "key_file": &options.ClientKeyFile,
		"server_ca_file": &options.ServerCAFile, "timeout": &options.Timeout,
		"max_content_bytes": &options.MaxContentBytes,
	}
	seen := map[string]bool{}
	content := document.Content[0].Content
	for index := 0; index < len(content); index += 2 {
		key, value := content[index], content[index+1]
		target, known := fields[key.Value]
		if !known {
			return nil, invalidInitialization("settings file", fmt.Sprintf("has an unknown field at line %d", key.Line), "Allowed keys: url, token, token_file, cert_file, key_file, server_ca_file, timeout, max_content_bytes.")
		}
		if seen[key.Value] {
			return nil, initializationSource(invalidInitialization(key.Value, fmt.Sprintf("is duplicated at line %d", key.Line), "Keep only one value for each field; settings are not merged."), "file")
		}
		seen[key.Value] = true
		if err := value.Decode(target); err != nil {
			return nil, initializationSource(invalidInitialization(key.Value, fmt.Sprintf("has the wrong type or format at line %d", value.Line), "Use text for paths and Tokens, a duration such as 10s for timeout, and an integer for max_content_bytes."), "file")
		}
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("Configra cannot resolve client settings directory")
	}
	for _, value := range []*string{&options.TokenFile, &options.ClientCertificateFile, &options.ClientKeyFile, &options.ServerCAFile} {
		if *value != "" && !filepath.IsAbs(*value) {
			*value = filepath.Join(base, *value)
		}
	}
	client, err := NewClient(options)
	return client, initializationSource(err, "file")
}

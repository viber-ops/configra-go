package configra

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

type MutationResult struct {
	Outcome  string          `json:"outcome"`
	Revision uint64          `json:"revision,omitempty"`
	Warnings []ConfigWarning `json:"warnings,omitempty"`
}

type ConfigWarning struct {
	Code         string `json:"code"`
	NamespaceKey string `json:"namespace_key"`
	ItemKey      string `json:"item_key"`
	FieldKey     string `json:"field_key"`
}

// OperationID is required. Reuse it only for identical requests; ExpectedRevision
// is zero for creation and the current revision for updates (HTTP 409 on conflict).
type RevisionWrite struct {
	OperationID      string `json:"-"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type ConfigWrite struct {
	RevisionWrite
	Name    string `json:"name"`
	Format  string `json:"format"`
	Content string `json:"content"`
}

func (client *Client) WriteConfig(ctx context.Context, environment, config string, input ConfigWrite) (MutationResult, error) {
	var result MutationResult
	if len(input.Content) > maxContentBytes || (input.Format != "yaml" && input.Format != "json") {
		return result, errors.New("invalid Configra Config format or size")
	}
	err := client.requestJSON(ctx, http.MethodPut, configPath(environment, config), input.OperationID, input, &result, environment, config)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

type VaultField struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"type"` // text, secret, or file; immutable for a Field key.
}

type VaultValue struct {
	Text *string    `json:"text,omitempty"`
	File *VaultFile `json:"file,omitempty"`
}

type VaultFile struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Bytes       []byte `json:"bytes"` // JSON/base64 upload, encrypted with the Item snapshot.
}

type VaultItemWrite struct {
	RevisionWrite
	DisplayName string                `json:"display_name,omitempty"`
	Fields      []VaultField          `json:"fields"`
	Values      map[string]VaultValue `json:"values"`
}

type VaultItem struct {
	NamespaceKey string `json:"namespace_key"`
	Key          string `json:"key"`
	DisplayName  string `json:"display_name"`
	Revision     uint64 `json:"revision"`
	Snapshot     struct {
		Fields   []VaultField `json:"fields"`
		Variants []struct {
			ID           string                `json:"id"`
			Environments []string              `json:"environments"`
			Values       map[string]VaultValue `json:"values"`
		} `json:"variants"`
	} `json:"snapshot"`
}

// ReadVaultItem requires a write-scoped Token and returns only the requested
// Environment's current values, including small File fields.
func (client *Client) ReadVaultItem(ctx context.Context, environment, namespace, item string) (VaultItem, error) {
	var result VaultItem
	err := client.requestJSON(ctx, http.MethodGet, vaultItemPath(environment, namespace, item), "", nil, &result, environment, namespace, item)
	if err != nil {
		return VaultItem{}, err
	}
	return result, nil
}

// WriteVaultItem replaces the selected Environment's values. Shared schema/name
// changes require grants for every bound Environment; other values are retained.
func (client *Client) WriteVaultItem(ctx context.Context, environment, namespace, item string, input VaultItemWrite) (MutationResult, error) {
	var result MutationResult
	err := client.requestJSON(ctx, http.MethodPut, vaultItemPath(environment, namespace, item), input.OperationID, input, &result, environment, namespace, item)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

type VaultFieldWrite struct {
	RevisionWrite
	Name  string     `json:"name"`
	Type  string     `json:"type"`
	Value VaultValue `json:"value"`
}

func (client *Client) WriteVaultField(ctx context.Context, environment, namespace, item, field string, input VaultFieldWrite) (MutationResult, error) {
	var result MutationResult
	err := client.requestJSON(ctx, http.MethodPut, vaultItemPath(environment, namespace, item)+"/fields/"+field, input.OperationID, input, &result, environment, namespace, item, field)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

type FileWrite struct {
	RevisionWrite
	Name string
	File VaultFile
}

func (client *Client) WriteFile(ctx context.Context, environment, namespace, item, field string, input FileWrite) (MutationResult, error) {
	if len(input.File.Bytes) > maxContentBytes {
		return MutationResult{}, errors.New("Configra File exceeds 5 MiB")
	}
	return client.WriteVaultField(ctx, environment, namespace, item, field, VaultFieldWrite{
		RevisionWrite: input.RevisionWrite, Name: input.Name, Type: "file", Value: VaultValue{File: &input.File},
	})
}

// DeleteVaultItem archives the Item and retains history. It requires grants for
// all bound Environments. DeleteVaultField removes the shared Field definition.
func (client *Client) DeleteVaultItem(ctx context.Context, environment, namespace, item string, input RevisionWrite) (MutationResult, error) {
	var result MutationResult
	err := client.requestJSON(ctx, http.MethodDelete, vaultItemPath(environment, namespace, item), input.OperationID, input, &result, environment, namespace, item)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

func (client *Client) DeleteVaultField(ctx context.Context, environment, namespace, item, field string, input RevisionWrite) (MutationResult, error) {
	var result MutationResult
	err := client.requestJSON(ctx, http.MethodDelete, vaultItemPath(environment, namespace, item)+"/fields/"+field, input.OperationID, input, &result, environment, namespace, item, field)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

type DeploymentCredentialIssue struct {
	OperationID string    `json:"-"`
	DisplayName string    `json:"display_name"`
	AuthorityID string    `json:"authority_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type DeploymentCredential struct {
	Outcome string `json:"outcome"`
	Token   struct {
		Kind            string     `json:"kind"`
		PublicID        string     `json:"public_id"`
		Token           string     `json:"token,omitempty"`
		EnvironmentKeys []string   `json:"environment_keys"`
		ConfigKeys      []string   `json:"config_keys"`
		NamespaceKeys   []string   `json:"namespace_keys"`
		ExpiresAt       *time.Time `json:"expires_at"`
	} `json:"token"`
	Certificate struct {
		AuthorityID string `json:"authority_id"`
		Certificate struct {
			FingerprintSHA256 string    `json:"fingerprint_sha256"`
			NotAfter          time.Time `json:"not_after"`
		} `json:"certificate"`
		// Base64 ZIP containing client.crt, client.key and public ca.crt, returned once.
		ExportBundle string `json:"export_bundle,omitempty"`
	} `json:"certificate"`
}

// IssueDeploymentCredential atomically issues an mTLS-bound read-only Token and
// certificate with inherited scopes. Replay returns metadata without secrets.
func (client *Client) IssueDeploymentCredential(ctx context.Context, environment string, input DeploymentCredentialIssue) (DeploymentCredential, error) {
	var result DeploymentCredential
	err := client.requestJSON(ctx, http.MethodPost, "/v1/environments/"+environment+"/deployment-credentials", input.OperationID, input, &result, environment)
	if err != nil {
		return DeploymentCredential{}, err
	}
	return result, nil
}

func (client *Client) RevokeDeploymentCredential(ctx context.Context, environment, publicID, operationID string) error {
	if !validPublicID(publicID) {
		return errors.New("invalid Configra Token ID")
	}
	var result struct {
		Outcome  string `json:"outcome"`
		PublicID string `json:"public_id"`
		Revoked  bool   `json:"revoked"`
	}
	if err := client.requestJSON(ctx, http.MethodPost, "/v1/environments/"+environment+"/deployment-credentials/"+publicID+"/revoke", operationID, nil, &result, environment); err != nil {
		return err
	}
	if result.PublicID != publicID || !result.Revoked || (result.Outcome != "success" && result.Outcome != "no_change") {
		return errors.New("invalid Configra deployment revocation response")
	}
	return nil
}

type RawConfig struct {
	EnvironmentKey string `json:"environment_key"`
	ConfigKey      string `json:"config_key"`
	ConfigName     string `json:"config_name"`
	Format         string `json:"format"`
	Content        string `json:"content"`
	Revision       uint64 `json:"revision"`
}

func (client *Client) ReadRawConfig(ctx context.Context, environment, config string) (RawConfig, error) {
	var result RawConfig
	err := client.requestJSON(ctx, http.MethodGet, configPath(environment, config)+"/raw", "", nil, &result, environment, config)
	if err != nil {
		return RawConfig{}, err
	}
	return result, nil
}

func configPath(environment, config string) string {
	return "/v1/environments/" + environment + "/configs/" + config
}
func vaultItemPath(environment, namespace, item string) string {
	return "/v1/environments/" + environment + "/vault-items/" + namespace + "/" + item
}

func (client *Client) requestJSON(ctx context.Context, method, path, operationID string, input, result any, keys ...string) error {
	if client == nil || ctx == nil {
		return errors.New("Configra Client and Context are required")
	}
	for _, key := range keys {
		if !validResourceKey(key) {
			return errors.New("invalid Configra Resource Key")
		}
	}
	if method != http.MethodGet && !validOperationID(operationID) {
		return errors.New("invalid Configra OperationID")
	}
	var body io.Reader
	var payload []byte
	if input != nil {
		var err error
		payload, err = json.Marshal(input)
		// Transport may still own the request body when Do returns an early
		// rejection, so leave its backing bytes to Go rather than race a clear.
		if err != nil || len(payload) > 32<<20 {
			return errors.New("invalid Configra write request size or encoding")
		}
		body = bytes.NewReader(payload)
	}
	response, err := client.do(ctx, method, path, body, operationID, "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return decodeAPIError(response)
	}
	data, err := readLimited(response.Body, 32<<20)
	defer clear(data)
	if err != nil || decodeOneJSON(data, result) != nil {
		return errors.New("invalid Configra JSON response")
	}
	switch value := result.(type) {
	case *MutationResult:
		if (value.Outcome != "success" && value.Outcome != "no_change") || value.Revision == 0 {
			return errors.New("invalid Configra mutation response")
		}
	case *RawConfig:
		if value.Revision == 0 || value.EnvironmentKey != keys[0] || value.ConfigKey != keys[1] || (value.Format != "yaml" && value.Format != "json") || int64(len(value.Content)) > client.contentLimit {
			return errors.New("invalid Configra raw Config response")
		}
	case *VaultItem:
		if value.Revision == 0 || value.NamespaceKey != keys[1] || value.Key != keys[2] || len(value.Snapshot.Variants) != 1 || len(value.Snapshot.Variants[0].Environments) != 1 || value.Snapshot.Variants[0].Environments[0] != keys[0] {
			return errors.New("invalid Configra Vault response")
		}
	case *DeploymentCredential:
		fingerprint, fingerprintErr := hex.DecodeString(value.Certificate.Certificate.FingerprintSHA256)
		if value.Outcome != "success" || value.Token.Kind != "read-only" || !validPublicID(value.Token.PublicID) || len(value.Token.EnvironmentKeys) != 1 || value.Token.EnvironmentKeys[0] != keys[0] || value.Token.ExpiresAt == nil || value.Certificate.Certificate.NotAfter.IsZero() || fingerprintErr != nil || len(fingerprint) != 32 || (value.Token.Token != "" && !validToken(value.Token.Token)) || (value.Token.Token == "") != (value.Certificate.ExportBundle == "") {
			return errors.New("invalid Configra deployment credential response")
		}
	}
	return nil
}

func validPublicID(value string) bool {
	id, err := hex.DecodeString(value)
	return err == nil && len(id) == 8 && hex.EncodeToString(id) == value
}

func validOperationID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

package configra

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

type Identity struct {
	PublicID               string     `json:"public_id"`
	ParentPublicID         string     `json:"parent_public_id,omitempty"`
	Kind                   string     `json:"kind"`
	Environment            string     `json:"environment"`
	ConfigKeys             []string   `json:"config_keys"`
	NamespaceKeys          []string   `json:"namespace_keys"`
	ExpiresAt              *time.Time `json:"expires_at"`
	Authentication         string     `json:"authentication"`
	CertificateFingerprint string     `json:"certificate_fingerprint,omitempty"`
	CertificateExpiresAt   *time.Time `json:"certificate_expires_at,omitempty"`
}

func (client *Client) ReadIdentity(ctx context.Context, environment string) (Identity, error) {
	var result Identity
	if err := client.requestJSON(ctx, http.MethodGet, "/v1/environments/"+environment+"/identity", "", nil, &result, environment); err != nil {
		return Identity{}, err
	}
	if !validPublicID(result.PublicID) || (result.ParentPublicID != "" && !validPublicID(result.ParentPublicID)) || result.Environment != environment || (result.Kind != "read-only" && result.Kind != "write-scoped") || !validScopeKeys(result.ConfigKeys) || !validScopeKeys(result.NamespaceKeys) {
		return Identity{}, errors.New("invalid Configra identity metadata")
	}
	switch result.Authentication {
	case "mtls":
		fingerprint, err := hex.DecodeString(result.CertificateFingerprint)
		if err != nil || len(fingerprint) != 32 || result.CertificateExpiresAt == nil {
			return Identity{}, errors.New("invalid Configra certificate metadata")
		}
	case "token_only":
		if result.Kind == "write-scoped" || result.ParentPublicID != "" || result.CertificateFingerprint != "" {
			return Identity{}, errors.New("invalid Configra authentication metadata")
		}
	default:
		return Identity{}, errors.New("invalid Configra authentication metadata")
	}
	return result, nil
}

type DeploymentSummary struct {
	PublicID               string    `json:"public_id"`
	ParentPublicID         string    `json:"parent_public_id"`
	DisplayName            string    `json:"display_name"`
	ExpiresAt              time.Time `json:"expires_at"`
	Revoked                bool      `json:"revoked"`
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	ConfigKeys             []string  `json:"config_keys"`
	NamespaceKeys          []string  `json:"namespace_keys"`
}
type DeploymentPage struct {
	Items      []DeploymentSummary `json:"items"`
	NextCursor string              `json:"next_cursor"`
}

func (client *Client) ListDeploymentCredentials(ctx context.Context, environment, after string) (DeploymentPage, error) {
	if after != "" && !validPublicID(after) {
		return DeploymentPage{}, errors.New("invalid Configra deployment cursor")
	}
	var result DeploymentPage
	path := "/v1/environments/" + environment + "/deployment-credentials"
	// do encodes Path, so keep query separate from path segments via a dedicated suffix.
	if after != "" {
		path += "?after=" + after
	}
	if err := client.requestJSON(ctx, http.MethodGet, path, "", nil, &result, environment); err != nil {
		return DeploymentPage{}, err
	}
	if len(result.Items) > 100 || (result.NextCursor != "" && !validPublicID(result.NextCursor)) {
		return DeploymentPage{}, errors.New("invalid Configra deployment page")
	}
	for _, entry := range result.Items {
		fingerprint, err := hex.DecodeString(entry.CertificateFingerprint)
		if !validPublicID(entry.PublicID) || !validPublicID(entry.ParentPublicID) || entry.PublicID <= after || entry.ExpiresAt.IsZero() || err != nil || len(fingerprint) != 32 || !validScopeKeys(entry.ConfigKeys) || !validScopeKeys(entry.NamespaceKeys) {
			return DeploymentPage{}, errors.New("invalid Configra deployment metadata")
		}
	}
	return result, nil
}

func validScopeKeys(keys []string) bool {
	if len(keys) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if !validResourceKey(key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

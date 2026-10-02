package configra

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"path"
	"strings"
)

type ReleaseSpec struct {
	ConfigRevision uint64           `json:"config_revision"`
	ConfigPath     string           `json:"config_path"`
	Files          []ReleaseFileRef `json:"files"`
}
type ReleaseFileRef struct {
	Namespace string `json:"namespace"`
	Item      string `json:"item"`
	Field     string `json:"field"`
	Path      string `json:"path"`
	Revision  uint64 `json:"revision"`
}
type ReleaseManifest struct {
	Environment string `json:"environment"`
	ConfigKey   string `json:"config_key"`
	ReleaseKey  string `json:"release_key"`
	ReleaseSpec
	VaultRevisions map[string]uint64 `json:"vault_revisions"`
}
type ReleaseState struct {
	ReleaseKey string `json:"release_key"`
	Generation uint64 `json:"generation"`
}
type ReleaseResult struct {
	Outcome string `json:"outcome"`
	ReleaseState
	Digest string `json:"digest"`
}
type ReleasePrepare struct {
	OperationID string `json:"-"`
	ReleaseSpec
}
type ReleaseActivate struct {
	OperationID        string `json:"-"`
	ExpectedGeneration uint64 `json:"expected_generation"`
}
type ReleaseFile struct {
	Path  string `json:"path"`
	Bytes []byte `json:"bytes"`
}
type ReleaseBundle struct {
	Manifest   ReleaseManifest
	Generation uint64
	Digest     string
	Config     ResolvedConfig
	Files      []ReleaseFile
	ETag       string
}

// PrepareRelease records an immutable, bounded manifest without activating it.
// All File revisions and the Config revision must still be current at preparation.
func (client *Client) PrepareRelease(ctx context.Context, environment, config, key string, input ReleasePrepare) (ReleaseResult, error) {
	if !validReleaseSpec(input.ReleaseSpec) {
		return ReleaseResult{}, errors.New("invalid Configra release manifest")
	}
	var result ReleaseResult
	err := client.requestJSON(ctx, http.MethodPut, configPath(environment, config)+"/releases/"+key, input.OperationID, input, &result, environment, config, key)
	if err != nil {
		return ReleaseResult{}, err
	}
	if !validReleaseResult(result, key) {
		return ReleaseResult{}, errors.New("invalid Configra release response")
	}
	return result, nil
}

// ActivateRelease also rolls back by activating a previously prepared key.
// ExpectedGeneration is required; this method never retries a write automatically.
func (client *Client) ActivateRelease(ctx context.Context, environment, config, key string, input ReleaseActivate) (ReleaseResult, error) {
	var result ReleaseResult
	err := client.requestJSON(ctx, http.MethodPost, configPath(environment, config)+"/releases/"+key+"/activate", input.OperationID, input, &result, environment, config, key)
	if err != nil {
		return ReleaseResult{}, err
	}
	if !validReleaseResult(result, key) || result.Generation == 0 {
		return ReleaseResult{}, errors.New("invalid Configra release response")
	}
	return result, nil
}
func (client *Client) ReadReleaseState(ctx context.Context, environment, config string) (ReleaseState, error) {
	var result ReleaseState
	err := client.requestJSON(ctx, http.MethodGet, configPath(environment, config)+"/release-state", "", nil, &result, environment, config)
	if err != nil {
		return ReleaseState{}, err
	}
	if (result.Generation == 0) != (result.ReleaseKey == "") || (result.ReleaseKey != "" && !validResourceKey(result.ReleaseKey)) {
		return ReleaseState{}, errors.New("invalid Configra release state")
	}
	return result, nil
}

// ReadRelease fetches the entire immutable set in one snapshot. An empty key
// follows the active stream; a nonempty key reads a candidate for validation.
func (client *Client) ReadRelease(ctx context.Context, environment, config, key, etag string) (ReleaseBundle, error) {
	if client == nil || ctx == nil {
		return ReleaseBundle{}, errors.New("Configra Client and Context are required")
	}
	if !validResourceKey(environment) || !validResourceKey(config) || (key != "" && !validResourceKey(key)) {
		return ReleaseBundle{}, errors.New("invalid Configra Resource Key")
	}
	url := configPath(environment, config) + "/release"
	if key != "" {
		url = configPath(environment, config) + "/releases/" + key
	}
	response, err := client.get(ctx, url, etag)
	if err != nil {
		return ReleaseBundle{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return ReleaseBundle{}, ErrNotModified
	}
	if response.StatusCode != http.StatusOK {
		return ReleaseBundle{}, decodeAPIError(response)
	}
	data, err := readLimited(response.Body, max(128<<10, 8*client.contentLimit))
	defer clear(data)
	invalid := errors.New("invalid Configra release response")
	if err != nil {
		return ReleaseBundle{}, invalid
	}
	var wire struct {
		Manifest   ReleaseManifest `json:"manifest"`
		Generation uint64          `json:"generation"`
		Digest     string          `json:"digest"`
		Config     struct {
			Format         string            `json:"format"`
			Content        string            `json:"content"`
			ConfigRevision uint64            `json:"config_revision"`
			VaultRevisions map[string]uint64 `json:"vault_revisions"`
		} `json:"config"`
		Files []ReleaseFile `json:"files"`
	}
	if decodeOneJSON(data, &wire) != nil || wire.Manifest.Environment != environment || wire.Manifest.ConfigKey != config || !validResourceKey(wire.Manifest.ReleaseKey) || (key != "" && wire.Manifest.ReleaseKey != key) || (key == "" && wire.Generation == 0) || !validReleaseSpec(wire.Manifest.ReleaseSpec) || wire.Manifest.ConfigRevision != wire.Config.ConfigRevision || !maps.Equal(wire.Manifest.VaultRevisions, wire.Config.VaultRevisions) || wire.Manifest.VaultRevisions == nil || !validRevisions(wire.Manifest.VaultRevisions) || (wire.Config.Format != "yaml" && wire.Config.Format != "json") || !validReleaseDigest(wire.Digest) || !validETag(response.Header.Get("ETag")) || len(wire.Files) != len(wire.Manifest.Files) {
		return ReleaseBundle{}, invalid
	}
	size := int64(len(wire.Config.Content))
	seen := map[string]bool{}
	for i, file := range wire.Files {
		ref := wire.Manifest.Files[i]
		if seen[file.Path] || file.Path != ref.Path || ref.Revision != wire.Manifest.VaultRevisions[ref.Namespace+"."+ref.Item] {
			return ReleaseBundle{}, invalid
		}
		seen[file.Path] = true
		size += int64(len(file.Bytes))
	}
	if size > client.contentLimit {
		return ReleaseBundle{}, invalid
	}
	return ReleaseBundle{Manifest: wire.Manifest, Generation: wire.Generation, Digest: wire.Digest, Config: ResolvedConfig{Format: wire.Config.Format, Content: wire.Config.Content, ConfigRevision: wire.Config.ConfigRevision, VaultRevisions: wire.Config.VaultRevisions, ETag: response.Header.Get("ETag")}, Files: wire.Files, ETag: response.Header.Get("ETag")}, nil
}

func validReleaseResult(result ReleaseResult, key string) bool {
	return (result.Outcome == "success" || result.Outcome == "no_change") && result.ReleaseKey == key && validReleaseDigest(result.Digest)
}
func validReleaseDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 64 && value == strings.ToLower(value)
}
func validReleaseSpec(spec ReleaseSpec) bool {
	if spec.ConfigRevision == 0 || !ValidReleasePath(spec.ConfigPath) || len(spec.Files) > 31 {
		return false
	}
	paths := []string{spec.ConfigPath}
	for _, file := range spec.Files {
		if !validResourceKey(file.Namespace) || !validResourceKey(file.Item) || !validResourceKey(file.Field) || file.Revision == 0 || !ValidReleasePath(file.Path) {
			return false
		}
		for _, existing := range paths {
			if file.Path == existing || strings.HasPrefix(file.Path, existing+"/") || strings.HasPrefix(existing, file.Path+"/") {
				return false
			}
		}
		paths = append(paths, file.Path)
	}
	return true
}

// ValidReleasePath rejects absolute, noncanonical, and platform-ambiguous paths.
// Exporters must also create a new private directory and reject existing links.
func ValidReleasePath(value string) bool {
	if value == "" || len(value) > 255 || path.IsAbs(value) || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\:\x00\r\n") {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

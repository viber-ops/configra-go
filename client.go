package configra

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxContentBytes = 5 << 20
	maxErrorBytes   = 64 << 10
)

// ErrNotModified means the server accepted the supplied ETag and returned HTTP 304.
var ErrNotModified = errors.New("Configra content not modified")

// ClientOptions configures a Configra machine-read client.
type ClientOptions struct {
	BaseURL   string
	Token     string
	TLSConfig *tls.Config
	Timeout   time.Duration
	// MaxContentBytes optionally lowers the protocol's 5 MiB content limit.
	MaxContentBytes int64
}

// Client reads resolved configuration and File fields from the Configra V1 API.
type Client struct {
	baseURL      *url.URL
	token        string
	http         *http.Client
	contentLimit int64
}

// ResolvedConfig is a final YAML or JSON document plus the revisions used to build it.
type ResolvedConfig struct {
	Format         string
	Content        string
	ConfigRevision uint64
	VaultRevisions map[string]uint64
	ETag           string
}

// File is the exact content and metadata of a Configra File field.
type File struct {
	Bytes       []byte
	Filename    string
	ContentType string
	ETag        string
}

// APIError is a value-free error envelope returned by the Configra API.
type APIError struct {
	StatusCode int
	Code       string
	RequestID  string
}

func (err *APIError) Error() string {
	if err.RequestID == "" {
		return fmt.Sprintf("Configra API returned HTTP %d (%s)", err.StatusCode, err.Code)
	}
	return fmt.Sprintf("Configra API returned HTTP %d (%s), request %s", err.StatusCode, err.Code, err.RequestID)
}

// NewClient validates options and creates an HTTPS-only Configra client.
func NewClient(options ClientOptions) (*Client, error) {
	baseURL, err := url.Parse(options.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		(baseURL.Path != "" && baseURL.Path != "/") || baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.Opaque != "" {
		return nil, errors.New("Configra Base URL must be one HTTPS origin")
	}
	if !validToken(options.Token) {
		return nil, errors.New("Configra API Token is invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.TLSConfig != nil {
		if options.TLSConfig.InsecureSkipVerify {
			return nil, errors.New("Configra TLS verification cannot be disabled")
		}
		tlsConfig = options.TLSConfig.Clone()
		if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS12 {
			return nil, errors.New("Configra TLS requires TLS 1.2 or newer")
		}
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	timeout := options.Timeout
	if timeout < 0 {
		return nil, errors.New("Configra HTTP Timeout cannot be negative")
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	contentLimit := options.MaxContentBytes
	if contentLimit == 0 {
		contentLimit = maxContentBytes
	}
	if contentLimit < 1 || contentLimit > maxContentBytes {
		return nil, errors.New("Configra content limit must be between 1 byte and 5 MiB")
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	baseURL.Path = ""
	return &Client{
		baseURL:      baseURL,
		token:        options.Token,
		contentLimit: contentLimit,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// CloseIdleConnections forces future requests to establish a new TLS connection.
// Call it after updating the certificate returned by TLSConfig.GetClientCertificate.
func (client *Client) CloseIdleConnections() {
	if client != nil {
		client.http.CloseIdleConnections()
	}
}

// ReadResolvedConfig reads the final document for one Config in one Environment.
func (client *Client) ReadResolvedConfig(ctx context.Context, environment, config, etag string) (ResolvedConfig, error) {
	if client == nil || ctx == nil {
		return ResolvedConfig{}, errors.New("Configra Client and Context are required")
	}
	if !validResourceKey(environment) || !validResourceKey(config) {
		return ResolvedConfig{}, errors.New("invalid Configra Resource Key")
	}
	response, err := client.get(ctx, "/v1/environments/"+environment+"/configs/"+config, etag)
	if err != nil {
		return ResolvedConfig{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return ResolvedConfig{}, ErrNotModified
	}
	if response.StatusCode != http.StatusOK {
		return ResolvedConfig{}, decodeAPIError(response)
	}
	payload, err := readLimited(response.Body, max(64<<10, 8*client.contentLimit))
	if err != nil {
		return ResolvedConfig{}, errors.New("invalid Configra Resolved Config response")
	}
	var envelope struct {
		Format         string            `json:"format"`
		Content        string            `json:"content"`
		ConfigRevision uint64            `json:"config_revision"`
		VaultRevisions map[string]uint64 `json:"vault_revisions"`
	}
	if err := decodeOneJSON(payload, &envelope); err != nil ||
		(envelope.Format != "yaml" && envelope.Format != "json") || int64(len(envelope.Content)) > client.contentLimit ||
		envelope.ConfigRevision == 0 || envelope.VaultRevisions == nil || !validRevisions(envelope.VaultRevisions) ||
		!validETag(response.Header.Get("ETag")) {
		return ResolvedConfig{}, errors.New("invalid Configra Resolved Config response")
	}
	return ResolvedConfig{
		Format:         envelope.Format,
		Content:        envelope.Content,
		ConfigRevision: envelope.ConfigRevision,
		VaultRevisions: maps.Clone(envelope.VaultRevisions),
		ETag:           response.Header.Get("ETag"),
	}, nil
}

// ReadFile reads one namespaced Vault File field in an Environment.
func (client *Client) ReadFile(ctx context.Context, environment, namespace, item, field, etag string) (File, error) {
	if client == nil || ctx == nil {
		return File{}, errors.New("Configra Client and Context are required")
	}
	if !validResourceKey(environment) || !validResourceKey(namespace) || !validResourceKey(item) || !validResourceKey(field) {
		return File{}, errors.New("invalid Configra Resource Key")
	}
	response, err := client.get(ctx, "/v1/environments/"+environment+"/vault-items/"+namespace+"/"+item+"/fields/"+field+"/content", etag)
	if err != nil {
		return File{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return File{}, ErrNotModified
	}
	if response.StatusCode != http.StatusOK {
		return File{}, decodeAPIError(response)
	}
	content, err := readLimited(response.Body, client.contentLimit)
	if err != nil || !validETag(response.Header.Get("ETag")) {
		return File{}, errors.New("invalid Configra File response")
	}
	disposition, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || !validFilename(parameters["filename"]) {
		return File{}, errors.New("invalid Configra File response")
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType == "" {
		return File{}, errors.New("invalid Configra File response")
	}
	return File{
		Bytes:       content,
		Filename:    parameters["filename"],
		ContentType: contentType,
		ETag:        response.Header.Get("ETag"),
	}, nil
}

func (client *Client) get(ctx context.Context, path, etag string) (*http.Response, error) {
	if etag != "" && !validETag(etag) {
		return nil, errors.New("invalid Configra ETag")
	}
	endpoint := *client.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("create Configra request")
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Configra request failed: %w", err)
	}
	return response, nil
}

func decodeAPIError(response *http.Response) error {
	payload, err := readLimited(response.Body, maxErrorBytes)
	if err != nil {
		return &APIError{StatusCode: response.StatusCode, Code: "unexpected_response"}
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if decodeOneJSON(payload, &envelope) != nil || !validErrorCode(envelope.Error.Code) || !validRequestID(envelope.Error.RequestID) {
		return &APIError{StatusCode: response.StatusCode, Code: "unexpected_response"}
	}
	return &APIError{StatusCode: response.StatusCode, Code: envelope.Error.Code, RequestID: envelope.Error.RequestID}
}

func decodeOneJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return nil, errors.New("response exceeds limit")
	}
	return payload, nil
}

func validToken(token string) bool {
	if len(token) > 512 || strings.ContainsAny(token, " \t\r\n") || !strings.HasPrefix(token, "cfg_") {
		return false
	}
	publicID, encodedSecret, found := strings.Cut(strings.TrimPrefix(token, "cfg_"), "_")
	if !found || len(publicID) < 6 || len(publicID) > 64 || encodedSecret == "" || strings.Contains(encodedSecret, "=") {
		return false
	}
	for _, character := range publicID {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	return err == nil && len(secret) == 32 && base64.RawURLEncoding.EncodeToString(secret) == encodedSecret
}

func validResourceKey(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validRevisions(revisions map[string]uint64) bool {
	for key, revision := range revisions {
		parts := strings.Split(key, ".")
		if len(parts) != 2 || !validResourceKey(parts[0]) || !validResourceKey(parts[1]) || revision == 0 {
			return false
		}
	}
	return true
}

func validETag(value string) bool {
	return len(value) >= 2 && len(value) <= 1024 && !strings.ContainsAny(value, "\x00\r\n")
}

func validFilename(value string) bool {
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, "\x00\r\n")
}

func validErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validRequestID(value string) bool {
	if len(value) != 24 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

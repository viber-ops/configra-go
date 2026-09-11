# configra-go

**Read Configra configuration from Go, without writing your own TLS setup.**

[Configra](https://viber-ops.github.io/configra/) ·
[SDK guide](https://viber-ops.github.io/docs/configra/go-sdk/) ·
[Service repository](https://github.com/viber-ops/configra) · [中文](README.zh-CN.md)

Use this SDK when a Go application needs resolved YAML/JSON, Vault file bytes,
or a periodically refreshed Viper snapshot. The service resolves sensitive-value
references before returning configuration; the client does not need to resolve them.

> **Preview: v0.1.0-rc.1.** Install the tag below for these initialization helpers;
> the feature PR remains under review. Go 1.25.13+ is required.

```sh
go get github.com/viber-ops/configra-go@v0.1.0-rc.1
```

## Start with your deployment's settings

```go
client, err := configra.NewClientFromEnv()
if err != nil {
    return err
}
defer client.CloseIdleConnections()

result, err := client.ReadResolvedConfig(ctx, "production", "payment", "")
if err != nil {
    return err
}
// Parse result.Content into your application model. Do not log secret-bearing content.
```

Import `github.com/viber-ops/configra-go`; `ctx` is your application's context.
The SDK handles certificate loading, HTTPS verification, timeouts and connection
pooling. [Complete runnable example](https://github.com/viber-ops/configra-go/blob/v0.1.0-rc.1/examples/basic/main.go).

Your deployment provides `CONFIGRA_URL` and either `CONFIGRA_TOKEN` or
`CONFIGRA_TOKEN_FILE`. For mTLS, provide `CONFIGRA_CLIENT_CERT` and
`CONFIGRA_CLIENT_KEY`; omit the key path when the certificate PEM also contains
the private key. `CONFIGRA_SERVER_CA` is only needed for an internal server CA.
There is **no mandatory credential directory**.

## Three entry points, one configuration model

| Your application already uses | Initialize with |
| --- | --- |
| Container environment / Secret mounts | `configra.NewClientFromEnv()` |
| A deployment settings file | `configra.NewClientFromFile("configra.yaml")` |
| Its own config system or in-memory values | `configra.NewClient(configra.ClientOptions{...})` |

A client settings file can reference existing files without putting secrets in YAML:

```yaml
url: https://configra-api.example.internal:9443
token_file: /run/secrets/configra-token
cert_file: /run/secrets/client.crt
key_file: /run/secrets/client.key
# server_ca_file: /run/secrets/server-ca.crt # only for an internal server CA
```

File paths can be anywhere; relative paths resolve next to the YAML file.
The file loader rejects unknown keys and multiple documents. It does not silently
merge environment settings or expand shell variables. `Token` and `TokenFile`
are mutually exclusive. File-based TLS options cannot be mixed with `TLSConfig`.

For an application that already owns its settings:

```go
client, err := configra.NewClient(configra.ClientOptions{
    BaseURL:               apiURL,
    Token:                 token,
    ClientCertificateFile: "client.pem", // combined certificate + private key
})
```

The server address and Token cannot be inferred from a client certificate.
Only Tokens explicitly permitting Token-only access may omit mTLS; HTTPS server
verification is always enforced. Defaults are a 30-second request timeout and
a 5 MiB content limit. `CONFIGRA_TIMEOUT`, YAML `timeout`, or `ClientOptions.Timeout`
can customize the timeout; other advanced controls stay in `ClientOptions`.

## Files and live configuration

`ReadFile(ctx, environment, namespace, item, field, etag)` returns exact bytes.
`NewViperHandler` adds Load/Reload/Watch with ETag polling, jitter and in-memory
last-known-good snapshots. Watch is opt-in; it does not start background work
during client construction.

Cold-start failure has no old snapshot. OnChange runs **after** the SDK installs
a parsed snapshot, and callback failure does not roll it back. Validate and
atomically replace your own application state. See the
[Viper guide](https://viber-ops.github.io/docs/configra/go-sdk/#viper-快照与热更新).

Credential files are loaded once. Rebuild the client to adopt new files, or use
the advanced `TLSConfig.GetClientCertificate` callback for live rotation and call
`CloseIdleConnections()` after replacing the identity. The SDK has its own HTTP
transport, independent of `http.DefaultTransport`.

## Verify

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Configra's service and Kubernetes integration suites additionally exercise the
machine-read protocol over HTTPS/mTLS. Permissions remain Environment-wide;
the SDK does not add resource-level authorization.

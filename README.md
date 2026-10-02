# configra-go

Development additions: `ViperHandlerOptions.Validate` checks a candidate before
Load/Reload installs it. Rejection returns value-free `ErrSnapshotRejected`, keeps
the previous Snapshot/ETag and skips OnChange. The validator must be side-effect-free,
respect cancellation and must not reenter the Handler. `Status()` reports the
last completed check, accepted/unchanged fetch and consecutive failures; it does
not attest application callback success. `ReadIdentity` and the scoped writer's
`ListDeploymentCredentials` expose value-free lifecycle metadata and require the
corresponding new server endpoints. `APIError.RetryAfter` exposes bounded numeric
retry hints; mutations are not automatically retried with a different identity.

**Read Configra configuration and automate scoped writes from Go.**

[Configra](https://viber-ops.github.io/en/configra/) ·
[SDK guide](https://viber-ops.github.io/en/docs/configra/go-sdk/) ·
[Service repository](https://github.com/viber-ops/configra) · [中文](README.zh-CN.md)

Use this SDK when a Go application needs resolved YAML/JSON, Vault file bytes,
or a periodically refreshed Viper snapshot. The service resolves sensitive-value
references before returning configuration; the client does not need to resolve them.

> **Stable release: v1.1.0.** Requires Go 1.25.13+.
> Configuration reloads remain application-controlled; handle errors and validate new snapshots before applying them.

```sh
go get github.com/viber-ops/configra-go@v1.1.0
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
pooling. [Complete runnable example](https://github.com/viber-ops/configra-go/blob/v1.1.0/examples/basic/main.go).

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
[Viper guide](https://viber-ops.github.io/en/docs/configra/go-sdk/#viper-snapshots-and-live-updates).

Credential files are loaded once. Rebuild the client to adopt new files, or use
the advanced `TLSConfig.GetClientCertificate` callback for live rotation and call
`CloseIdleConnections()` after replacing the identity. The SDK has its own HTTP
transport, independent of `http.DefaultTransport`.
Closing idle connections does not interrupt active requests or guarantee an
immediate identity change on a busy HTTP/2 connection. For a strict cutover,
stop old callers and switch to a new client. Token changes also require a new client.

## Verify

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Configra's service and Kubernetes integration suites additionally exercise the
machine-read protocol over HTTPS/mTLS. Permissions remain Environment-wide;
the SDK does not add resource-level authorization.

## License

Original project source is licensed under [Apache-2.0](LICENSE). Third-party
components retain their own licenses and notices. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md) for contributions and private vulnerability reports.

## Scoped writes (server v1.1.0+)

Keep read-only credentials on deployed hosts and a separately issued
`write-scoped` Token plus registered mTLS certificate on the operator. A verified
OIDC/MFA Administrator issues the writer; automation does not receive a human
session or any CA/Master signing key. [Model, issuance and boundaries](https://github.com/viber-ops/configra/blob/feat/scoped-write-tokens/docs/scoped-write-tokens.md).

```go
result, err := client.WriteConfig(ctx, "testing", "server", configra.ConfigWrite{
    RevisionWrite: configra.RevisionWrite{OperationID: "upload-server-001", ExpectedRevision: 0},
    Name: "server.yaml", Format: "yaml", Content: "port: 8080\n",
})
```

Use a new OperationID for new content; reuse it for identical retries only.
`ExpectedRevision` is zero for creation and the current revision for updates.
HTTP 403 means a scope denial, 401 an inactive/missing credential, and 409 a
revision or OperationID conflict; `APIError` contains only a safe code/Request ID.
No method automatically logs Config, Vault values or credential exports.

| Method | Purpose |
| --- | --- |
| `WriteConfig`, `ReadRawConfig` | Commit a version and read its current raw source/revision |
| `WriteVaultItem`, `ReadVaultItem` | Replace/read one Environment's complete Item values |
| `WriteVaultField`, `WriteFile` | Create/update Text/Secret or File fields |
| `DeleteVaultField`, `DeleteVaultItem` | Remove a shared Field or archive an Item, retaining history |
| `IssueDeploymentCredential`, `RevokeDeploymentCredential` | Atomically issue/revoke a read-only Token and bound certificate |

Item/Field schema changes require grants for all bound Environments. File bytes
use JSON/base64 and remain limited to 5 MiB each and 10 MiB per Vault snapshot.
Deployment credentials inherit Config/Namespace restrictions; their expiry cannot
outlive the writer/CA, and writer revocation cascades to its deployment pairs.
Issuance returns the Token and base64 certificate ZIP once; retries return only
metadata. Save exports privately, with Token/key files at `0600`.

The [operator example](examples/operator/main.go) uploads server YAML and a complete
set of secret files (`file_01` through `file_17` for 17 arguments). Supply files in
a stable order; it reads revisions before writing and saves a new deployment pair:

```sh
export CONFIGRA_URL=https://configra-api.example.internal:9443
export CONFIGRA_TOKEN_FILE=/run/secrets/operator-token
export CONFIGRA_CLIENT_CERT=/run/secrets/operator.crt
export CONFIGRA_CLIENT_KEY=/run/secrets/operator.key
export CONFIGRA_SERVER_CA=/run/secrets/server-ca.crt
export CONFIGRA_DEPLOYMENT_CA_ID=YOUR_PUBLIC_MANAGED_CA_ID
go run ./examples/operator -environment testing -namespace deployment \
  -authority "$CONFIGRA_DEPLOYMENT_CA_ID" -config server.yaml \
  -output deployment-identity secrets/*.key
```

The example uses Config key `server`, Vault Item `deployment/secrets`, a 24-hour
host credential (the writer must have at least that much lifetime remaining),
and a new private output directory. `token` and `client.zip` are mode `0600`.
Unzip privately; `ca.crt` is client-issuer trust, not necessarily the HTTPS server
CA. Existing read methods and Viper handlers remain compatible with older servers.
The Configra repository's `make test-integration` runs this example over real
HTTPS/mTLS with MySQL 8.0.22, NATS and ClickHouse.

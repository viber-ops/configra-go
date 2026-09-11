# configra-go

`configra-go` is the Configra V1 Go client. It reads the final Resolved Config or exact
File bytes over HTTPS and keeps Viper snapshots in process memory only.

Install the V1 module with Go 1.25.13 or newer:

```sh
go get github.com/viber-ops/configra-go@latest
```

If the repository is private, authenticate Git with GitHub and add
`github.com/viber-ops/*` to your existing `GOPRIVATE` patterns before installing.

Vault Items are addressed by their immutable `(namespace, item)` identity. Config
references use `{vault.<namespace>.<item>.<field>}`; the client intentionally has no
legacy three-segment or implicit-default Namespace mode.

Put references in the Config document managed by Configra, not in the application's
local cold-start YAML. A reference must occupy the complete YAML/JSON scalar and inherits
the Config's Environment:

```yaml
database:
  username: "{vault.platform.mysql.username}"
  password: "{vault.platform.mysql.password}"
```

Text and Secret Fields resolve to their current values before the client receives the
document. V1 does not support historical `@vN` references or interpolation inside a
larger string. File Fields are read separately with `ReadFile`.

```go
client, err := configra.NewClient(configra.ClientOptions{
    BaseURL:   "https://configra-api.example.internal:9443",
    Token:     os.Getenv("CONFIGRA_TOKEN"),
    TLSConfig: tlsConfig, // cloned by the client
})
if err != nil {
    return err
}

var applicationConfig atomic.Pointer[ApplicationConfig]
apply := func(snapshot *configra.Snapshot) error {
    next := new(ApplicationConfig)
    if err := snapshot.Unmarshal(next); err != nil {
        return err
    }
    applicationConfig.Store(next)
    return nil
}

handler, err := configra.NewViperHandler(configra.ViperHandlerOptions{
    Client:      client,
    Environment: "production",
    Config:      "payment",
    OnChange: func(ctx context.Context, previous, current *configra.Snapshot) error {
        return apply(current)
    },
    OnError: func(err error) {
        logger.Warn("Configra reload failed", zap.Error(err))
    },
})
if err != nil {
    return err
}

snapshot, err := handler.Load(ctx)
if err != nil { // cold start has no Last-known-good and must fail
    return err
}
if err := apply(snapshot); err != nil {
    return err
}
go func() { _ = handler.Watch(ctx) }()

file, err := client.ReadFile(ctx, "production", "platform", "mysql", "tls_cert", "")
```

For mTLS, set `tls.Config.GetClientCertificate`; the client clones and preserves that
callback so the application can rotate certificates at runtime. After atomically replacing
the certificate returned by the callback, call `client.CloseIdleConnections()` so the next
request performs a new TLS handshake. An API Token that allows Token-only Authentication
may omit a client certificate, but HTTPS server verification is always required.

The client owns its HTTP transport and is unaffected by applications replacing
`http.DefaultTransport`. `ClientOptions.MaxContentBytes` can lower the default
5 MiB Config/File limit for constrained consumers such as Kubernetes providers;
the client also bounds the JSON envelope while reading the response.

`Load` installs the initial snapshot without a callback. `Reload` and `Watch` send the
current ETag, retain the Last-known-good after fetch or parse failure, install changed
snapshots atomically, and then invoke `OnChange` serially. Callback failure does not roll
back an installed snapshot. `Watch` defaults to 30 seconds with jitter, rejects intervals
below 5 seconds, and backs repeated failures off to at most 5 minutes. An unchanged Reload
may complete while a callback is running; a changed overlapping Reload returns
`ErrReloadRunning` without installing another snapshot, so callbacks never overlap.

## Verify

```sh
go test -race -count=1 ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

The Configra service repository additionally exercises this module against the
production scratch image over real HTTPS/mTLS, MySQL 8.0.22, NATS, and ClickHouse.

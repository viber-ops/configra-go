# Contributing to configra-go

Describe the application scenario before adding an initialization option or new
interface. The common path should stay short; advanced settings must not change
defaults silently. All initialization paths share the same validation rules.

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

Add regression tests through exported interfaces. Use real local HTTPS/mTLS
fixtures for transport changes, check error redaction, and preserve cancellation,
ETag and snapshot semantics. Authentication must not fall back silently.

Update both README languages and the website's SDK guide. Compile and execute
examples against a disposable fixture; do not use live credentials in tests or
reports. Format changed Go files with `gofmt` and run `git diff --check`.

Only contribute work you can publish. Original contributions are licensed under
[Apache-2.0](LICENSE); preserve third-party notices. Be respectful, do not publish
private information, and report vulnerabilities through [SECURITY.md](SECURITY.md).

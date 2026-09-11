# Security policy

Report SDK vulnerabilities through [GitHub private vulnerability reporting](https://github.com/viber-ops/configra-go/security/advisories/new).
Service-side issues belong in [Configra's private reporting channel](https://github.com/viber-ops/configra/security/advisories/new).

Include the release/commit, Go version, affected initialization/read path and a
minimal reproduction with synthetic credentials. Do not post live Tokens,
private keys or resolved configuration in public issues. If the private form is
unavailable, ask for a private contact without describing the vulnerability.

The SDK is currently in prerelease; fixes are published as new versions rather
than by rewriting tags. No fixed response or remediation SLA is promised.

HTTPS verification is mandatory. File credentials are loaded once; advanced live
rotation requires the documented callback. Last-known-good snapshots are in
memory only and do not make cold starts independent of Configra availability.
Keep business validation separate from SDK snapshot installation.

# Production readiness

This document defines the supported production scope and the release gates for
`airlock-gateway-certctl`. It is a certificate-lifecycle tool, not a complete
replacement for every function of a general-purpose appliance SDK.

## Supported scope

- Airlock Gateway 8.x; the implementation and live contract tests were
  validated with Airlock Gateway 8.6.0.
- Typed SSL certificate CRUD and typed relationships for Virtual Hosts,
  Back-end Groups, remote JSON Web Key Sets, and Nodes.
- Atomic certificate/key synchronization, including leaf-only and key-only
  updates, configuration validation, activation, and session cleanup.
- Stable Virtual Host name targeting for the normal managed workflow.

Managed mutations fail before opening a configuration session when the target
does not report an Airlock Gateway 8.x version. `VerifyGatewayVersion` and the
CLI command `verify-version` expose the same preflight explicitly. Untyped
operations through `Client.Raw()` are outside this compatibility guarantee.

## Safety guarantees

- Certificate and private-key PEM, X.509 structure, key matching, chains,
  passphrases, identifiers, certificate types, and policies are validated
  locally.
- The safe default rejects an outdated appliance working copy. Merge and
  overwrite behavior require an explicit policy.
- Each configuration transaction has an independent REST session and cookie
  jar. Changes become active only after appliance validation succeeds.
- Secret fields are excluded from typed JSON serialization and CLI output is
  redacted unless `--show-secrets` is explicitly selected.
- Error strings omit raw appliance response bodies. Structured diagnostic
  fields remain available to callers that deliberately inspect them.
- Release binaries identify their embedded semantic version in the User-Agent;
  local builds report `dev`.

## Mandatory release gates

Run these gates on the exact commit to be tagged:

```bash
test -z "$(gofmt -l .)"
go mod tidy
git diff --exit-code -- go.mod go.sum
go vet ./...
go test -race ./...
go test -coverprofile=coverage.out ./...
go build ./cmd/airlock-certctl
govulncheck ./...
```

The live test suite must also pass against a disposable Airlock Gateway 8.x
test configuration:

```bash
AIRLOCK_LIVE_TEST=1 \
AIRLOCK_HOST=gateway.example.com \
AIRLOCK_API_KEY='...' \
go test ./pkg/airlock -run Live -v
```

The live gates cover the appliance OpenAPI contract for the target 8.x release,
certificate lifecycle, independent concurrent sessions, frontend TLS
presentation, and restoration of the original configuration. A production
rollout additionally requires a trusted management CA, a least-privilege API
key, customer-specific topology and HA/failover acceptance, backup/restore
validation, and protected handling of certificate keys and passphrases.

## Release integrity

An existing tag must never be moved. Before publishing a release, verify that
the semantic tag resolves to the intended commit, CI is green for that commit,
and the generated archive checksums are retained with the release.

At the time this document was added, `main` contained commits after `v0.0.4`.
Those changes therefore require a new semantic version; they are not part of
the immutable `v0.0.4` tag.

## Known boundaries

- Compatibility is asserted for Airlock Gateway 8.x and tested with 8.6.0.
  The API is expected to remain compatible within major version 8; a new major
  version requires a fresh OpenAPI and live lifecycle qualification before
  support is claimed.
- Encrypted private-key updates require the caller to supply the relevant
  passphrase because the Gateway exposes it as write-only.
- `OverwriteConcurrentChanges` can replace another operator's changes and is
  suitable only for deliberately serialized operational workflows.
- The generic raw client is an escape hatch and has no typed schema or
  production compatibility promise.

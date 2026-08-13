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
- Mutex-serialized creation and activation of unbound certificate resources
  before a Virtual Host exists.
- Stable Virtual Host name targeting for the normal managed workflow.
- A facade vocabulary aligned with the designated `gateway-rest-api-lib`
  foundation (`GatewayVersion`, `APIError`, `VersionSkewError`, and explicit
  managed-certificate/configuration method names).

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
presentation, concurrent unbound managed creation, and restoration of the
original configuration. A production rollout additionally requires a trusted
management CA, a least-privilege API key, customer-specific topology and
HA/failover acceptance, backup/restore validation, and protected handling of
certificate keys and passphrases.

## Release integrity

An existing tag must never be moved. Before publishing a release, verify that
the semantic tag resolves to the intended commit, CI is green for that commit,
and the generated archive checksums are retained with the release.

The production hardening baseline is released as `v0.0.5`. Later changes must
be published under a newer semantic version and must not move the immutable
`v0.0.5` tag.

## Known boundaries

- `gateway-rest-api-lib` is not yet imported directly because its current
  workspace copy uses a placeholder module path and a newer Go toolchain
  baseline. The stable certctl facade is the migration boundary; replacing its
  internal transport requires the same unit, OpenAPI, and live lifecycle gates.
- Compatibility is asserted for Airlock Gateway 8.x and tested with 8.6.0.
  The API is expected to remain compatible within major version 8; a new major
  version requires a fresh OpenAPI and live lifecycle qualification before
  support is claimed.
- Configuration Center displays non-editable comment metadata on the built-in
  `test.certificate`, but provides no certificate-comment feature for normal
  customer-created objects. Gateway 8.6 also does not expose that metadata on
  the public REST v3 `SSLCertificateDto`. The library records audit descriptions
  as configuration activation comments instead.
- Encrypted private-key updates require the caller to supply the relevant
  passphrase because the Gateway exposes it as write-only.
- `OverwriteConcurrentChanges` can replace another operator's changes and is
  suitable only for deliberately serialized operational workflows.
- The generic raw client is an escape hatch and has no typed schema or
  production compatibility promise.

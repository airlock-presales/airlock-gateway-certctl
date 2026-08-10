# airlock-gateway-certctl

A typed Go library and administrative CLI for Airlock Gateway SSL certificate
lifecycle management.

The library validates certificates, private keys, chains, passphrases, targets,
and activation policies locally. Certificate and key material is
checksum-compared and written in one appliance configuration transaction.

## Scope and compatibility

- Supports Airlock Gateway 8.x.
- Implemented and live-tested with Airlock Gateway 8.6.0.
- Provides typed SSL certificate CRUD and typed relationships.
- Supports atomic pair, leaf-only, and key-only synchronization.
- Addresses normal managed workflows by stable Virtual Host name instead of
  appliance resource IDs.
- Rejects unsupported major versions before opening a mutation session.
- Keeps untyped transport behind the explicit `client.Raw()` escape hatch.

This project manages certificate lifecycles. It is not a general-purpose SDK
for every Airlock Gateway resource. See
[Production readiness](PRODUCTION_READINESS.md) for the exact delivery scope,
release gates, and known boundaries.

## Install

Library:

```bash
go get github.com/airlock-presales/airlock-gateway-certctl@latest
```

CLI:

```bash
go install github.com/airlock-presales/airlock-gateway-certctl/cmd/airlock-certctl@latest
```

Release archives contain the CLI for Linux, macOS, and Windows together with
documentation and checksums. `airlock-certctl build-info` prints the embedded
release version; a local unversioned build prints `dev`.

## Go quickstart

The normal integration selects a certificate through its Virtual Host name:

```go
certificatePEM, err := os.ReadFile("fullchain.pem")
if err != nil {
    log.Fatal(err)
}
privateKeyPEM, err := os.ReadFile("privkey.pem")
if err != nil {
    log.Fatal(err)
}

bundle, err := airlock.ParseCertificateBundle(airlock.CertificateBundleInput{
    Type:           airlock.ServerCertificate,
    CertificatePEM: certificatePEM,
    PrivateKeyPEM:  privateKeyPEM,
})
if err != nil {
    log.Fatal(err)
}

client, err := airlock.New(airlock.Config{
    Address:            "gateway.example.com",
    APIKey:             os.Getenv("AIRLOCK_API_KEY"),
    TrustedCertificate: "/etc/pki/airlock-management-ca.pem",
})
if err != nil {
    log.Fatal(err)
}

result, err := client.SyncCertificate(
    context.Background(),
    airlock.ForVirtualHost("www"),
    bundle,
    airlock.SyncOptions{ActivationComment: "Rotate www certificate"},
)
if err != nil {
    log.Fatal(err)
}

log.Printf("changed=%t certificate=%s bundle=%s",
    result.Changed, result.Certificate.ID, result.Certificate.Checksum)
```

`SyncCertificate` validates the material, verifies Gateway 8.x compatibility,
opens an independent configuration session, resolves the Virtual Host,
compares canonical checksums, applies the change, validates and activates it,
and terminates the session. The safe default rejects concurrent appliance
changes.

See the [Go API reference](docs/API.md) for typed CRUD, transaction behavior,
encrypted keys, error classification, and raw API access.

## CLI quickstart

```bash
export AIRLOCK_HOST=gateway.example.com
export AIRLOCK_API_KEY='...'

airlock-certctl verify-version
airlock-certctl list

airlock-certctl attrs-from-pem \
  --cert fullchain.pem \
  --key privkey.pem \
  --out cert-attrs.json

airlock-certctl update \
  --id 17 \
  --attrs cert-attrs.json \
  --activate \
  --activate-comment "Rotate www certificate"
```

Global flags such as `--host` and `--api-key` may be used instead of the
environment. Sensitive output fields are redacted unless `--show-secrets` is
explicitly selected.

See the [CLI reference](docs/CLI.md) for commands, flags, attribute input,
configuration sessions, and output safety. Operational replacement procedures
are documented in the [certificate rotation runbook](docs/CERTIFICATE_ROTATION.md).

## Build and test

```bash
go build ./cmd/airlock-certctl
go test ./...
```

The release gates additionally run formatting checks, module drift detection,
`go vet`, the race detector, coverage, `govulncheck`, release builds, and live
Gateway contract and lifecycle tests.

See [Development and releases](docs/DEVELOPMENT.md) for local quality gates,
live-test configuration, GitHub automation, Code Security, and tag-based
publishing.

## Documentation

| Document | Purpose |
| --- | --- |
| [Go API reference](docs/API.md) | Typed API, synchronization semantics, errors, raw access, and endpoints |
| [CLI reference](docs/CLI.md) | Commands, connection settings, input format, sessions, and secret handling |
| [Certificate rotation](docs/CERTIFICATE_ROTATION.md) | In-place, atomic replacement, manual procedures, verification, and rollback |
| [Development and releases](docs/DEVELOPMENT.md) | Tests, live validation, automation, vulnerability scanning, and releases |
| [Production readiness](PRODUCTION_READINESS.md) | Supported production scope, mandatory gates, and known boundaries |
| [Changelog](CHANGELOG.md) | Released and unreleased changes |

The Gateway publishes its authoritative OpenAPI schema at
`/airlock/rest/v3/api-docs` and `/airlock/rest/v3/api-docs.yaml`. Download the
target schema with:

```bash
airlock-certctl schema --format yaml --out airlock-openapi.yaml
```

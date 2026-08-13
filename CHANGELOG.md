# Changelog

## v0.0.10 - 2026-08-13

### Fixed

- Corrected the certificate-comment documentation after verification against
  Configuration Center: comments are editable in the GUI, but the GUI writes
  them through an internal JSF form rather than the public REST v3 certificate
  resource. The API-key-based library therefore does not claim support for
  setting them through the supported REST contract.

## v0.0.9 - 2026-08-13

### Added

- Mutex-serialized `Client.CreateManagedCertificate` and
  `ConfigurationTransaction.CreateManagedCertificate` operations for safely
  creating and activating unbound certificate objects before a Virtual Host
  exists.
- Unit coverage for transaction ownership, serialization, commit behavior, and
  failure cleanup, plus a live parallel-producer lifecycle test on Airlock
  Gateway 8.6.0.

### Changed

- Documented the certificate-comment behavior known at release time. This was
  clarified after release; see `v0.0.10`.

## v0.0.8 - 2026-08-11

### Changed

- Aligned the public facade with the designated `gateway-rest-api-lib`
  foundation: `GatewayVersion`, `ValidateConfiguration`,
  `GetManagedCertificate`, `SetVirtualHostCertificate`, `APIError`, and
  `VersionSkewError` now describe their semantics explicitly.
- Aligned `VersionSkewError.ClientVersion` and `ErrorData` with the diagnostic
  vocabulary of the foundation library.

### Removed

- Removed the ambiguous pre-v1 names `Version`, `Validate`, `GetCertificate`,
  `AddVirtualHostCertificateRelationship`, `Error`, `GatewayVersionError`, and
  the non-foundation `APIErrorBody` name. This was an intentional pre-v1
  breaking API cleanup.

## v0.0.7 - 2026-08-11

### Added

- Expanded the Go library reference with configuration parameters, certificate
  properties, return values, and the origin of Gateway resource IDs.
- Added the X.509 serial number to typed certificate metadata and documented
  every exported certificate property.
- Added a package example demonstrating the managed `SyncCertificate` flow.

### Changed

- Expanded exported Go documentation for client configuration, certificate
  bundles, managed results, identifiers, and certificate metadata.

## v0.0.6 - 2026-08-10

### Changed

- Split the long README into a concise project overview and focused API, CLI,
  certificate-rotation, development, and release documentation under `docs/`.
- Included the documentation directory in release archives.
- Updated the production-readiness status for the immutable `v0.0.5`
  baseline.

## v0.0.5 - 2026-08-10

### Added

- Fully typed SSL certificate CRUD resources, attributes, IDs, filters, and
  relationship targets.
- Explicit `Client.Raw()` transport for endpoints outside the typed release
  contract.
- Idiomatic `errors.Is` support for authentication, not-found, and conflict
  responses.
- Gateway 8.x version verification through `VerifyGatewayVersion`.
- A production-readiness contract with explicit supported scope, release
  gates, operational acceptance criteria, and known boundaries.
- A credential-free `build-info` CLI command and semantic build-version
  injection for release binaries.
- A `verify-version` CLI command for explicit compatibility preflight.

### Changed

- Managed library transactions and all mutating CLI commands now reject an
  unsupported Gateway version before opening a configuration session.
- Unsupported versions can be classified with
  `errors.Is(err, airlock.ErrUnsupportedGatewayVersion)`.
- The default User-Agent now contains the embedded release version instead of
  a hard-coded development version.
- PATCH attributes distinguish omitted fields from explicit empty values.
- The remote-JWKS relationship uses the authoritative Airlock 8.6 path
  `json-web-key-sets/remotes`.
- Error strings no longer include raw appliance bodies.
- Error strings no longer include server-provided error titles, which may echo
  submitted secret values; typed diagnostic fields remain available explicitly.

### Fixed

- Release documentation no longer claims that post-tag `main` changes are
  contained in the immutable `v0.0.4` tag.

### Removed

- Direct `Client.DoJSON` and `Client.DoRaw`; use `Client.Raw()` for deliberate
  untyped access.
- Map-based certificate CRUD and free-form relationship names.

## v0.0.4 - 2026-08-10

### Added

- Typed Airlock certificate, key, bundle, target, result, and activation-policy APIs.
- Virtual-Host-name addressing that hides Airlock certificate and relationship IDs.
- Local PEM, X.509, private-key, passphrase, chain, and certificate/key-pair validation.
- Canonical SHA-256 checksums for certificates, keys, and complete bundles.
- Atomic pair, leaf-only, and key-only synchronization operations.
- Independent per-transaction Airlock REST sessions for safe concurrent client use.
- Explicit reject, merge, and overwrite policies for appliance-side concurrent changes.
- Live lifecycle, concurrency, frontend TLS, restore, and OpenAPI contract tests.

### Changed

- Activation now rejects every outdated configuration by default.
- Built-in Airlock certificate resources are replaced and rebound instead of patched.
- Virtual Host certificate relationship payloads follow the Airlock 8.6 to-one schema.
- Structured Airlock error details and request metadata are exposed on `Error`.

### Removed

- The stringly typed, resource-ID-driven certificate synchronization API.

## v0.0.3 - 2026-07-14

### Added

- Transaction-based certificate synchronization with configuration validation,
  save, activation, and cleanup.
- Trusted-root-CA handling, configurable TLS/client settings, and live SSL
  certificate lifecycle tests.
- Certificate synchronization and validation unit coverage.

### Changed

- Corrected accepted certificate create/update status codes and Virtual Host
  certificate relationship paths.
- Updated the GitHub Actions checkout dependency and workflow-script
  permissions.

## v0.0.2 - 2026-05-28

### Changed

- Published an additional version tag for the initial release. `v0.0.2` points
  to the same source commit as `v0.0.1` and contains no source changes.

## v0.0.1 - 2026-05-28

### Added

- Initial Go client library and CLI for Airlock Gateway SSL certificate
  management.
- REST session and configuration lifecycle operations, certificate CRUD,
  relationship management, OpenAPI schema download, secret redaction, and PEM
  attribute generation.
- CI, security scanning, dependency updates, and release automation.

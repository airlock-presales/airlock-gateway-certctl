# Changelog

## Unreleased

### Added

- Expanded the Go library reference with configuration parameters, certificate
  properties, return values, and the origin of Gateway resource IDs.
- Added the X.509 serial number to typed certificate metadata and documented
  every exported certificate property.
- A production-readiness contract with explicit supported scope, release
  gates, operational acceptance criteria, and known boundaries.
- A credential-free `build-info` CLI command and semantic build-version
  injection for release binaries.
- A `verify-version` CLI command for explicit compatibility preflight.

### Changed

- Split the long README into a concise project overview and focused API, CLI,
  certificate-rotation, development, and release documentation under `docs/`.
- Updated the production-readiness release status after publication of the
  immutable `v0.0.5` baseline.
- Managed library transactions and all mutating CLI commands now reject an
  unsupported Gateway version before opening a configuration session.
- Unsupported versions can be classified with
  `errors.Is(err, airlock.ErrUnsupportedGatewayVersion)`.
- The default User-Agent now contains the embedded release version instead of
  a hard-coded development version.
- Error strings no longer include server-provided error titles, which may echo
  submitted secret values; typed diagnostic fields remain available explicitly.

### Fixed

- Release documentation no longer claims that post-tag `main` changes are
  contained in the immutable `v0.0.4` tag.

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
- Fully typed SSL certificate CRUD resources, attributes, IDs, filters, and
  relationship targets.
- Explicit `Client.Raw()` transport for endpoints outside the typed release
  contract.
- Idiomatic `errors.Is` support for authentication, not-found, and conflict
  responses.
- Gateway 8.6 version verification through `VerifyGatewayVersion`.

### Changed

- Activation now rejects every outdated configuration by default.
- Built-in Airlock certificate resources are replaced and rebound instead of patched.
- Virtual Host certificate relationship payloads follow the Airlock 8.6 to-one schema.
- Structured Airlock error details and request metadata are exposed on `Error`.
- PATCH attributes distinguish omitted fields from explicit empty values.
- The remote-JWKS relationship uses the authoritative Airlock 8.6 path
  `json-web-key-sets/remotes`.
- Error strings no longer include raw appliance bodies that could echo secret
  request material.

### Removed

- The stringly typed, resource-ID-driven certificate synchronization API.
- Direct `Client.DoJSON` and `Client.DoRaw`; use `Client.Raw()` for deliberate
  untyped access.
- Map-based certificate CRUD and free-form relationship names.

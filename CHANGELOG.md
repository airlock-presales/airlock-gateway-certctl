# Changelog

## Unreleased

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

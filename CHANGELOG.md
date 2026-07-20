# Changelog

## Unreleased

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


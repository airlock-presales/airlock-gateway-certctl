# Go API reference

The public Go API provides typed certificate lifecycle operations for Airlock
Gateway 8.x. It is implemented and live-tested with Airlock Gateway 8.6.0.

## Typed API surface

The certificate lifecycle API consists of concrete domain types rather than
attribute maps:

- connection and authentication: `Config`, `New`;
- validated local material: `Certificate`, `Key`, `CertificateBundle`,
  `ParseCertificate`, `ParseKey`, `ParseEncryptedKey`, and
  `ParseCertificateBundle`;
- typed selectors: `ForVirtualHost`, `ByCertificateID`;
- typed appliance state: `ManagedCertificate`, `VirtualHost`, `SyncResult`;
- typed wire API: `SSLCertificateAttributes`, `SSLCertificateResource`,
  `CertificateID`, `VirtualHostID`, `BackEndGroupID`, `RemoteJWKSID`, `NodeID`,
  and `CertificateRelationship`;
- typed CRUD: `ListSSLCertificates`, `GetSSLCertificate`,
  `CreateSSLCertificate`, `UpdateSSLCertificate`, and `DeleteSSLCertificate`;
- lifecycle methods: `GetCertificate`, `SyncCertificate`,
  `SyncLeafCertificate`, `SyncKey`, `StartConfigurationTransaction`, `Commit`,
  `CommitWithOptions`, and `Abort`;
- concurrency policies: `RejectConcurrentChanges` (default),
  `MergeNonConflictingChanges`, and `OverwriteConcurrentChanges`.

`Certificate.Checksum`, `Key.Checksum`, and `ManagedCertificate.Checksum` are
available for audit logs and drift detection. Private-key PEM and passphrases
are not JSON-serializable fields of these types.

## Synchronization behavior

`SyncCertificate` performs the complete managed lifecycle:

1. validates the PEM objects and verifies that the private key matches the
   leaf certificate;
2. verifies that the target runs a supported Airlock Gateway 8.x release;
3. opens an independent REST session and loads the active configuration;
4. resolves the exact Virtual Host name and current certificate binding;
5. compares canonical SHA-256 checksums of DER data;
6. creates and binds a missing certificate or replaces a changed pair;
7. validates and activates the working configuration; and
8. terminates the session on success and error paths.

Certificate, key, chain, root CA, and relationship changes are staged in one
Gateway working configuration and become visible together at activation. The
zero-value `SyncOptions` rejects an outdated configuration. Merge and
overwrite behavior must be selected explicitly.

Every transaction owns a separate cookie jar and server-side working copy. A
single `Client` can therefore be used concurrently without mixing appliance
sessions.

`SyncLeafCertificate` and `SyncKey` read the other side of the existing pair,
verify the resulting pair locally, and still write the complete pair
atomically. A genuinely different key is rejected until its matching
certificate is supplied through `SyncCertificate`.

Because the Gateway exposes private-key passphrases as write-only, partial
updates of encrypted keys require `ReadOptions.PrivateKeyPassphrase` or
`SyncOptions.ExistingKeyPassphrase`. `SyncCertificate` uses the passphrase from
the validated bundle without persisting it.

Use `ByCertificateID` only for a certificate not owned through a Virtual Host:

```go
state, err := client.GetCertificate(ctx, airlock.ByCertificateID(17))
```

## Errors

HTTP errors are available as `*airlock.Error`. Authentication, not-found,
conflict, and unsupported-version conditions support `errors.Is`:

```go
if errors.Is(err, airlock.ErrConflict) {
    // The working configuration became outdated.
}
```

Error strings exclude raw appliance bodies and server-provided titles because
they may echo secret input. Structured fields remain available to callers that
deliberately inspect them.

## Advanced raw JSON:API access

Resources outside the typed release contract can be accessed through
`client.Raw().DoJSON`, `client.Raw().DoRaw`, and `ResourceAny`. The explicit
`Raw()` boundary makes the loss of compile-time guarantees visible. The CLI
and normal certificate workflows use the typed API.

```go
var response airlock.Document[airlock.ResourceAny]
err := client.Raw().DoJSON(ctx, http.MethodGet,
    "/configuration/future-resource/1", nil, &response, http.StatusOK)
```

## Implemented endpoints

The client uses the `/airlock/rest` base path and includes:

- `POST /session/create`
- `POST /session/terminate`
- `GET /system/status/node`
- `POST /configuration/configurations/load-active`
- `POST /configuration/configurations/{id}/load`
- `POST /configuration/configurations/save`
- `GET /configuration/validator-messages?filter=meta.severity==ERROR`
- `POST /configuration/configurations/activate`
- `GET|POST /configuration/ssl-certificates`
- `GET|PATCH|DELETE /configuration/ssl-certificates/{id}`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/virtual-hosts`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/back-end-groups`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/json-web-key-sets/remotes`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/nodes`
- `GET /configuration/virtual-hosts`
- `PATCH|DELETE /configuration/virtual-hosts/{id}/relationships/ssl-certificate`
- `GET /v3/api-docs[.yaml]`

The authoritative schema is available from the target Gateway:

- JSON: `https://<configuration-center-url>/airlock/rest/v3/api-docs`
- YAML: `https://<configuration-center-url>/airlock/rest/v3/api-docs.yaml`

Use the CLI `schema` command to download it for the exact target release.

# Go API reference

The public Go API provides typed certificate lifecycle operations for Airlock
Gateway 8.x. It is implemented and live-tested with Airlock Gateway 8.6.0.

Its hand-written facade uses the same canonical vocabulary as
`gateway-rest-api-lib`, the designated future REST foundation. The current
release keeps its existing transport internally until that library has a
publishable module path and compatible toolchain baseline; callers use the
stable facade described here and do not depend on that transport boundary.

## Client construction

```go
client, err := airlock.New(airlock.Config{
    Address: "gateway.example.com",
    APIKey:  os.Getenv("AIRLOCK_API_KEY"),
})
```

| Config property | Required | Meaning |
| --- | --- | --- |
| `Address` | yes | Configuration Center hostname or URL |
| `Port` | no | optional management port |
| `APIKey` | yes | bearer API key; excluded from JSON |
| `Timeout` | no | complete HTTP timeout; default 30 seconds |
| `TrustedCertificate` | no | management CA as PEM text or file path |
| `InsecureSkipVerify` | no | lab-only TLS verification bypass |
| `HTTPClient` | no | caller-provided client, useful in tests |
| `UserAgent` | no | overrides the versioned default User-Agent |

`New` returns a concurrency-safe client. Each managed configuration
transaction receives an independent cookie jar and Gateway working copy.

## Gateway and configuration calls

```go
GatewayVersion(ctx context.Context) (string, error)
ValidateConfiguration(ctx context.Context) ([]ValidationMessage, error)
```

`GatewayVersion` reports the appliance version and is intentionally distinct
from `BuildVersion`, which reports the library/CLI build.
`ValidateConfiguration` validates the configuration loaded in the current
Gateway session; it does not validate a client or local certificate object.

## Certificate input

`CertificateBundleInput` properties:

| Property | Meaning |
| --- | --- |
| `Type` | `SERVER_CERT` by default or `CLIENT_CERT` |
| `CertificatePEM` | exactly one leaf X.509 certificate |
| `PrivateKeyPEM` | PKCS#1, SEC1, PKCS#8, or encrypted PKCS#8 key |
| `PrivateKeyPassphrase` | transient UTF-8 passphrase; excluded from JSON |
| `CertificateChainPEM` | intermediate certificates in leaf-to-root order |
| `RootCAPEM` | optional public root CA certificate |

`ParseCertificateBundle` returns typed `Certificate`, `Key`, `Chain`, optional
`RootCA`, and canonical checksums. It verifies PEM structure, the
certificate/key match, CA constraints, and chain signatures locally.

`Certificate` exposes `Checksum`, `Subject`, `Issuer`, uppercase hexadecimal
`Serial`, `DNSNames`, `IPAddresses`, `NotBefore`, and `NotAfter`. Its `PEM()`
method returns a defensive copy of the canonical certificate PEM.

## Targets and identifier origin

| Type/property | Source and meaning |
| --- | --- |
| `VirtualHostName` | stable operator-defined `attributes.name` returned by `/configuration/virtual-hosts` |
| `VirtualHostID` | numeric JSON:API `data.id` assigned and returned by Gateway |
| `CertificateID` | numeric `ssl-certificate` `data.id`; negative IDs can represent built-in resources |
| `BackEndGroupID`, `RemoteJWKSID`, `NodeID` | numeric JSON:API IDs returned by their Gateway resources |
| `ForVirtualHost(name)` | preferred managed selector; resolves the exact name and hides IDs |
| `ByCertificateID(id)` | explicit selector for unbound or low-level managed resources |

Relationship IDs are never invented by the library. They come from JSON:API
resource identifiers returned by the target Gateway or from caller inventory
obtained through the corresponding typed list operation.

## High-level parameters and returns

`SyncOptions`:

| Property | Default | Meaning |
| --- | --- | --- |
| `ActivationComment` | empty | Gateway configuration audit comment |
| `ConflictPolicy` | `RejectConcurrentChanges` | reject, merge non-conflicting, or explicitly overwrite an outdated working copy |
| `DisableFailoverActivation` | false | activate on failover nodes by default |
| `ExistingKeyPassphrase` | empty | transient passphrase for leaf-only or key-only operations |

`SyncResult`:

| Property | Meaning |
| --- | --- |
| `Certificate` | final typed resource, certificate/key material, checksums, chain, and root CA |
| `VirtualHost` | resolved Virtual Host and final certificate relationship when selected by name |
| `Changed` | whether appliance state changed |
| `Created` | whether a new `ssl-certificate` resource was created |
| `Bound` | whether a Virtual Host relationship was created or moved |

`ManagedCertificate.ID` comes directly from the Gateway response.
`ManagedCertificate.Checksum` is calculated locally from canonical certificate,
key, chain, root CA, and certificate-type checksums.

`GetManagedCertificateWithOptions` accepts `ReadOptions.PrivateKeyPassphrase` only for
decoding an encrypted key returned by the Gateway; the passphrase is never
persisted or JSON-serialized.

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
- lifecycle methods: `GetManagedCertificate`, `SyncCertificate`,
  `SyncLeafCertificate`, `SyncKey`, `StartConfigurationTransaction`, `Commit`,
  `CommitWithOptions`, and `Abort`;
- to-one Virtual Host relationship methods: `SetVirtualHostCertificate` and
  `RemoveVirtualHostCertificate`;
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
state, err := client.GetManagedCertificate(ctx, airlock.ByCertificateID(17))
```

## Errors

HTTP errors are available as `*airlock.APIError`. An unsupported Gateway major
release is returned as `*airlock.VersionSkewError`. Both names and their core
fields align with `gateway-rest-api-lib`. Authentication, not-found, conflict,
and unsupported-version conditions support `errors.Is`:

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

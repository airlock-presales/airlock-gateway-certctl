# airlock-certctl

A small Go client library and CLI for Airlock Gateway SSL certificate management.

The implementation deliberately keeps certificate attributes as `map[string]any`. Airlock Gateway versions expose the authoritative OpenAPI schema at the Configuration Center endpoint:

- JSON: `https://<configuration-center-url>/airlock/rest/v3/api-docs`
- YAML: `https://<configuration-center-url>/airlock/rest/v3/api-docs.yaml`

Use the `schema` command to download the live schema from your Gateway and verify the exact `ssl-certificate` attributes for your version.

## Build

```bash
go build ./cmd/airlock-certctl
```

## Test

```bash
go test ./...
```

## Environment

```bash
export AIRLOCK_HOST=gateway.example.com
export AIRLOCK_API_KEY='...'
```

For lab systems with a self-signed management certificate, add `--insecure-skip-verify`.

## Configuration loading

Airlock Gateway requires a configuration to be loaded in the REST session before configuration resources such as SSL certificates can be read or changed. The CLI therefore always performs this sequence before executing a command:

```text
POST /session/create
POST /configuration/configurations/load-active
... command-specific request ...
POST /session/terminate
```

This mirrors the Python pattern:

```python
sess = gw_api.create_session(target_gateway["ip"], target_gateway["api_key"], 443)
gw_api.load_active_config(sess)
```

Mutating commands can still load a specific saved configuration after the initial active configuration load by using `--config-id`.

## CLI examples

List certificates. Sensitive attributes such as `privateKey`, passwords, tokens, and secrets are redacted by default:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" list
```

Print raw secret values only when you explicitly need them and your terminal/session logs are protected:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" --show-secrets get --id 17
```

Download the live OpenAPI schema:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" schema --format yaml --out airlock-openapi.yaml
```

Create a certificate in the currently active configuration and save it:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  create --attrs cert-attrs.json --save-comment "add certificate"
```

Connect a certificate to a virtual host and activate:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect-vh --cert-id 123 --virtual-host-ids 456 \
  --activate --activate-comment "attach certificate"
```

## Certificate rotation runbooks

The examples below assume that your shell already contains the Gateway access data:

```bash
export AIRLOCK_HOST=gateway.example.com
export AIRLOCK_API_KEY='...'
export DOMAIN=www.example.com
```

Create an Airlock `ssl-certificate` attributes file from PEM files. The output file contains private key material and is written with mode `0600`.

If `fullchain.pem` contains the leaf certificate followed by intermediate certificates, the first certificate is used as `certificate` and the remaining certificates become `certificateChain`:

```bash
./airlock-certctl attrs-from-pem \
  --cert fullchain.pem \
  --key privkey.pem \
  --out new-cert-attrs.json
```

If the leaf and chain are separate files, pass both explicitly:

```bash
./airlock-certctl attrs-from-pem \
  --cert cert.pem \
  --key privkey.pem \
  --chain chain.pem \
  --out new-cert-attrs.json
```

`--chain` is for intermediate CA certificates only. If Airlock should also receive the issuing root CA certificate, use `--root-ca`. This maps to Airlock's `rootCaCertificate` attribute. Pass the public CA certificate only, never a CA private key:

```bash
./airlock-certctl attrs-from-pem \
  --cert cert.pem \
  --key privkey.pem \
  --chain intermediate-ca.pem \
  --root-ca root-ca.pem \
  --out new-cert-attrs.json
```

The generated attributes then look conceptually like this:

```json
{
  "certType": "SERVER_CERT",
  "certificate": "leaf/server certificate",
  "certificateChain": ["intermediate CA certificate(s)"],
  "privateKey": "server private key",
  "rootCaCertificate": "root CA certificate"
}
```

For public certificates, the root CA is usually not needed because clients already trust public roots. For private/internal PKI, include `--root-ca` when the Airlock configuration expects the root CA certificate as part of the SSL certificate object.

Find the currently configured certificate for a domain. The command searches the certificate SAN DNS names and the subject common name and prints matching certificate IDs plus existing relationships such as bound virtual hosts:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  find-domain --domain "$DOMAIN" \
  > matching-certs.json

cat matching-certs.json
```

Extract the first matching certificate ID. If multiple certificates match, inspect `matching-certs.json` and choose the correct ID manually.

```bash
OLD_CERT_ID=$(jq -r '.[0].id' matching-certs.json)
echo "$OLD_CERT_ID"
```

### Scenario 1: replace the certificate data in-place

Use this when you want to keep the same Airlock certificate resource ID and preserve all existing relationships automatically. Only the certificate attributes are patched.

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  update \
  --id "$OLD_CERT_ID" \
  --attrs new-cert-attrs.json \
  --activate \
  --activate-comment "Rotate certificate for $DOMAIN in-place"
```

Verify that the domain now points to the updated certificate data:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  find-domain --domain "$DOMAIN"
```

### Scenario 2: create a new certificate, move the bindings, then delete the old certificate

The safest way is the built-in `replace-with-new` command. It does the full operation in one loaded configuration session:

1. reads the old certificate and its relationships,
2. creates the new certificate,
3. connects the new certificate to the same relationships,
4. disconnects the old certificate from those relationships,
5. deletes the old certificate by default,
6. validates and activates when `--activate` is set.

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  replace-with-new \
  --old-cert-id "$OLD_CERT_ID" \
  --attrs new-cert-attrs.json \
  --activate \
  --activate-comment "Replace certificate resource for $DOMAIN"
```

The output contains the new certificate ID and a `movedRelationships` object. Secret fields such as `privateKey` are redacted unless `--show-secrets` is explicitly set.

To keep the old certificate resource for manual cleanup, add `--delete-old=false`:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  replace-with-new \
  --old-cert-id "$OLD_CERT_ID" \
  --attrs new-cert-attrs.json \
  --delete-old=false \
  --activate \
  --activate-comment "Create replacement certificate for $DOMAIN but keep old resource"
```

### Scenario 2 manual variant: create, bind, unbind, delete

Use this only when you deliberately want separate activation steps. Because each CLI invocation creates a new REST session and loads the active configuration, every step must be activated before the next command can see the previous change.

Create and activate the new certificate:

```bash
NEW_CERT_ID=$(./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  create \
  --attrs new-cert-attrs.json \
  --activate \
  --activate-comment "Create replacement certificate for $DOMAIN" \
  | jq -r '.id')

echo "$NEW_CERT_ID"
```

Extract the virtual-host bindings from the old certificate:

```bash
VH_IDS=$(jq -r --arg id "$OLD_CERT_ID" \
  '.[] | select(.id == $id) | .relationships."virtual-hosts".data[]?.id' \
  matching-certs.json | paste -sd, -)

echo "$VH_IDS"
```

Connect the new certificate to the same virtual hosts:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect-vh \
  --cert-id "$NEW_CERT_ID" \
  --virtual-host-ids "$VH_IDS" \
  --activate \
  --activate-comment "Bind replacement certificate for $DOMAIN"
```

Disconnect the old certificate from those virtual hosts:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  disconnect-vh \
  --cert-id "$OLD_CERT_ID" \
  --virtual-host-ids "$VH_IDS" \
  --activate \
  --activate-comment "Unbind old certificate for $DOMAIN"
```

Delete the old certificate:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  delete \
  --id "$OLD_CERT_ID" \
  --activate \
  --activate-comment "Delete old certificate for $DOMAIN"
```

For non-virtual-host relationships, use the generic relationship command. Supported relationship names are `virtual-hosts`, `back-end-groups`, `remote-jwks`, and `nodes`:

```bash
./airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect \
  --cert-id "$NEW_CERT_ID" \
  --relationship back-end-groups \
  --ids 10,11 \
  --activate \
  --activate-comment "Bind replacement certificate to backend groups"
```


## Output safety

Airlock Gateway returns private key material as part of SSL certificate resources. To avoid leaking keys into terminals, CI logs, ticket systems, or chat transcripts, the CLI redacts sensitive output fields by default. The redaction currently covers keys whose names contain values such as `privateKey`, `password`, `passphrase`, `secret`, or `token`.

Use `--show-secrets` only for a controlled export workflow, for example when redirecting output into a protected file with restrictive permissions.

## Attribute input

`--attrs` expects the `attributes` object, not the full JSON:API envelope. Example shape only; verify actual names against your Gateway schema:

```json
{
  "name": "www.example.com",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
}
```

The library wraps this object as:

```json
{
  "data": {
    "type": "ssl-certificate",
    "attributes": {}
  }
}
```

## Library usage

```go
ctx := context.Background()
client, err := airlock.NewClient("gateway.example.com", os.Getenv("AIRLOCK_API_KEY"), airlock.WithInsecureSkipVerify())
if err != nil {
    log.Fatal(err)
}
if err := client.CreateSessionAndLoadActiveConfiguration(ctx); err != nil {
    log.Fatal(err)
}
defer client.TerminateSession(ctx)

cert, err := client.CreateSSLCertificate(ctx, map[string]any{"name": "www.example.com"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(cert.ID)
```

### Transactional certificate synchronization

`Config` contains the Airlock Gateway address, API key, TLS trust, and timeout
settings. `SyncSSLCertificate` performs the complete Configuration REST API
sequence documented for [Airlock Gateway 8.6](https://docs.airlock.com/gateway/8.6/index/rest-api/config-rest-api.html)
and synchronizes the full desired `ssl-certificate` state:

```go
client, err := airlock.New(airlock.Config{
    Address: "gateway.example.com",
    APIKey:  os.Getenv("AIRLOCK_API_KEY"),
    // InsecureSkipVerify: true, // lab systems only
})
if err != nil {
    log.Fatal(err)
}

result, err := client.SyncSSLCertificate(
    context.Background(),
    "42", // existing Airlock ssl-certificate ID; use "" to create a new resource
    airlock.CertificateMaterial{
        CertType:         "SERVER_CERT",
        Certificate:      string(certificatePEM),
        CertificateChain: []string{string(intermediatePEM)},
        PrivateKey:       string(privateKeyPEM),
    },
    "Rotate certificate for www.example.com",
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("changed=%t certificate=%s key=%s\n",
    result.Changed,
    result.Checksums.Certificate,
    result.Checksums.PrivateKey,
)
```

The synchronization compares SHA-256 checksums of the exact supplied
certificate and private-key bytes. If all material is already identical, no
configuration write or activation is performed. Otherwise the certificate,
chain, private key, and optional root CA are sent together in one JSON:API
create/update request. The loaded configuration is then validated and
activated before the REST session is terminated.

Airlock Gateway 8.6 does not expose a `name` attribute on `ssl-certificate`
resources. Keep the resource ID returned by a create operation and pass it to
subsequent synchronization calls.

## Implemented endpoints

The client uses the `/airlock/rest` base path and currently includes:

- `POST /session/create`
- `POST /session/terminate`
- session helper: `CreateSessionAndLoadActiveConfiguration(ctx)`
- `GET /system/status/node`
- `POST /configuration/configurations/load-active`
- `POST /configuration/configurations/{id}/load`
- `POST /configuration/configurations/save`
- `GET /configuration/validator-messages?filter=meta.severity==ERROR`
- `POST /configuration/configurations/activate`
- `GET /configuration/ssl-certificates`
- `GET /configuration/ssl-certificates/{id}`
- `POST /configuration/ssl-certificates`
- `PATCH /configuration/ssl-certificates/{id}`
- `DELETE /configuration/ssl-certificates/{id}`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/virtual-hosts`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/back-end-groups`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/remote-jwks`
- `PATCH|DELETE /configuration/ssl-certificates/{id}/relationships/nodes`
- `GET /v3/api-docs[.yaml]`

## GitHub automation

This repository includes a small GitHub automation setup:

- `.github/workflows/ci.yml` runs formatting checks, `go mod tidy` drift checks, `go vet`, race-enabled tests, a CLI build, and `govulncheck` on pushes and pull requests to `main` or `master`.
- `.github/workflows/codeql.yml` runs CodeQL for Go on pushes, pull requests, a weekly schedule, and manual dispatch. For private/internal repositories it skips the CodeQL job by default unless the repository variable `ENABLE_GITHUB_CODE_SECURITY=true` is set. This avoids failing private repositories that do not have GitHub Code Security/GHAS enabled yet.
- `.github/workflows/govulncheck.yml` runs the Go vulnerability scanner on a weekly schedule and manual dispatch. Push and pull request scans are part of `ci.yml`. The scanner uses `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` directly instead of `golang/govulncheck-action@v1`, because that composite action still performs an internal checkout with `actions/checkout@v4.1.1` by default. The scanner intentionally uses Go `1.25.x` plus `GOTOOLCHAIN=auto`, while the normal test job still uses `go-version-file: go.mod` to test the project's declared Go version.
- `.github/workflows/dependency-review.yml` reviews dependency changes in pull requests and fails on moderate-or-higher severity vulnerabilities. For private/internal repositories it is skipped by default unless the repository variable `ENABLE_GITHUB_CODE_SECURITY=true` is set.
- `.github/workflows/release.yml` publishes Linux, macOS, and Windows release artifacts with GoReleaser from explicit semantic version tags such as `v0.1.0`. It does not create tags automatically. Before publishing, it checks the tag format and reruns the release quality gates: formatting, `go mod tidy`, `go vet`, race-enabled tests, a CLI build, and `govulncheck`.
- `scripts/check-workflow-actions.sh` can be run locally or in CI to detect stale workflow references such as `golang/govulncheck-action@v1`, `actions/checkout@v4`, and `actions/setup-go@v5`.
- `.github/dependabot.yml` opens grouped weekly update pull requests for Go modules and GitHub Actions.

Notes:

- `Dependency Review` runs on pull requests only. It will not run for direct pushes to `main`, and on private/internal repositories it needs GitHub Code Security/GHAS unless the repository is made public.
- `Dependabot Updates` is not a manually dispatched workflow. Dependabot reads `.github/dependabot.yml` on the default branch on its schedule and opens pull requests when updates are found.

### Fixing the old govulncheck workflow failure

If GitHub Actions still shows a log line like this, the repository is still running an old workflow file:

```text
Run golang/govulncheck-action@v1
Run actions/checkout@v4.1.1
remote: Duplicate header: "Authorization"
```

The fixed workflow does not contain `golang/govulncheck-action@v1`. It checks out the repository with `actions/checkout@v6`, sets up Go with `actions/setup-go@v6`, and runs govulncheck with:

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

If the workflow fails with a message like this:

```text
go: golang.org/x/vuln/cmd/govulncheck@latest: golang.org/x/vuln@v1.3.0 requires go >= 1.25.0
```

then the govulncheck job is using the project Go version from `go.mod` instead of the scanner toolchain. The included workflow fixes that by using `go-version: "1.25.x"` in `govulncheck.yml` and by setting `GOTOOLCHAIN=auto`. Do not change the project `go.mod` just for this; the application can still keep `go 1.23` while the scanner itself runs with a newer Go toolchain.

After copying this repository content, confirm the old reference is gone:

```bash
git grep -n 'golang/govulncheck-action@v1\|actions/checkout@v4\|actions/setup-go@v5' -- .github/workflows || true
./scripts/check-workflow-actions.sh
```

If the old line is still present, delete or replace the stale workflow file in `.github/workflows` and commit the change.

### GitHub Code Security / GHAS

GitHub code scanning and dependency review are available by default for public repositories. For private or internal repositories, enable GitHub Code Security / GitHub Advanced Security first, then create a repository variable:

```text
ENABLE_GITHUB_CODE_SECURITY=true
```

Without that variable, CodeQL and Dependency Review are skipped with a clear notice for private/internal repositories, so the workflow does not fail with `Advanced Security must be enabled for this repository to use code scanning`. The normal CI and `govulncheck` workflows continue to run and do not require GitHub Code Security/GHAS.

For a private repository that will become public later, keep `ENABLE_GITHUB_CODE_SECURITY` unset for now. When the repository is public, CodeQL and Dependency Review run automatically. If the repository must remain private and you want GitHub-hosted code scanning results, enable GitHub Code Security/GHAS first and then add this repository variable:

```text
ENABLE_GITHUB_CODE_SECURITY=true
```

### Releases

Releases are tag-based. The workflow does not invent versions and does not create tags for you. To release, tag the commit you want to publish and push the tag:

```bash
git checkout main
git pull
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

That starts `.github/workflows/release.yml`. The release workflow validates the tag name, checks out the tagged commit, reruns the release quality gates, and only then runs GoReleaser. If any test or scan fails, no GitHub Release is created.

The accepted tag format is:

```text
vMAJOR.MINOR.PATCH
vMAJOR.MINOR.PATCH-PRERELEASE
```

Examples:

```text
v0.1.0
v1.2.3
v1.2.3-rc.1
```

The workflow also has `workflow_dispatch`, but only as a recovery path for an already existing tag. It does not create a tag. In the GitHub UI you can run:

```text
Actions -> Release -> Run workflow -> tag = v0.1.0
```

or with GitHub CLI:

```bash
gh workflow run release.yml -f tag=v0.1.0 --ref main
```

The repository must allow GitHub Actions to create releases. Check:

```text
Repository -> Settings -> Actions -> General -> Workflow permissions
```

Use `Read and write permissions`, or the Release workflow will fail when it tries to publish the release assets.

To check existing tags locally:

```bash
git fetch --tags
git tag --list 'v*.*.*'
```

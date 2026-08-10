# CLI reference

`airlock-certctl` administers Airlock Gateway SSL certificate resources. Run
`airlock-certctl help` for the command synopsis built into the binary.

## Connection settings

Global flags must appear before the command. The normal environment is:

```bash
export AIRLOCK_HOST=gateway.example.com
export AIRLOCK_API_KEY='...'
```

An optional management port can be set with `--port` or `AIRLOCK_PORT`.
`--timeout` defaults to 30 seconds. For a lab management endpoint with a
self-signed certificate, use `--insecure-skip-verify`; production systems
should use a trusted management CA.

## Common commands

Inspect build and appliance compatibility:

```bash
airlock-certctl build-info
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" version
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" verify-version
```

List, retrieve, and find certificates:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" list
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" get --id 17
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  find-domain --domain www.example.com
```

Download the live OpenAPI schema:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  schema --format yaml --out airlock-openapi.yaml
```

Create or update certificate attributes:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  create --attrs cert-attrs.json --save-comment "add certificate"

airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  update --id 17 --attrs cert-attrs.json \
  --activate --activate-comment "rotate certificate"
```

Connect a certificate to Virtual Hosts:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect-vh --cert-id 17 --virtual-host-ids 23,24 \
  --activate --activate-comment "attach certificate"
```

The generic `connect` and `disconnect` commands support `virtual-hosts`,
`back-end-groups`, `remote-jwks`, and `nodes` relationships.

## Configuration sessions

Every configuration command creates a REST session and loads the active
configuration before accessing configuration resources:

```text
POST /session/create
POST /configuration/configurations/load-active
... command-specific request ...
POST /session/terminate
```

Mutating commands may load a saved configuration after the initial active
configuration by using `--config-id`. `--save-comment` saves without
activation. `--activate` validates and activates the working configuration.
Mutations verify Airlock Gateway 8.x compatibility before opening a session.

## Attribute input

`--attrs` expects a typed `SSLCertificateAttributes` object, not a complete
JSON:API envelope. Unknown properties and unsupported `certType` values are
rejected locally. Omitted pointer-backed fields remain unchanged; explicitly
empty fields are cleared.

```json
{
  "certType": "SERVER_CERT",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "certificateChain": [],
  "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "rootCaCertificate": ""
}
```

Create this file safely from PEM input:

```bash
airlock-certctl attrs-from-pem \
  --cert fullchain.pem \
  --key privkey.pem \
  --out cert-attrs.json
```

The output contains private-key material and is written with mode `0600`.
Use `--chain` for intermediate certificates and `--root-ca` for an optional
public root certificate. Never pass a CA private key.

## Output safety

The Gateway may return private-key material with certificate resources. CLI
output therefore redacts fields whose names indicate private keys, passwords,
passphrases, secrets, or tokens.

`--show-secrets` disables redaction. Use it only in a controlled export
workflow and redirect output to a protected destination.

For complete operational replacement procedures, see
[Certificate rotation](CERTIFICATE_ROTATION.md).

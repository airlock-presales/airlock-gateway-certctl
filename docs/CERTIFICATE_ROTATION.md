# Certificate rotation

This runbook describes supported certificate replacement workflows with
`airlock-certctl`.

## Preparation

Set the Gateway and target domain:

```bash
export AIRLOCK_HOST=gateway.example.com
export AIRLOCK_API_KEY='...'
export DOMAIN=www.example.com
```

Create typed attributes from a leaf certificate or full chain and its private
key. If `fullchain.pem` contains multiple certificates, the first becomes the
leaf and the remainder become `certificateChain`:

```bash
airlock-certctl attrs-from-pem \
  --cert fullchain.pem \
  --key privkey.pem \
  --out new-cert-attrs.json
```

For separate files:

```bash
airlock-certctl attrs-from-pem \
  --cert cert.pem \
  --key privkey.pem \
  --chain intermediate-ca.pem \
  --root-ca root-ca.pem \
  --out new-cert-attrs.json
```

`--chain` is for intermediate CA certificates. `--root-ca` accepts the public
root certificate only. Public roots usually need not be included; private PKI
deployments may require one.

Find the current certificate and inspect every match before selecting an ID:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  find-domain --domain "$DOMAIN" > matching-certs.json

jq . matching-certs.json
OLD_CERT_ID=$(jq -r '.[0].id' matching-certs.json)
```

If multiple resources match, select the correct ID manually instead of relying
on the first array element.

## Scenario 1: update in place

Use an in-place update to preserve the certificate resource ID and all existing
relationships:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  update \
  --id "$OLD_CERT_ID" \
  --attrs new-cert-attrs.json \
  --activate \
  --activate-comment "Rotate certificate for $DOMAIN in-place"
```

Verify the resulting appliance state and the certificate served by the VIP:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  find-domain --domain "$DOMAIN"

openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null \
  | openssl x509 -noout -subject -issuer -serial -dates
```

## Scenario 2: replace the resource atomically

`replace-with-new` performs the resource replacement in one loaded
configuration session. It reads the old relationships, creates the new
resource, moves every supported binding, deletes the old resource by default,
validates, and activates:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  replace-with-new \
  --old-cert-id "$OLD_CERT_ID" \
  --attrs new-cert-attrs.json \
  --activate \
  --activate-comment "Replace certificate resource for $DOMAIN"
```

The output contains the new ID and `movedRelationships`. Secret fields remain
redacted. Add `--delete-old=false` when the old resource must remain for manual
cleanup.

## Manual multi-step replacement

Use separate steps only when the operational procedure explicitly requires
them. Each CLI invocation creates a new session and loads the active
configuration, so every step must be activated before the next command can see
it.

Create and activate the replacement:

```bash
NEW_CERT_ID=$(airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  create --attrs new-cert-attrs.json --activate \
  --activate-comment "Create replacement certificate for $DOMAIN" \
  | jq -r '.id')
```

Extract the old Virtual Host relationships:

```bash
VH_IDS=$(jq -r --arg id "$OLD_CERT_ID" \
  '.[] | select(.id == $id) | .relationships."virtual-hosts".data[]?.id' \
  matching-certs.json | paste -sd, -)
```

Bind the replacement, unbind the old resource, and then delete it:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect-vh --cert-id "$NEW_CERT_ID" --virtual-host-ids "$VH_IDS" \
  --activate --activate-comment "Bind replacement certificate for $DOMAIN"

airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  disconnect-vh --cert-id "$OLD_CERT_ID" --virtual-host-ids "$VH_IDS" \
  --activate --activate-comment "Unbind old certificate for $DOMAIN"

airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  delete --id "$OLD_CERT_ID" --activate \
  --activate-comment "Delete old certificate for $DOMAIN"
```

For non-Virtual-Host relationships, use `connect` or `disconnect` with one of
`back-end-groups`, `remote-jwks`, or `nodes`:

```bash
airlock-certctl --host "$AIRLOCK_HOST" --api-key "$AIRLOCK_API_KEY" \
  connect --cert-id "$NEW_CERT_ID" --relationship back-end-groups --ids 10,11 \
  --activate --activate-comment "Bind replacement to backend groups"
```

## Rollback and verification

Before the change window, retain a Gateway backup or saved configuration ID.
After activation:

1. verify the certificate resource and its relationships;
2. verify the leaf certificate, chain, SNI, and validity dates at every VIP;
3. verify HA/failover nodes where applicable; and
4. restore the saved configuration if functional validation fails.

See [Production readiness](../PRODUCTION_READINESS.md) for the required
customer acceptance and release gates.

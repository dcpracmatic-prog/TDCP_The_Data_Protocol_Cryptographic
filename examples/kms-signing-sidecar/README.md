# External signing sidecar (example, P0-2)

A tiny HTTP signer for `TDCP_SIGNING_BACKEND=external`. The Authority never
sees the private key: it POSTs canonical grant bytes here and gets a raw
ECDSA P-256 signature back. See `docs/AUTHORITY.md` ("Firma externa
(KMS/HSM)") for the full picture.

## Files

- `kms-signing-sidecar.mjs` — the sidecar. Two modes, same HTTP contract.
- `fake-cmd-signer.mjs` — a local-command signer (same signing idea, but
  invoked as a process instead of over HTTP). Used by the automated tests.

## Try it without any real credentials (fake mode)

```bash
# 1. Start the fake signer (ephemeral in-memory key; NOT production)
node examples/kms-signing-sidecar/kms-signing-sidecar.mjs --port 8011

# 2. In another terminal, check it
curl -s http://127.0.0.1:8011/health
curl -s http://127.0.0.1:8011/v1/public-key

# 3. Point the Authority at it (dev only — the fake key is not production-grade)
export TDCP_SIGNING_BACKEND=external
export TDCP_SIGNING_EXTERNAL_URL=http://127.0.0.1:8011
npm run authority   # or: node --experimental-strip-types server/authority/index.ts
```

The Authority will refuse to start if the sidecar is down, and will refuse
to issue a grant if a signing call fails — there is no silent fallback to
the `file` backend.

## Production: real AWS KMS

Install the AWS SDK **in this sidecar's own directory only** (it is
intentionally not a dependency of the TDCP repo):

```bash
cd examples/kms-signing-sidecar
npm init -y
npm install @aws-sdk/client-kms
```

Then run it with your key (credentials come from the standard AWS chain —
environment, `~/.aws/credentials`, or the host IAM role — never from this repo):

```bash
export AWS_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION=us-east-1
node kms-signing-sidecar.mjs --mode kms --port 8011 --host 127.0.0.1
```

And on the Authority side, attest that the signer is real:

```bash
export TDCP_SIGNING_BACKEND=external
export TDCP_SIGNING_EXTERNAL_URL=http://127.0.0.1:8011
export TDCP_SIGNING_EXTERNAL_KEY_ID="$AWS_KMS_KEY_ID"
export TDCP_SIGNING_EXTERNAL_ATTESTED=true
```

### Minimum IAM permissions (attach to the sidecar's role/user, key-scoped)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
  ]
}
```

That is all: signing + publishing the public key. No `kms:Decrypt`,
`kms:Encrypt`, `kms:GenerateDataKey`, and no `kms:*`. The key itself must
be an **ECC_NIST_P256** (ECDSA P-256) key with usage `SIGN_VERIFY`
(create it with `--customer-master-key-spec ECC_NIST_P256 --key-usage
SIGN_VERIFY`); a symmetric KMS key cannot sign TDCP grants.

### Deploy notes

- Keep the sidecar on the same host / private network as the Authority
  (bind `127.0.0.1` by default). If it ever leaves localhost, put TLS and
  a reverse proxy in front, and set a shared token (`SIDECAR_TOKEN` here,
  `TDCP_SIGNING_EXTERNAL_TOKEN` on the Authority).
- Key rotation: create a new KMS key, point `AWS_KMS_KEY_ID` at it, restart
  the sidecar, then restart the Authority. Old grants keep verifying with
  the old public key only while the old key is still published — plan the
  rotation window; there is no automatic multi-key support yet.
- The sidecar is stateless (no database, no files). The Authority keeps its
  durable revoke/replay state as before; only the signature moves out.

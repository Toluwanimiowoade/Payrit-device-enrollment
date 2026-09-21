# Payrit — device enrollment test harness

Walks the sequence at https://payrit-ble.mintlify.site/quickstart end to end — register an
account, mint the bootstrap key, create a customer, enroll a device, then refresh and revoke
its credential — with a phone-shaped UI you click through as the customer and a pane showing
every call that actually went out. No dependencies, no build step.

## Run

```sh
node server.js          # harness at http://localhost:4546
node run-tests.js       # test suite, terminal. Creates nothing on the deployment.
node run-tests.js --flow  # also walks the live sequence with a throwaway account
```

Nothing needs configuring first. On the first click the harness registers its own business
account and mints the bootstrap key, because `POST /accounts/{id}/api-keys` is open exactly
once per account — while it has zero active keys. To reuse an account you already have,
copy `.env.local.example` to `.env.local` and paste the key in; that file is gitignored and
re-read on every request, so pasting a key in never needs a restart.

| Env var | Purpose |
| --- | --- |
| `PAYRIT_API_KEY` | `pk_test_…`. Leave unset and the UI bootstraps its own account and key. |
| `PAYRIT_API_BASE` | Defaults to the Production server in the OpenAPI spec. |
| `PAYRIT_APP_ID` | Bundle id the simulated App Attest statement claims. |
| `PAYRIT_ALLOW_LIVE` | Set to `yes` to permit a `pk_live_` key. Refused otherwise. |
| `PORT` | Defaults to `4546`. |

Live enrollment additionally needs the test roots. These default to the files in
`.harness-pki/`, so they only need setting if they live elsewhere:

| Env var | Purpose |
| --- | --- |
| `PAYRIT_APPATTEST_ROOT_CERT` / `_JWK` | Test App Attest root and its signing key. |
| `PAYRIT_TEAM_ID`, `PAYRIT_BUNDLE_ID` | The app identity the attestation claims. |
| `PAYRIT_ANDROID_ROOT_CERT` / `_JWK` | Test Android attestation root and its signing key. |
| `ANDROID_APP_PACKAGE` | Package name in the AttestationApplicationId. |
| `ANDROID_SIGNING_CERT_DIGEST` | Signing certificate digest, hex. |
| `PAYRIT_ANDROID_BINDING` | `raw` (default) or `payrit`. |
| `PAYRIT_ANDROID_APPID_LOCATION` | `tee` (default), `software`, or `both`. |

## The two modes

The toggle in the header decides who verifies the attestation. In both modes the account, the
key, the customer and every nonce come from the real deployment.

**Live** sends the real thing and, with the test roots configured, succeeds: `POST /v1/enroll`
returns a Payrit-signed Device Credential, which then refreshes and revokes. This works because
the deployment trusts a pair of *test* roots whose private keys live in `.harness-pki/`, so the
harness can sign attestations it accepts. Without those, enrollment fails closed with a `422`,
exactly as the docs describe.

**Simulated** verifies the attestation locally instead, against the harness's own root. It is
not a rubber stamp: the nonce is still the real one, still single-use and expiring, the chain
really has to verify, and refresh really checks an ES256 signature from the device key.

## Integrating against Payrit yourself

If you are writing a client rather than reading this harness, start with
[INTEGRATION.md](INTEGRATION.md) — the binding formulas, the response shape, an error-message
map, a pre-flight checklist, and the open questions worth raising with the Payrit team.

## The attestation bindings

These are the parts specific to Payrit rather than to Apple or Google, and they are what took
longest to get right.

**iOS** uses Apple's App Attest structure with a custom `clientDataHash` that folds in a hash of
the public key, binding the attestation to the nonce *and* the signing key at once:

```
clientDataHash = SHA256( UTF8(nonceString) || SHA256(publicKeySpkiDer) )
appleNonce     = SHA256( authData || clientDataHash )
```

`appleNonce` goes in the credCert extension `1.2.840.113635.100.8.2`. The nonce is hashed as the
literal text from `/enroll/challenge`, not base64url-decoded first, and the key as the full SPKI
DER — the same bytes the request's `publicKey` field base64-encodes.

**Android** differs in two ways worth remembering:

* the attestation challenge is the **plain nonce string**, with no key folded in;
* the `attestationApplicationId` is read from **`teeEnforced`**, not `softwareEnforced` where
  real Android Key Attestation puts it.

Both are settable via `PAYRIT_ANDROID_BINDING` and `PAYRIT_ANDROID_APPID_LOCATION`.

## Response shape

The 201 carries no `deviceId`:

```json
{ "paymentInstrumentId": "...", "deviceCredential": "...", "expiresAt": "..." }
```

`deviceCredential` is a JSON *string* holding `{ credential, signature }`, where `credential` is
base64 protobuf — field 1 the device id, 2 the payment instrument, 3 the customer, 4 the account,
5 the device SPKI, 7 and 8 the issue and expiry times. `lib/credential.js` reads it.

`POST /enroll/refresh` and `POST /devices/{id}/revoke` key on the **paymentInstrumentId**, even
though the DTO field is called `deviceId`; passing the id from inside the credential returns
`404 Device not found`.

## What stands in for what

| The real thing | Here |
| --- | --- |
| P-256 key in StrongBox / Secure Enclave, non-exportable | P-256 key generated by node, held server-side, never sent to the browser |
| Android Key Attestation chain rooted at Google | Real X.509 chain with a real KeyDescription extension, rooted at the Payrit **test** Android root |
| Play Integrity token | Token-shaped, unsigned. Not checked against the test root |
| iOS App Attest CBOR object | Real `apple-appattest` CBOR, rooted at the Payrit **test** App Attest root |

Everything except the roots is genuine: real CBOR, real DER, real X.509, real ES256.

## Deploying

The harness runs as a normal node process locally, and as a serverless function on Vercel —
`api/index.js` hands requests to the same server, and `vercel.json` routes `/api/*` to it.

Two things change when it is hosted:

* **State is ephemeral.** `.runtime.json` and the harness PKI move to the platform's temp
  directory (see `lib/paths.js`), so a cold start loses the bootstrapped account, the key and
  any enrolled devices. Set `PAYRIT_API_KEY` so at least the key survives.
* **Anyone with the URL can drive it.** It creates real customers and devices on whichever
  deployment `PAYRIT_API_BASE` points at, using the key it holds. Keep it on a test key, and
  treat the URL as semi-private.

Environment variables to set on the host: `PAYRIT_API_KEY`, and for live enrollment the test
roots — `PAYRIT_APPATTEST_ROOT_CERT` / `_JWK`, `PAYRIT_TEAM_ID`, `PAYRIT_BUNDLE_ID`,
`PAYRIT_ANDROID_ROOT_CERT` / `_JWK`, `ANDROID_APP_PACKAGE`, `ANDROID_SIGNING_CERT_DIGEST`.
All of those accept the value inline, so no files need to be deployed.

## Layout

| File | Role |
| --- | --- |
| `server.js` | Stands in for the institution's backend — holds the key, owns the device keys, drives the sequence. |
| `lib/payrit.js` | Client for the documented API. One event logged per call. |
| `lib/hardware.js` | The SDK's half: keygen, attestation, ES256 proof of possession. |
| `lib/simulator.js` | The backend's half, locally: nonce rules, attestation check, credential issue/refresh/revoke. |
| `lib/state.js` | `.env.local` and `.runtime.json`. |
| `lib/http.js` | Core-module JSON client, plus the redaction the event log relies on. |
| `lib/events.js` | The wire log the UI polls. |
| `public/index.html` | The page: phone on the left, setup and wire log on the right. |
| `run-tests.js` | Terminal suite, including assertions against the published OpenAPI spec. |
| `lib/appattest.js` | Apple App Attest objects: authData, the nonce binding, the credCert. |
| `lib/androidattest.js` | Android Key Attestation chains. |
| `lib/keyattestation.js` | The KeyDescription ASN.1 structure and AttestationApplicationId. |
| `lib/cbor.js`, `lib/der.js` | Minimal CBOR and DER writers and a DER reader. |
| `lib/x509.js` | Issues and verifies X.509 certificates in pure JS — no openssl. |
| `lib/paths.js` | Where writable state lives; redirects to tmp when serverless. |
| `api/index.js`, `vercel.json` | Serverless entry point and routing. |
| `lib/credential.js` | Reads the Device Credential the deployment returns. |

## Endpoints

The harness's own routes, all called by the page:

| Route | Does |
| --- | --- |
| `POST /api/bootstrap` | `POST /v1/accounts` then `POST /v1/accounts/{id}/api-keys`. |
| `POST /api/customer` | `POST /v1/customers`. |
| `POST /api/enroll` | `POST /v1/enroll/challenge`, generates the key and attestation, then `POST /v1/enroll`. |
| `POST /api/refresh` | Fresh nonce, signs it with the device key, then `POST /v1/enroll/refresh`. |
| `POST /api/revoke` | `POST /v1/devices/{id}/revoke`. |
| `GET /api/state` | Account, key prefix, customer, devices. Never a raw secret. |
| `GET /api/events` | Everything on the wire so far. |
| `POST /api/reset` | Drops `.runtime.json` and the log. The Payrit-side records stay. |

## Secrets

`.runtime.json` holds the minted API key and the device private keys, and `.harness-pki/`
holds the attestation root and the credential issuer key. Both are gitignored and written
`0600`. The browser is only ever told the first 11 characters of the API key, and the event
log masks keys and truncates the long base64 blobs. `POST /api/enroll` refuses a `pk_live_`
key unless `PAYRIT_ALLOW_LIVE=yes` is set.

## Notes

* No external binaries are required. Certificates are issued and verified in pure JavaScript
  (`lib/x509.js`), so the harness runs anywhere node does, including serverless.
* Reset clears local state only. Accounts, keys and customers already created on the
  deployment stay there — the bootstrap route will not re-open for an account that already
  has a key, so a reset always registers a fresh account.
* Later phases in the docs — pre-authorizations, the offline BLE handshake, settlement — are
  not in the API yet, so there is nothing here for them.

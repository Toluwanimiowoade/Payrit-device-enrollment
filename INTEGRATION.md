# Integrating Payrit device enrollment

Notes from getting a client through `POST /v1/enroll` against the live deployment, written
down because most of them are not in the API reference and cost real time to find.

The official sequence is at https://payrit-ble.mintlify.site/quickstart. Follow that first.
This document covers the parts that will reject you afterwards, and why.

Verified against `https://payrit-ble-backend.vercel.app`, September 2026.

---

## 1. The attestation binding is custom

This is the single biggest source of lost time. Payrit uses Apple's and Google's attestation
structures, but **the challenge bound inside them is not what Apple and Google document**. If
you implement standard App Attest or standard Key Attestation, you will be rejected with a
message that gives no hint that the binding is the problem.

The two platforms also do not agree with each other. Do not assume symmetry.

### iOS

The `clientDataHash` folds in a hash of the public key, so the attestation is bound to the
nonce *and* the signing key at once:

```
clientDataHash = SHA256( UTF8(nonceString) || SHA256(publicKeySpkiDer) )
appleNonce     = SHA256( authData || clientDataHash )
```

`appleNonce` goes in the credCert extension `1.2.840.113635.100.8.2`, DER-encoded as
`SEQUENCE { [1] { OCTET STRING nonce } }` — on the wire, `30 24 A1 22 04 20` followed by the
32 nonce bytes.

Two details that are easy to get wrong:

* **`nonceString` is the literal text** returned by `/enroll/challenge`. Do not base64url-decode
  it first. Hash the characters you received.
* **`publicKeySpkiDer` is the full SubjectPublicKeyInfo DER** — the exact bytes that the
  request's `publicKey` field base64-encodes. It is *not* the raw 65-byte X9.63 point that
  `SecKeyCopyExternalRepresentation` hands you on iOS. You must wrap it in SPKI first, and hash
  the wrapped form.

Standard Apple App Attest uses `clientDataHash = SHA256(challenge)` with no key involved. That
will fail here.

### Android

Android does **not** fold in the key. The attestation challenge in the `KeyDescription`
extension (`1.3.6.1.4.1.11129.2.1.17`) is the plain nonce string, as UTF-8 bytes:

```
attestationChallenge = UTF8(nonceString)
```

---

## 2. Android: where the application id must live

The verifier reads `attestationApplicationId` (tag `709`) from **`teeEnforced`**.

Real Android Key Attestation puts it in `softwareEnforced`, because the app identity is not
something the TEE attests. Putting it where the platform actually puts it gets you:

```
422 — Attestation application id does not match the configured app
```

The structure itself is standard:

```
AttestationApplicationId ::= SEQUENCE {
  package_infos      SET OF SEQUENCE { package_name OCTET STRING, version INTEGER },
  signature_digests  SET OF OCTET STRING
}
```

with `package_name` matching the deployment's `ANDROID_APP_PACKAGE` and one digest matching its
`ANDROID_SIGNING_CERT_DIGEST`.

> **If you are testing from a real device, read this.** A genuine Android device will place the
> application id in `softwareEnforced`. Confirm with the backend team which location the
> verifier accepts before building against either — as of this writing it accepts only
> `teeEnforced`, which real hardware will not produce.

The `integrityToken` field is required to be present but is not validated against Google when
the deployment is configured with a test root.

---

## 3. What comes back is not what you expect

A successful enrollment returns:

```json
{
  "message": "Success",
  "data": {
    "paymentInstrumentId": "9731cb04-…",
    "deviceCredential": "{\"credential\":\"CiQyYjJm…\",\"signature\":\"DAIq4cD…\"}",
    "expiresAt": "2026-09-22T08:09:05.578Z"
  }
}
```

Three things to note:

* **There is no `deviceId` field.** The device id is *inside* the credential.
* **`deviceCredential` is a JSON string**, not an object. Parse it, then you have
  `{ credential, signature }` — `credential` is base64 protobuf, `signature` is a raw ES256
  signature over it.
* The expiry field is **`expiresAt`**, not `credentialExpiresAt`.

The credential protobuf, by field number:

| # | Contents |
| --- | --- |
| 1 | device id |
| 2 | payment instrument id |
| 3 | customer id |
| 4 | account id |
| 5 | device public key, SPKI DER |
| 7 | issued at, epoch ms |
| 8 | expires at, epoch ms |

Credentials last 24 hours.

---

## 4. `deviceId` does not mean device id

`POST /v1/enroll/refresh` takes a field called `deviceId`, and `POST /v1/devices/{id}/revoke`
takes an `{id}` path parameter. **Both want the `paymentInstrumentId`.**

Passing field 1 from the credential — the actual device id — returns `404 Device not found`.
The naming and the behaviour disagree; the behaviour wins.

---

## 5. Smaller things that will bite

**`currency` was removed from `EnrollDeviceDto`.** Older integrations sent it. It is now
rejected outright with `400 property currency should not exist`. The published spec is current;
older copies are not.

**Nonces are single-use and short-lived.** `/enroll/challenge` nonces expire in about five
minutes and are consumed on use. Fetch a fresh one per attempt — including per retry while
debugging, which is easy to forget when iterating.

**The bootstrap key is a one-shot.** `POST /v1/accounts/{id}/api-keys` works without
authentication only while the account has zero active keys. After the first key exists, minting
another needs an existing key with `api_keys:write`. The raw key is returned exactly once, at
mint time — there is no way to recover it. If you lose it, you register a new account.

**Refresh does not re-attest.** It proves possession by signing the nonce with the device key:
raw ES256 (`ieee-p1363`) over the UTF-8 nonce bytes, base64-encoded. That is 64 raw bytes, not a
DER-wrapped signature.

---

## 5b. Pre-authorization, and what blocks it

`POST /v1/authorizations` reserves a spend cap against the account's wallet. Two things will stop you
before the request shape ever matters:

**Your key needs the new scopes.** `authorizations:read` / `authorizations:write` were added after the
first release. A bootstrap key minted before they existed does not have them and gets `403 API key is
missing a required scope`. Mint a new key — an existing key with `api_keys:write` can request the full
scope list — or register a fresh account, whose bootstrap key now carries all eight.

**The account needs a funded ledger.** Two distinct failures, in order:

| Message | Meaning |
| --- | --- |
| `422 No NGN ledger accounts are provisioned for this account` | The account has no ledger for that currency at all. Accounts registered before ledgers existed have none. |
| `422 Insufficient available balance to reserve this amount` | The ledger exists but holds nothing. Fails even for `cap: "1"`. |

There is **no endpoint in the API to provision or fund a ledger**, and the docs do not mention one. As of
this writing a freshly registered account gets NGN ledgers automatically but they are empty, so live
pre-authorization cannot succeed from a client at all — the balance has to come from the Payrit side.

Also worth knowing: `deviceId` in `RequestPreAuthorizationDto` is the **`paymentInstrumentId`** again, the
same aliasing as refresh and revoke (§4). A device may hold only one active authorization; asking for a
second returns `409`.

---

## 5c. The offline handshake: what the chain does and does not prove

The handshake is specified in the docs and has no API. Implementing it surfaced one property worth being
deliberate about.

The `previous_record_hash` chain anchors at the **PreAuthorization**, at the start. Each record points
backwards to the one before it. That makes the chain tamper-evident in every direction but one:

| Tampering | Detected? |
| --- | --- |
| Reorder two records | Yes — sequence numbers and hashes break |
| Remove a record from the middle | Yes — the next record's hash no longer matches |
| Rewrite an amount | Yes — the payer signature no longer verifies |
| Append a record signed by another key | Yes — signature fails |
| **Truncate the chain, dropping the most recent records** | **No** |

A prefix of an honest chain is itself a perfectly valid chain: every hash still links, every signature
still verifies, and `running_consumed` is consistent with what remains. A payer presenting only the first
two of its four records looks like a device that has spent less and has more headroom.

Nothing in the presented data can prove a chain is *complete*, because completeness is a claim about
records the receiver has never seen. This is inherent to offline verification rather than a flaw in the
encoding, and it is the reason `receiverSignature` matters: every receiver holds countersigned proof of
the transaction it took part in, so an overspend is reconstructible at settlement even though it cannot be
prevented at handshake time.

If that is the intended model, say so in the docs — an implementer reading "the receiver replays that
chain, confirms every signature and every link" will reasonably assume the cap is enforced offline, when
what is actually enforced offline is "no *disclosed* spending exceeds the cap."

---

## 6. Reading the error messages

Each rejection is specific, and the message tells you how far you got. Working through them in
this order saves time:

| Status and message | What it means |
| --- | --- |
| `401 API key required` / `Invalid API key` | No or bad `x-api-key`. |
| `403` | Key lacks `devices:write`. |
| `400 property X should not exist` | Unknown field — the DTO is stricter than you think. |
| `400 customerId must be a UUID` | Payload validation, before any attestation work. |
| `422 Apple App Attest root not configured` | Deployment-side: `APPLE_APPATTEST_ROOT` unset. Not your bug. |
| `422 Malformed App Attest CBOR object` | Your attestation object did not parse. Check the CBOR. |
| `422 Chain does not terminate at a trusted root` | Chain parsed; root not trusted. |
| `422 Attestation challenge does not match the issued nonce` | **Android**: chain trusted, challenge construction wrong. |
| `422 Attestation is not bound to the issued nonce and signing key` | **iOS**: chain trusted, `clientDataHash` construction wrong — see §1. |
| `422 Attestation application id does not match the configured app` | Package or digest mismatch, or the app id is in `softwareEnforced`. |
| `404 Device not found` on refresh/revoke | You passed the device id instead of the payment instrument id. |
| `403 Device is not active` | Already revoked. Correct behaviour. |
| `403 API key is missing a required scope` | On `/v1/authorizations`: the key predates the `authorizations:*` scopes. |
| `422 No NGN ledger accounts are provisioned` | The account has no ledger for that currency. Server-side to fix. |
| `422 Insufficient available balance` | The ledger exists but is empty. No funding endpoint exists. |

The useful property here is that the messages are ordered by how deep you got. Moving from
"chain does not terminate" to "challenge does not match" is progress, not a new problem.

---

## 7. Checklist for a new integration

- [ ] Register account, mint the bootstrap key, **store it immediately** — shown once.
- [ ] Create a customer. Devices enroll against one; it must exist first.
- [ ] Generate a P-256 key in secure hardware, non-exportable.
- [ ] Fetch a nonce from `/enroll/challenge` for the right platform.
- [ ] Build the attestation with the **platform-correct binding** (§1) — they differ.
- [ ] iOS: hash the **SPKI DER**, not the X9.63 point.
- [ ] iOS: hash the nonce as **text**, not decoded bytes.
- [ ] Android: put `attestationApplicationId` where this deployment reads it (§2).
- [ ] Send `publicKey` as base64 SPKI DER. Do not send `currency`.
- [ ] Parse `deviceCredential` as a **JSON string**, then decode the protobuf.
- [ ] Store the **`paymentInstrumentId`** — that is what refresh and revoke key on.
- [ ] Refresh before `expiresAt`; credentials last 24 hours.
- [ ] Handle revocation: a revoked device cannot refresh, and must re-enroll.

---

## 8. Open questions for the Payrit team

Worth resolving before anyone builds a production client:

1. **Will the `teeEnforced` application id location work with real devices?** Real hardware
   populates `softwareEnforced`. As written, the verifier appears to accept only what a
   simulator produces and would reject a genuine phone. This needs testing on real hardware.
2. **Why do the two platforms bind differently?** iOS folds `SHA256(publicKey)` into the
   clientDataHash; Android does not. If this is deliberate, document it. If not, aligning them
   removes a whole class of integration bugs.
3. **Rename the `deviceId` field, or accept both values.** Every integrator will hit the `404`
   at least once.
4. **Document the credential format.** The protobuf schema and the signature algorithm are not
   published, so clients cannot verify the credential they are issued.
5. **Is the `integrityToken` ever validated?** Currently required but unchecked. Clients need to
   know whether to invest in producing a real one.
6. **Is there a way to fund a test ledger?** Live pre-authorization is unreachable from a client
   without one, so no integrator can exercise steps 6 onward against the real API.
7. **Is chain truncation an accepted limitation?** See §5c. If the answer is "settlement catches it",
   the docs should say so where they describe the replay.
8. **Publish the custom binding in the API reference.** It is the one thing no integrator can
   guess, and none of it appears in the docs today.

---

## Reference implementation

The harness in this directory implements all of the above and enrolls successfully on both
platforms. The pieces worth reading:

| File | What it shows |
| --- | --- |
| `lib/appattest.js` | The iOS binding, authData layout, credCert with the nonce extension. |
| `lib/androidattest.js` | The Android chain and challenge. |
| `lib/keyattestation.js` | `KeyDescription` and `AttestationApplicationId` in ASN.1. |
| `lib/credential.js` | Parsing the returned credential. |
| `server.js` | The whole sequence, in order. |

It has no dependencies and shells out to nothing — CBOR, DER and X.509 are all implemented
directly — so the crypto is readable rather than hidden behind a library.

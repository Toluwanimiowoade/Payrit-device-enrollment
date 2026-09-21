"use strict";

var crypto = require("crypto");
var fs = require("fs");
var path = require("path");

var hardware = require("./hardware.js");
var events = require("./events.js");
var httpc = require("./http.js");

var PKI_DIR = path.join(__dirname, "..", ".harness-pki");
var ISSUER_KEY = path.join(PKI_DIR, "issuer.key");
var CREDENTIAL_TTL_SECONDS = 900;

function issuerKey() {
  if (!fs.existsSync(ISSUER_KEY)) {
    fs.mkdirSync(PKI_DIR, { recursive: true });
    var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    fs.writeFileSync(ISSUER_KEY, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  }
  return crypto.createPrivateKey(fs.readFileSync(ISSUER_KEY, "utf8"));
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function mintCredential(claims) {
  var header = { alg: "ES256", typ: "JWT", kid: "harness-issuer-v1" };
  var now = Math.floor(Date.now() / 1000);
  var payload = Object.assign(
    {
      iss: "payrit-harness-simulator",
      iat: now,
      exp: now + CREDENTIAL_TTL_SECONDS
    },
    claims
  );
  var signingInput =
    b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  var signature = crypto.sign("sha256", Buffer.from(signingInput, "utf8"), {
    key: issuerKey(),
    dsaEncoding: "ieee-p1363"
  });
  return {
    credential: signingInput + "." + b64url(signature),
    claims: payload,
    expiresAt: new Date(payload.exp * 1000).toISOString()
  };
}

function log(entry) {
  events.record(
    Object.assign({ origin: "simulated", kind: entry.ok === false ? "sim-error" : "sim" }, entry)
  );
}

function fail(label, status, message, detail) {
  log({
    ok: false,
    label: label,
    method: "POST",
    url: detail && detail.url ? detail.url : null,
    status: status,
    request: detail && detail.request ? httpc.forLog(detail.request) : null,
    response: { message: message, data: {} },
    note: "verified locally by the harness simulator"
  });
  return { ok: false, status: status, body: { message: message, data: {} } };
}

function enroll(input) {
  var body = input.body;
  var nonceRecord = input.nonceRecord;

  if (!nonceRecord) {
    return fail("Enroll device", 400, "Unknown nonce", { url: "/v1/enroll", request: body });
  }
  if (nonceRecord.consumedAt) {
    return fail("Enroll device", 409, "Nonce has already been used", {
      url: "/v1/enroll",
      request: body
    });
  }
  if (new Date(nonceRecord.expiresAt).getTime() < Date.now()) {
    return fail("Enroll device", 410, "Nonce has expired", { url: "/v1/enroll", request: body });
  }
  if (nonceRecord.platform !== body.platform) {
    return fail("Enroll device", 400, "Nonce was issued for platform " + nonceRecord.platform, {
      url: "/v1/enroll",
      request: body
    });
  }

  var check;
  if (body.platform === "android") {
    check = hardware.verifyAndroidChain(
      body.android ? body.android.certChain : null,
      body.publicKey,
      body.nonce
    );
    if (check.ok && !(body.android && body.android.integrityToken)) {
      check = { ok: false, reason: "Play Integrity token missing" };
    }
  } else {
    check = hardware.verifyIosAttestation(
      body.ios ? body.ios.attestationObject : null,
      body.publicKey,
      body.nonce
    );
  }

  if (!check.ok) {
    return fail("Enroll device", 422, check.reason, { url: "/v1/enroll", request: body });
  }

  var deviceId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  var instrumentId = crypto.randomUUID
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");
  var minted = mintCredential({
    sub: deviceId,
    customerId: body.customerId,
    paymentInstrumentId: instrumentId,
    platform: body.platform,
    currency: body.currency,
    pkFingerprint: hardware.fingerprintSpki(body.publicKey)
  });

  var response = {
    message: "Success",
    data: {
      deviceId: deviceId,
      paymentInstrumentId: instrumentId,
      customerId: body.customerId,
      platform: body.platform,
      currency: body.currency,
      status: "active",
      attestation: { verified: true, detail: check.reason },
      deviceCredential: minted.credential,
      credentialExpiresAt: minted.expiresAt
    }
  };

  log({
    label: "Enroll device",
    method: "POST",
    url: "/v1/enroll",
    status: 201,
    request: httpc.forLog(body),
    response: httpc.forLog(response),
    note: "attestation verified against the harness root: " + check.reason
  });

  return { ok: true, status: 201, body: response, claims: minted.claims };
}

function refresh(input) {
  var body = input.body;
  var device = input.device;
  var nonceRecord = input.nonceRecord;

  if (!device) {
    return fail("Refresh device credential", 404, "Device not found", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }
  if (device.revokedAt) {
    return fail("Refresh device credential", 403, "Device has been revoked", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }
  if (!nonceRecord) {
    return fail("Refresh device credential", 400, "Unknown nonce", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }
  if (nonceRecord.consumedAt) {
    return fail("Refresh device credential", 409, "Nonce has already been used", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }
  if (new Date(nonceRecord.expiresAt).getTime() < Date.now()) {
    return fail("Refresh device credential", 410, "Nonce has expired", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }
  if (!hardware.verifyNonceSignature(device.publicKey, body.nonce, body.signature)) {
    return fail("Refresh device credential", 401, "Signature did not prove possession of the device key", {
      url: "/v1/enroll/refresh",
      request: body
    });
  }

  var minted = mintCredential({
    sub: device.deviceId,
    customerId: device.customerId,
    paymentInstrumentId: device.paymentInstrumentId,
    platform: device.platform,
    currency: device.currency,
    pkFingerprint: device.fingerprint
  });

  var response = {
    message: "Success",
    data: {
      deviceId: device.deviceId,
      deviceCredential: minted.credential,
      credentialExpiresAt: minted.expiresAt,
      reattested: false
    }
  };

  log({
    label: "Refresh device credential",
    method: "POST",
    url: "/v1/enroll/refresh",
    status: 201,
    request: httpc.forLog(body),
    response: httpc.forLog(response),
    note: "ES256 proof of possession verified against the enrolled public key"
  });

  return { ok: true, status: 201, body: response, claims: minted.claims };
}

function revoke(input) {
  var device = input.device;
  if (!device) {
    return fail("Revoke device", 404, "Device not found", {
      url: "/v1/devices/" + input.deviceId + "/revoke"
    });
  }
  if (device.revokedAt) {
    return fail("Revoke device", 409, "Device is already revoked", {
      url: "/v1/devices/" + device.deviceId + "/revoke"
    });
  }
  var revokedAt = new Date().toISOString();
  var response = {
    message: "Success",
    data: { deviceId: device.deviceId, status: "revoked", revokedAt: revokedAt }
  };
  log({
    label: "Revoke device",
    method: "POST",
    url: "/v1/devices/" + device.deviceId + "/revoke",
    status: 201,
    response: response,
    note: "the credential can no longer be refreshed"
  });
  return { ok: true, status: 201, body: response, revokedAt: revokedAt };
}

function decodeCredential(credential) {
  try {
    var parts = String(credential).split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch (e) {
    return null;
  }
}

module.exports = {
  enroll: enroll,
  refresh: refresh,
  revoke: revoke,
  decodeCredential: decodeCredential,
  CREDENTIAL_TTL_SECONDS: CREDENTIAL_TTL_SECONDS
};

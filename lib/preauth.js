"use strict";

var crypto = require("crypto");
var fs = require("fs");
var path = require("path");

var pb = require("./protobuf.js");
var paths = require("./paths.js");

var ISSUER_KEY = path.join(paths.pkiDir(), "issuer.key");
var DEFAULT_TTL_SECONDS = 900;

function issuerKey() {
  if (!fs.existsSync(ISSUER_KEY)) {
    fs.mkdirSync(paths.pkiDir(), { recursive: true });
    var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    fs.writeFileSync(ISSUER_KEY, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  }
  return crypto.createPrivateKey(fs.readFileSync(ISSUER_KEY, "utf8"));
}

function issuerPublicKey() {
  return crypto.createPublicKey(issuerKey());
}

function build(fields) {
  return pb.encode({
    1: { type: "string", value: fields.authorizationId },
    2: { type: "string", value: fields.deviceId },
    3: { type: "string", value: fields.customerId },
    4: { type: "string", value: fields.accountId },
    5: { type: "uint", value: Number(fields.cap) },
    6: { type: "string", value: fields.currency },
    7: { type: "uint", value: fields.issuedAt },
    8: { type: "uint", value: fields.expiresAt }
  });
}

function sign(bytes) {
  return crypto.sign("sha256", bytes, { key: issuerKey(), dsaEncoding: "ieee-p1363" });
}

function verifySignature(bytes, signatureB64) {
  try {
    return crypto.verify(
      "sha256",
      bytes,
      { key: issuerPublicKey(), dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureB64, "base64")
    );
  } catch (e) {
    return false;
  }
}

function issue(input) {
  var now = Date.now();
  var ttl = (input.ttlSeconds || DEFAULT_TTL_SECONDS) * 1000;
  var authorizationId = crypto.randomUUID();
  var bytes = build({
    authorizationId: authorizationId,
    deviceId: input.deviceId,
    customerId: input.customerId,
    accountId: input.accountId,
    cap: input.cap,
    currency: input.currency,
    issuedAt: now,
    expiresAt: now + ttl
  });
  return {
    authorizationId: authorizationId,
    preAuthorization: bytes.toString("base64"),
    signature: sign(bytes).toString("base64"),
    cap: String(input.cap),
    currency: input.currency,
    expiresAt: new Date(now + ttl).toISOString()
  };
}

function parse(preAuthorizationB64) {
  if (!preAuthorizationB64) return null;
  var fields;
  try {
    fields = pb.decode(Buffer.from(preAuthorizationB64, "base64"));
  } catch (e) {
    return null;
  }
  function text(n) {
    return Buffer.isBuffer(fields[n]) ? fields[n].toString("utf8") : null;
  }
  return {
    authorizationId: text(1),
    deviceId: text(2),
    customerId: text(3),
    accountId: text(4),
    cap: typeof fields[5] === "number" ? fields[5] : null,
    currency: text(6),
    issuedAt: fields[7] || null,
    expiresAt: fields[8] || null
  };
}

module.exports = {
  issue: issue,
  parse: parse,
  sign: sign,
  verifySignature: verifySignature,
  issuerPublicKey: issuerPublicKey,
  DEFAULT_TTL_SECONDS: DEFAULT_TTL_SECONDS
};

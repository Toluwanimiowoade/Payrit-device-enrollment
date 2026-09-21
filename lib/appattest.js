"use strict";

var crypto = require("crypto");

var cbor = require("./cbor.js");
var x509 = require("./x509.js");

var APPLE_NONCE_OID = "1.2.840.113635.100.8.2";

var P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004", "hex");

function b64uToBuf(value) {
  var s = String(value).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function jwkToPem(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d) {
    throw new Error("expected a P-256 EC private JWK");
  }
  var d = b64uToBuf(jwk.d);
  var x = b64uToBuf(jwk.x);
  var y = b64uToBuf(jwk.y);
  if (d.length !== 32 || x.length !== 32 || y.length !== 32) {
    throw new Error("JWK coordinates must be 32 bytes each");
  }
  var der = Buffer.concat([
    Buffer.from("30770201010420", "hex"),
    d,
    Buffer.from("a00a06082a8648ce3d030107a14403420004", "hex"),
    x,
    y
  ]);
  var lines = der.toString("base64").match(/.{1,64}/g) || [];
  return "-----BEGIN EC PRIVATE KEY-----\n" + lines.join("\n") + "\n-----END EC PRIVATE KEY-----\n";
}

function derToPem(derB64, label) {
  var lines = String(derB64).replace(/\s+/g, "").match(/.{1,64}/g) || [];
  return "-----BEGIN " + label + "-----\n" + lines.join("\n") + "\n-----END " + label + "-----\n";
}

function pemToDerB64(pem) {
  return pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
}

function x963FromPrivatePem(privatePem) {
  var spki = crypto.createPublicKey(privatePem).export({ type: "spki", format: "der" });
  if (!spki.slice(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
    throw new Error("device key is not an uncompressed P-256 key");
  }
  return spki.slice(P256_SPKI_PREFIX.length - 1);
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function aaguidFor(production) {
  if (production) {
    var prod = Buffer.alloc(16, 0);
    Buffer.from("appattest", "utf8").copy(prod, 0);
    return prod;
  }
  return Buffer.from("appattestdevelop", "utf8");
}

function buildAuthData(options) {
  var rpIdHash = sha256(Buffer.from(options.appId, "utf8"));
  var flags = Buffer.from([0x40]);
  var counter = Buffer.alloc(4, 0);

  var aaguid = aaguidFor(options.production);
  var credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(options.keyId.length, 0);
  return Buffer.concat([rpIdHash, flags, counter, aaguid, credIdLen, options.keyId]);
}

function nonceExtensionDer(nonce) {
  if (nonce.length !== 32) throw new Error("nonce must be 32 bytes");
  return Buffer.concat([
    Buffer.from([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]),
    nonce
  ]);
}



function issueCredCert(input) {
  return x509.issue({
    subject: { CN: input.keyIdHex, O: input.teamId },
    issuerNameDer: x509.subjectNameDer(input.rootCertPem),
    subjectPublicKey: input.devicePrivatePem,
    issuerPrivateKey: input.rootPrivatePem,
    notAfter: new Date(Date.now() + 30 * 24 * 3600 * 1000),
    extensions: [{ oid: APPLE_NONCE_OID, value: input.extensionDer }]
  });
}

function buildAttestation(input) {
  var appId = input.teamId + "." + input.bundleId;
  var x963 = x963FromPrivatePem(input.devicePrivatePem);
  var keyId = sha256(x963);

  var authData = buildAuthData({ appId: appId, keyId: keyId, production: input.production });

  var spkiDer = crypto.createPublicKey(input.devicePrivatePem).export({ type: "spki", format: "der" });
  var challengeBytes = Buffer.from(input.challenge, "utf8");
  var clientDataHash = sha256(Buffer.concat([challengeBytes, sha256(spkiDer)]));
  var nonce = sha256(Buffer.concat([authData, clientDataHash]));

  var rootPrivatePem = input.rootPrivatePem || jwkToPem(input.rootJwk);
  var rootCertPem = input.rootCertPem || derToPem(input.rootCertDerB64, "CERTIFICATE");

  var credCertDer = issueCredCert({
    devicePrivatePem: input.devicePrivatePem,
    rootPrivatePem: rootPrivatePem,
    rootCertPem: rootCertPem,
    keyIdHex: keyId.toString("hex"),
    teamId: input.teamId,
    extensionDer: nonceExtensionDer(nonce)
  });

  var rootCertDer = Buffer.from(pemToDerB64(rootCertPem), "base64");

  var x5c = input.includeRootInChain === false ? [credCertDer] : [credCertDer, rootCertDer];

  var attestationObject = cbor.encode({
    fmt: "apple-appattest",
    attStmt: { x5c: x5c, receipt: input.receipt || Buffer.alloc(0) },
    authData: authData
  });

  return {
    attestationObject: attestationObject.toString("base64"),
    keyId: keyId.toString("base64"),
    appId: appId,
    nonce: nonce.toString("hex"),
    authData: authData.toString("base64"),
    credCertPem: x509.toPem(credCertDer)
  };
}

module.exports = {
  buildAttestation: buildAttestation,
  jwkToPem: jwkToPem,
  pemToDerB64: pemToDerB64
};

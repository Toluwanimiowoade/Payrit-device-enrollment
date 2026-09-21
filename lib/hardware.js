"use strict";

var crypto = require("crypto");
var fs = require("fs");
var path = require("path");

var x509 = require("./x509.js");
var paths = require("./paths.js");

var PKI_DIR = paths.pkiDir();
var ROOT_KEY = path.join(PKI_DIR, "root.key");
var ROOT_CERT = path.join(PKI_DIR, "root.pem");
var NONCE_PREFIX = "payrit-attest-";

function ensureCa() {
  if (fs.existsSync(ROOT_KEY) && fs.existsSync(ROOT_CERT)) {
    return { privatePem: fs.readFileSync(ROOT_KEY, "utf8"), certPem: fs.readFileSync(ROOT_CERT, "utf8") };
  }
  fs.mkdirSync(PKI_DIR, { recursive: true });
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  var certPem = x509.toPem(
    x509.selfSign({
      subject: { CN: "Payrit Harness Attestation Root", O: "payrit-test-harness" },
      privateKey: privatePem,
      isCa: true,
      notAfter: new Date(Date.now() + 3650 * 24 * 3600 * 1000)
    })
  );
  fs.writeFileSync(ROOT_KEY, privatePem, { mode: 0o600 });
  fs.writeFileSync(ROOT_CERT, certPem);
  return { privatePem: privatePem, certPem: certPem };
}

function createDeviceKey() {
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    spkiB64: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64")
  };
}

function issueAndroidChain(privatePem, nonce) {
  var ca = ensureCa();
  var leaf = x509.issue({
    subject: { CN: NONCE_PREFIX + nonce, O: "payrit-test-harness" },
    issuer: { CN: "Payrit Harness Attestation Root", O: "payrit-test-harness" },
    subjectPublicKey: privatePem,
    issuerPrivateKey: ca.privatePem,
    notAfter: new Date(Date.now() + 24 * 3600 * 1000)
  });
  return [leaf.toString("base64"), x509.fromPem(ca.certPem).toString("base64")];
}

function verifyAndroidChain(certChainB64, expectedSpkiB64, expectedNonce) {
  if (!Array.isArray(certChainB64) || certChainB64.length === 0) {
    return { ok: false, reason: "certChain is empty" };
  }
  var ca = ensureCa();
  var rootDer = x509.fromPem(ca.certPem);
  var leafDer;
  try {
    leafDer = Buffer.from(certChainB64[0], "base64");
  } catch (e) {
    return { ok: false, reason: "leaf certificate is not readable" };
  }

  if (!x509.verifySignedBy(leafDer, rootDer)) {
    return { ok: false, reason: "Chain does not terminate at a trusted root" };
  }

  var leaf;
  try {
    leaf = x509.parse(leafDer);
  } catch (e) {
    return { ok: false, reason: "leaf certificate is malformed" };
  }

  var cn = x509.commonName(leaf.subject);
  if (cn !== NONCE_PREFIX + expectedNonce) {
    return { ok: false, reason: "Attestation challenge does not match the issued nonce" };
  }
  if (leaf.spki.toString("base64") !== expectedSpkiB64) {
    return { ok: false, reason: "Attested key does not match the submitted publicKey" };
  }
  return { ok: true, reason: "hardware-backed key attested, nonce bound, chain trusted" };
}

function issueIosAttestation(privatePem, nonce, appId) {
  var statement = {
    fmt: "apple-appattest-harness",
    appId: appId || "com.payrit.harness",
    nonce: nonce,
    publicKeyFingerprint: fingerprint(privatePem)
  };
  var payload = Buffer.from(JSON.stringify(statement), "utf8");
  var signature = crypto.sign("sha256", payload, {
    key: crypto.createPrivateKey(privatePem),
    dsaEncoding: "ieee-p1363"
  });
  return Buffer.from(
    JSON.stringify({ statement: statement, signature: signature.toString("base64") }),
    "utf8"
  ).toString("base64");
}

function verifyIosAttestation(attestationB64, expectedSpkiB64, expectedNonce) {
  var parsed;
  try {
    parsed = JSON.parse(Buffer.from(attestationB64, "base64").toString("utf8"));
  } catch (e) {
    return { ok: false, reason: "attestationObject is not readable" };
  }
  if (!parsed || !parsed.statement || !parsed.signature) {
    return { ok: false, reason: "attestationObject is missing its statement or signature" };
  }
  if (parsed.statement.nonce !== expectedNonce) {
    return { ok: false, reason: "Attestation challenge does not match the issued nonce" };
  }
  if (parsed.statement.publicKeyFingerprint !== fingerprintSpki(expectedSpkiB64)) {
    return { ok: false, reason: "Attested key does not match the submitted publicKey" };
  }
  var publicKey;
  try {
    publicKey = crypto.createPublicKey({
      key: derB64ToSpkiPem(expectedSpkiB64),
      format: "pem",
      type: "spki"
    });
  } catch (e) {
    return { ok: false, reason: "publicKey is not a readable SubjectPublicKeyInfo" };
  }
  var verified = crypto.verify(
    "sha256",
    Buffer.from(JSON.stringify(parsed.statement), "utf8"),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(parsed.signature, "base64")
  );
  if (!verified) return { ok: false, reason: "attestation signature did not verify" };
  return { ok: true, reason: "App Attest statement verified, nonce bound" };
}

function fingerprint(privatePem) {
  var spki = crypto.createPublicKey(privatePem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spki).digest("base64");
}

function fingerprintSpki(spkiB64) {
  return crypto.createHash("sha256").update(Buffer.from(spkiB64, "base64")).digest("base64");
}

function derB64ToSpkiPem(b64) {
  var lines = b64.match(/.{1,64}/g) || [];
  return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----\n";
}

function signNonce(privatePem, nonce) {
  return crypto
    .sign("sha256", Buffer.from(nonce, "utf8"), {
      key: crypto.createPrivateKey(privatePem),
      dsaEncoding: "ieee-p1363"
    })
    .toString("base64");
}

function verifyNonceSignature(spkiB64, nonce, signatureB64) {
  try {
    var key = crypto.createPublicKey({ key: derB64ToSpkiPem(spkiB64), format: "pem", type: "spki" });
    return crypto.verify(
      "sha256",
      Buffer.from(nonce, "utf8"),
      { key: key, dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureB64, "base64")
    );
  } catch (e) {
    return false;
  }
}

module.exports = {
  createDeviceKey: createDeviceKey,
  issueAndroidChain: issueAndroidChain,
  issueIosAttestation: issueIosAttestation,
  verifyAndroidChain: verifyAndroidChain,
  verifyIosAttestation: verifyIosAttestation,
  signNonce: signNonce,
  verifyNonceSignature: verifyNonceSignature,
  fingerprint: fingerprint,
  fingerprintSpki: fingerprintSpki
};

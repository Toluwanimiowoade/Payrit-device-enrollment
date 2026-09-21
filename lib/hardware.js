"use strict";

var crypto = require("crypto");
var fs = require("fs");
var os = require("os");
var path = require("path");
var execFileSync = require("child_process").execFileSync;

var PKI_DIR = path.join(__dirname, "..", ".harness-pki");
var ROOT_KEY = path.join(PKI_DIR, "root.key");
var ROOT_CERT = path.join(PKI_DIR, "root.pem");
var NONCE_PREFIX = "payrit-attest-";

var opensslChecked = false;
var opensslAvailable = false;

function haveOpenssl() {
  if (opensslChecked) return opensslAvailable;
  opensslChecked = true;
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    opensslAvailable = true;
  } catch (e) {
    opensslAvailable = false;
  }
  return opensslAvailable;
}

function tmpPath(suffix) {
  return path.join(os.tmpdir(), "payrit-harness-" + crypto.randomBytes(8).toString("hex") + suffix);
}

function cleanup(files) {
  files.forEach(function (f) {
    try {
      fs.unlinkSync(f);
    } catch (e) {
    }
  });
}

function ensureCa() {
  if (!haveOpenssl()) return false;
  if (fs.existsSync(ROOT_KEY) && fs.existsSync(ROOT_CERT)) return true;
  fs.mkdirSync(PKI_DIR, { recursive: true });
  var conf = tmpPath(".cnf");
  fs.writeFileSync(
    conf,
    [
      "[req]",
      "distinguished_name = dn",
      "x509_extensions = v3_ca",
      "prompt = no",
      "[dn]",
      "CN = Payrit Harness Attestation Root",
      "O = payrit-test-harness",
      "[v3_ca]",
      "basicConstraints = critical,CA:TRUE",
      "keyUsage = critical,keyCertSign,cRLSign",
      ""
    ].join("\n")
  );
  try {
    execFileSync(
      "openssl",
      [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "3650", "-config", conf,
        "-keyout", ROOT_KEY, "-out", ROOT_CERT
      ],
      { stdio: "ignore" }
    );
    return true;
  } catch (e) {
    return false;
  } finally {
    cleanup([conf]);
  }
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
  if (!ensureCa()) return null;
  var keyFile = tmpPath(".key");
  var csrFile = tmpPath(".csr");
  var leafFile = tmpPath(".pem");
  var confFile = tmpPath(".cnf");
  try {
    fs.writeFileSync(keyFile, privatePem, { mode: 0o600 });
    fs.writeFileSync(
      confFile,
      [
        "[req]",
        "distinguished_name = dn",
        "prompt = no",
        "[dn]",

        "CN = " + NONCE_PREFIX + nonce,
        "O = payrit-test-harness",
        ""
      ].join("\n")
    );
    execFileSync("openssl", ["req", "-new", "-key", keyFile, "-config", confFile, "-out", csrFile], {
      stdio: "ignore"
    });
    execFileSync(
      "openssl",
      [
        "x509", "-req", "-in", csrFile, "-CA", ROOT_CERT, "-CAkey", ROOT_KEY,
        "-days", "1", "-out", leafFile
      ],
      { stdio: "ignore" }
    );
    return [pemToDerB64(fs.readFileSync(leafFile, "utf8")), pemToDerB64(fs.readFileSync(ROOT_CERT, "utf8"))];
  } catch (e) {
    return null;
  } finally {
    cleanup([keyFile, csrFile, leafFile, confFile]);
  }
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
  return Buffer.concat([
    Buffer.from(JSON.stringify({ statement: statement, signature: signature.toString("base64") }), "utf8")
  ]).toString("base64");
}

function fingerprint(privatePem) {
  var spki = crypto.createPublicKey(privatePem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spki).digest("base64");
}

function fingerprintSpki(spkiB64) {
  return crypto.createHash("sha256").update(Buffer.from(spkiB64, "base64")).digest("base64");
}

function pemToDerB64(pem) {
  var body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return body;
}

function derB64ToPem(b64) {
  var lines = b64.match(/.{1,64}/g) || [];
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") + "\n-----END CERTIFICATE-----\n";
}

function verifyAndroidChain(certChainB64, expectedSpkiB64, expectedNonce) {
  if (!Array.isArray(certChainB64) || certChainB64.length === 0) {
    return { ok: false, reason: "certChain is empty" };
  }
  if (!ensureCa()) {
    return { ok: false, reason: "openssl unavailable, cannot verify a chain" };
  }
  var leafFile = tmpPath(".pem");
  try {
    fs.writeFileSync(leafFile, derB64ToPem(certChainB64[0]));
    try {
      execFileSync("openssl", ["verify", "-CAfile", ROOT_CERT, leafFile], { stdio: "ignore" });
    } catch (e) {
      return { ok: false, reason: "Chain does not terminate at a trusted root" };
    }
    var subject = execFileSync("openssl", ["x509", "-in", leafFile, "-noout", "-subject"], {
      encoding: "utf8"
    });
    if (subject.indexOf(NONCE_PREFIX + expectedNonce) === -1) {
      return { ok: false, reason: "Attestation challenge does not match the issued nonce" };
    }
    var leafSpki = execFileSync("openssl", ["x509", "-in", leafFile, "-noout", "-pubkey"], {
      encoding: "utf8"
    });
    if (pemToDerB64(leafSpki) !== expectedSpkiB64) {
      return { ok: false, reason: "Attested key does not match the submitted publicKey" };
    }
    return { ok: true, reason: "hardware-backed key attested, nonce bound, chain trusted" };
  } catch (e) {
    return { ok: false, reason: "chain verification failed: " + e.message };
  } finally {
    cleanup([leafFile]);
  }
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
    publicKey = crypto.createPublicKey({ key: derB64ToSpkiPem(expectedSpkiB64), format: "pem", type: "spki" });
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
    var key = crypto.createPublicKey({
      key: derB64ToSpkiPem(spkiB64),
      format: "pem",
      type: "spki"
    });
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

function derB64ToSpkiPem(b64) {
  var lines = b64.match(/.{1,64}/g) || [];
  return "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----\n";
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
  fingerprintSpki: fingerprintSpki,
  haveOpenssl: haveOpenssl
};

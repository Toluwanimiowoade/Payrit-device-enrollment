"use strict";

var crypto = require("crypto");

var keyattestation = require("./keyattestation.js");
var x509 = require("./x509.js");
var appattest = require("./appattest.js");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}



function challengeBytes(input) {
  var nonceBytes = Buffer.from(input.challenge, "utf8");
  if (input.binding === "raw") return nonceBytes;
  var spkiDer = crypto.createPublicKey(input.devicePrivatePem).export({ type: "spki", format: "der" });
  return sha256(Buffer.concat([nonceBytes, sha256(spkiDer)]));
}

function issueChain(input) {
  var rootPem = input.rootPrivatePem || appattest.jwkToPem(input.rootJwk);
  var challenge = challengeBytes(input);
  var extension = keyattestation.buildExtension({
    challenge: challenge,
    packageName: input.packageName,
    packageVersion: input.packageVersion || 1,
    signatureDigests: [input.signingCertDigest],
    attestationVersion: input.attestationVersion,
    securityLevel: input.securityLevel,
    appIdLocation: input.appIdLocation
  });

  var leaf = x509.issue({
    subject: { CN: "Android Keystore Key" },
    issuerNameDer: x509.subjectNameDer(input.rootCertPem),
    subjectPublicKey: input.devicePrivatePem,
    issuerPrivateKey: rootPem,
    notAfter: new Date(Date.now() + 30 * 24 * 3600 * 1000),
    extensions: [{ oid: keyattestation.OID, value: extension }]
  });

  return {
    certChain: [leaf.toString("base64"), x509.fromPem(input.rootCertPem).toString("base64")],
    challenge: challenge.toString("hex"),
    leafPem: x509.toPem(leaf),
    extensionBytes: extension.length
  };
}

module.exports = { issueChain: issueChain, challengeBytes: challengeBytes };

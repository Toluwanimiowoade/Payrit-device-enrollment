"use strict";

var crypto = require("crypto");
var fs = require("fs");
var os = require("os");
var path = require("path");
var execFileSync = require("child_process").execFileSync;

var keyattestation = require("./keyattestation.js");
var appattest = require("./appattest.js");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function tmpPath(suffix) {
  return path.join(os.tmpdir(), "payrit-android-" + crypto.randomBytes(8).toString("hex") + suffix);
}

function cleanup(files) {
  files.forEach(function (f) {
    try {
      fs.unlinkSync(f);
    } catch (e) {
    }
  });
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

  var devKeyFile = tmpPath(".key");
  var rootKeyFile = tmpPath("-root.key");
  var rootCertFile = tmpPath("-root.pem");
  var csrFile = tmpPath(".csr");
  var leafFile = tmpPath(".pem");
  var confFile = tmpPath(".cnf");

  try {
    fs.writeFileSync(devKeyFile, input.devicePrivatePem, { mode: 0o600 });
    fs.writeFileSync(rootKeyFile, rootPem, { mode: 0o600 });
    fs.writeFileSync(rootCertFile, input.rootCertPem);
    fs.writeFileSync(
      confFile,
      [
        "[req]",
        "distinguished_name = dn",
        "prompt = no",
        "[dn]",
        "CN = Android Keystore Key",
        "[leaf]",
        "basicConstraints = critical,CA:FALSE",
        "keyUsage = critical,digitalSignature",
        keyattestation.OID + " = DER:" + extension.toString("hex").toUpperCase(),
        ""
      ].join("\n")
    );

    execFileSync("openssl", ["req", "-new", "-key", devKeyFile, "-config", confFile, "-out", csrFile], {
      stdio: "ignore"
    });
    execFileSync(
      "openssl",
      [
        "x509", "-req", "-in", csrFile,
        "-CA", rootCertFile, "-CAkey", rootKeyFile,
        "-set_serial", "0x" + crypto.randomBytes(8).toString("hex"),
        "-days", "30",
        "-extfile", confFile, "-extensions", "leaf",
        "-out", leafFile
      ],
      { stdio: "ignore" }
    );

    var leafPem = fs.readFileSync(leafFile, "utf8");
    var chain = [appattest.pemToDerB64(leafPem), appattest.pemToDerB64(input.rootCertPem)];
    return {
      certChain: chain,
      challenge: challenge.toString("hex"),
      leafPem: leafPem,
      extensionBytes: extension.length
    };
  } finally {
    cleanup([devKeyFile, rootKeyFile, rootCertFile, csrFile, leafFile, confFile]);
  }
}

module.exports = { issueChain: issueChain, challengeBytes: challengeBytes };

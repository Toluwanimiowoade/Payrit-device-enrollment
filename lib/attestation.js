"use strict";

var state = require("./state.js");
var hardware = require("./hardware.js");
var appattest = require("./appattest.js");
var androidattest = require("./androidattest.js");

function b64url(value) {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function integrityToken(nonce) {
  var header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  var payload = b64url(
    JSON.stringify({
      requestDetails: { nonce: nonce, timestampMillis: String(Date.now()) },
      appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED" },
      deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
      harness: true
    })
  );
  return header + "." + payload + ".harness-unsigned";
}

function buildAndroid(deviceKey, nonce, live) {
  var config = state.androidAttestConfig();

  if (config.ready && live) {
    var issued = androidattest.issueChain({
      devicePrivatePem: deviceKey.privatePem,
      challenge: nonce,
      rootJwk: config.rootJwk,
      rootCertPem: config.rootCertPem,
      packageName: config.packageName,
      signingCertDigest: config.signingCertDigest,
      binding: config.binding,
      appIdLocation: config.appIdLocation
    });
    return {
      attestation: { android: { certChain: issued.certChain, integrityToken: integrityToken(nonce) } },
      detail: {
        format: "android-key-attestation",
        packageName: config.packageName,
        attestationChallenge: issued.challenge,
        binding: config.binding,
        appIdLocation: config.appIdLocation
      },
      note: "P-256 key generated, Android Key Attestation chain signed by the test root"
    };
  }

  var chain = hardware.issueAndroidChain(deviceKey.privatePem, nonce);
  return {
    attestation: { android: { certChain: chain, integrityToken: integrityToken(nonce) } },
    detail: null,
    note: "P-256 key generated, Android Key Attestation stand-in chain signed over the nonce"
  };
}

function buildIos(deviceKey, nonce, live) {
  var config = state.appAttestConfig();

  if (config.ready && live) {
    var built = appattest.buildAttestation({
      devicePrivatePem: deviceKey.privatePem,
      challenge: nonce,
      teamId: config.teamId,
      bundleId: config.bundleId,
      rootJwk: config.rootJwk,
      rootCertPem: config.rootCertPem,
      production: config.production,
      includeRootInChain: config.includeRootInChain
    });
    return {
      attestation: { ios: { attestationObject: built.attestationObject } },
      detail: {
        format: "apple-appattest",
        appId: built.appId,
        keyId: built.keyId,
        attestationNonce: built.nonce,
        aaguid: config.production ? "appattest" : "appattestdevelop"
      },
      note: "P-256 key generated, real-format App Attest object signed by the test root"
    };
  }

  return {
    attestation: {
      ios: { attestationObject: hardware.issueIosAttestation(deviceKey.privatePem, nonce, state.appId()) }
    },
    detail: null,
    note: "P-256 key generated, App Attest stand-in statement signed over the nonce"
  };
}

function build(platform, deviceKey, nonce, mode) {
  var live = mode === "live";
  return platform === "android" ? buildAndroid(deviceKey, nonce, live) : buildIos(deviceKey, nonce, live);
}

module.exports = { build: build, integrityToken: integrityToken };

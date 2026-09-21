"use strict";

var httpc = require("./lib/http.js");
var hardware = require("./lib/hardware.js");
var simulator = require("./lib/simulator.js");
var payrit = require("./lib/payrit.js");
var state = require("./lib/state.js");

var SPEC_URL = "https://payrit-ble.mintlify.site/api-reference/openapi.yaml";

var GREEN = "\x1b[32m";
var RED = "\x1b[31m";
var YELLOW = "\x1b[33m";
var OFF = "\x1b[0m";

var passed = 0;
var failed = 0;
var skipped = 0;

function ok(name, condition, detail) {
  if (condition) {
    passed += 1;
    console.log("  " + GREEN + "ok" + OFF + "   " + name);
  } else {
    failed += 1;
    console.log("  " + RED + "FAIL" + OFF + " " + name + (detail ? "\n         " + detail : ""));
  }
}

function skip(name, why) {
  skipped += 1;
  console.log("  " + YELLOW + "skip" + OFF + " " + name + "  (" + why + ")");
}

function group(title) {
  console.log("\n" + title);
}

function isoIn(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function nonceRecord(nonce, platform, extra) {
  return Object.assign(
    {
      platform: platform || "android",
      issuedAt: new Date().toISOString(),
      expiresAt: isoIn(300),
      consumedAt: null
    },
    extra || {}
  );
}

function checkSpec() {
  group("Published contract (" + SPEC_URL + ")");
  return httpc.request(SPEC_URL, { method: "GET" }).then(
    function (res) {
      ok("spec is reachable", res.status === 200, "got " + res.status);
      var text = res.text || "";

      ["/v1/enroll/challenge", "/v1/enroll", "/v1/enroll/refresh", "/v1/devices/{id}/revoke"].forEach(
        function (path) {
          ok("documents " + path, text.indexOf(path + ":") !== -1);
        }
      );

      ok(
        "EnrollDeviceDto requires customerId, platform, publicKey, nonce",
        ["customerId", "platform", "publicKey", "nonce"].every(function (f) {
          return text.indexOf(f) !== -1;
        })
      );

      ok("EnrollDeviceDto no longer carries currency", text.indexOf("currency") === -1);
      ok("refresh is proved with a raw ES256 (ieee-p1363) signature over the nonce", /ieee-p1363/.test(text));
      ok("device key is a P-256 SubjectPublicKeyInfo", /P-256 SubjectPublicKeyInfo/.test(text));
      ok(
        "android attestation carries certChain + integrityToken",
        text.indexOf("certChain") !== -1 && text.indexOf("integrityToken") !== -1
      );
      ok("ios attestation carries attestationObject", text.indexOf("attestationObject") !== -1);
      ok("auth is the x-api-key header", /name: x-api-key/.test(text));
      ok("devices:write scope exists", text.indexOf("devices:write") !== -1);

      var base = state.apiBase();
      ok(
        "harness points at a server the spec lists",
        text.indexOf(base.replace(/^https?:\/\//, "")) !== -1,
        "harness base: " + base
      );
    },
    function (err) {
      ok("spec is reachable", false, err.message);
    }
  );
}

function checkHardware() {
  group("Device key and attestation (the SDK's half)");

  var key = hardware.createDeviceKey();
  ok("generates a P-256 keypair", /BEGIN PRIVATE KEY/.test(key.privatePem));
  ok(
    "publicKey is a base64 SubjectPublicKeyInfo of the expected length",
    key.spkiB64.length === 124,
    "got " + key.spkiB64.length
  );
  ok("the private key never appears in the SPKI blob", key.spkiB64.indexOf("PRIVATE") === -1);

  var nonce = "test-nonce-" + Date.now();

  if (!hardware.haveOpenssl()) {
    skip("android attestation chain", "openssl not on PATH");
  } else {
    var chain = hardware.issueAndroidChain(key.privatePem, nonce);
    ok("builds an attestation chain, leaf first", Array.isArray(chain) && chain.length >= 2);
    ok(
      "chain verifies: trusted root, nonce bound, key matches",
      hardware.verifyAndroidChain(chain, key.spkiB64, nonce).ok
    );
    ok(
      "chain is rejected for a different nonce",
      !hardware.verifyAndroidChain(chain, key.spkiB64, "some-other-nonce").ok
    );
    var other = hardware.createDeviceKey();
    ok(
      "chain is rejected when it does not certify the submitted key",
      !hardware.verifyAndroidChain(chain, other.spkiB64, nonce).ok
    );
    ok("an empty chain is rejected", !hardware.verifyAndroidChain([], key.spkiB64, nonce).ok);
  }

  var ios = hardware.issueIosAttestation(key.privatePem, nonce, "com.payrit.harness");
  ok("builds an App Attest statement", typeof ios === "string" && ios.length > 0);
  ok("App Attest statement verifies", hardware.verifyIosAttestation(ios, key.spkiB64, nonce).ok);
  ok(
    "App Attest statement is rejected for a different nonce",
    !hardware.verifyIosAttestation(ios, key.spkiB64, "other").ok
  );
  ok("garbage attestationObject is rejected", !hardware.verifyIosAttestation("bm90LWNib3I=", key.spkiB64, nonce).ok);

  var sig = hardware.signNonce(key.privatePem, nonce);
  ok(
    "ES256 signature over the nonce is 64 raw bytes (ieee-p1363)",
    Buffer.from(sig, "base64").length === 64,
    "got " + Buffer.from(sig, "base64").length
  );
  ok("signature verifies against the enrolled public key", hardware.verifyNonceSignature(key.spkiB64, nonce, sig));
  ok("signature is rejected over a different nonce", !hardware.verifyNonceSignature(key.spkiB64, "different", sig));
  var stranger = hardware.createDeviceKey();
  ok(
    "signature is rejected against another device's key",
    !hardware.verifyNonceSignature(stranger.spkiB64, nonce, sig)
  );
}

function checkSimulator() {
  group("Credential lifecycle (the backend's half, simulated)");

  var key = hardware.createDeviceKey();
  var nonce = "sim-nonce-" + Date.now();
  var body = {
    customerId: "11111111-2222-3333-4444-555555555555",
    platform: "ios",
    publicKey: key.spkiB64,
    nonce: nonce,
    currency: "NGN",
    ios: { attestationObject: hardware.issueIosAttestation(key.privatePem, nonce, "com.payrit.harness") }
  };

  var enrolled = simulator.enroll({
    body: body,
    nonceRecord: nonceRecord(nonce, "ios")
  });
  ok("enrollment succeeds and returns 201", enrolled.ok && enrolled.status === 201);
  ok("returns a paymentInstrumentId", !!(enrolled.body && enrolled.body.data.paymentInstrumentId));
  ok("returns a device credential", !!(enrolled.body && enrolled.body.data.deviceCredential));

  var claims = simulator.decodeCredential(enrolled.body.data.deviceCredential);
  ok("credential decodes to claims about this device", !!claims && claims.sub === enrolled.body.data.deviceId);
  ok("credential binds the customer", claims.customerId === body.customerId);
  ok("credential is short-lived", claims.exp - claims.iat === simulator.CREDENTIAL_TTL_SECONDS);

  ok(
    "a consumed nonce cannot be reused",
    simulator.enroll({
      body: body,
      nonceRecord: nonceRecord(nonce, "ios", { consumedAt: new Date().toISOString() })
    }).status === 409
  );

  ok(
    "an expired nonce is refused",
    simulator.enroll({
      body: body,
      nonceRecord: nonceRecord(nonce, "ios", { expiresAt: isoIn(-1) })
    }).status === 410
  );

  ok(
    "an unknown nonce is refused",
    simulator.enroll({ body: body, nonceRecord: null }).status === 400
  );

  ok(
    "a nonce issued for another platform is refused",
    simulator.enroll({
      body: body,
      nonceRecord: nonceRecord(nonce, "android")
    }).status === 400
  );

  var tampered = JSON.parse(JSON.stringify(body));
  tampered.publicKey = hardware.createDeviceKey().spkiB64;
  ok(
    "a publicKey the attestation does not cover is refused with 422",
    simulator.enroll({
      body: tampered,
      nonceRecord: nonceRecord(nonce, "ios")
    }).status === 422
  );

  var device = {
    deviceId: enrolled.body.data.deviceId,
    customerId: body.customerId,
    paymentInstrumentId: enrolled.body.data.paymentInstrumentId,
    platform: "ios",
    currency: "NGN",
    publicKey: key.spkiB64,
    privatePem: key.privatePem,
    fingerprint: hardware.fingerprint(key.privatePem),
    revokedAt: null
  };

  var rNonce = "refresh-nonce-" + Date.now();
  var good = simulator.refresh({
    body: { deviceId: device.deviceId, nonce: rNonce, signature: hardware.signNonce(key.privatePem, rNonce) },
    device: device,
    nonceRecord: nonceRecord(rNonce, "ios")
  });
  ok("refresh succeeds with a valid proof of possession", good.ok && good.status === 201);
  ok("refresh does not re-attest", good.body.data.reattested === false);
  ok("refresh issues a different credential", good.body.data.deviceCredential !== enrolled.body.data.deviceCredential);

  ok(
    "refresh is refused when another key signed the nonce",
    simulator.refresh({
      body: {
        deviceId: device.deviceId,
        nonce: rNonce,
        signature: hardware.signNonce(hardware.createDeviceKey().privatePem, rNonce)
      },
      device: device,
      nonceRecord: nonceRecord(rNonce, "ios")
    }).status === 401
  );

  ok(
    "refresh is refused for an unknown device",
    simulator.refresh({ body: {}, device: null, nonceRecord: nonceRecord(rNonce, "ios") }).status === 404
  );

  var revoked = simulator.revoke({ device: device, deviceId: device.deviceId });
  ok("revoke succeeds", revoked.ok && revoked.body.data.status === "revoked");

  device.revokedAt = revoked.revokedAt;
  ok(
    "a revoked device cannot refresh",
    simulator.refresh({
      body: { deviceId: device.deviceId, nonce: rNonce, signature: hardware.signNonce(key.privatePem, rNonce) },
      device: device,
      nonceRecord: nonceRecord(rNonce, "ios")
    }).status === 403
  );
  ok("revoking twice is refused", simulator.revoke({ device: device, deviceId: device.deviceId }).status === 409);
}

function checkLiveReachable() {
  group("Live deployment (" + state.apiBase() + ")");
  return payrit.hello().then(
    function (r) {
      ok("GET /v1 answers", r.ok, "status " + r.status);
    },
    function (err) {
      ok("GET /v1 answers", false, err.message);
    }
  );
}

function checkAuthRefusals() {
  return payrit
    .enrollChallenge(null, "android")
    .then(function (r) {
      ok("a nonce request with no key is refused with 401", r.status === 401, "got " + r.status);
      return payrit.enrollChallenge("pk_test_definitely_not_a_key", "android");
    })
    .then(function (r) {
      ok("a nonce request with a bogus key is refused with 401", r.status === 401, "got " + r.status);
    });
}

function checkLiveFlow() {
  group("Live sequence with a throwaway account");
  var stamp = Date.now();
  var key = null;
  var customerId = null;

  return payrit
    .registerAccount({ name: "Harness suite " + stamp, email: "suite+" + stamp + "@example.test" })
    .then(function (r) {
      ok("POST /v1/accounts creates an account", r.status === 201 && !!r.json.data._id, "got " + r.status);
      return payrit.generateFirstKey(r.json.data._id, { name: "suite key", environment: "test" });
    })
    .then(function (r) {
      ok("the bootstrap key mints with no x-api-key", r.status === 201 && !!r.json.data.key, "got " + r.status);
      ok("the bootstrap key carries every scope", (r.json.data.scopes || []).indexOf("devices:write") !== -1);
      key = r.json.data.key;
      return payrit.createCustomer(key, { firstName: "Suite", lastName: "Runner" });
    })
    .then(function (r) {
      ok("POST /v1/customers creates a customer", r.status === 201 && !!r.json.data._id, "got " + r.status);
      customerId = r.json.data._id;
      return payrit.enrollChallenge(key, "android");
    })
    .then(function (r) {
      ok("POST /v1/enroll/challenge returns a nonce", r.status === 201 && !!r.json.data.nonce, "got " + r.status);
      ok("the nonce carries an expiry", !!r.json.data.expiresAt);
      var nonce = r.json.data.nonce;
      var deviceKey = hardware.createDeviceKey();
      return payrit.enroll(key, {
        customerId: customerId,
        platform: "android",
        publicKey: deviceKey.spkiB64,
        nonce: nonce,
        currency: "NGN",
        android: {
          certChain: hardware.issueAndroidChain(deviceKey.privatePem, nonce) || ["not-a-cert"],
          integrityToken: "harness.suite.token"
        }
      });
    })
    .then(function (r) {
      ok("POST /v1/enroll refuses a self-signed attestation with 422", r.status === 422, "got " + r.status);
      ok(
        "and says why",
        /trusted root|attestation|integrity/i.test((r.json && r.json.message) || ""),
        (r.json && r.json.message) || ""
      );
    });
}

console.log("\nPayrit device-enrollment harness - test suite");

var wantFlow = process.argv.indexOf("--flow") !== -1;

checkSpec()
  .then(function () {
    checkHardware();
    checkSimulator();
    return checkLiveReachable();
  })
  .then(checkAuthRefusals)
  .then(function () {
    if (!wantFlow) {
      group("Live sequence with a throwaway account");
      skip("full walkthrough", "pass --flow to register a throwaway account and run it");
      return null;
    }
    return checkLiveFlow();
  })
  .then(function () {
    console.log(
      "\n" + passed + " passed, " + failed + " failed" + (skipped ? ", " + skipped + " skipped" : "") + "\n"
    );
    process.exit(failed === 0 ? 0 : 1);
  })
  .catch(function (err) {
    console.error("\nsuite crashed: " + err.stack + "\n");
    process.exit(1);
  });

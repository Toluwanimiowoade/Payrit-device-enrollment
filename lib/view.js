"use strict";

var state = require("./state.js");
var hardware = require("./hardware.js");
var simulator = require("./simulator.js");
var credential = require("./credential.js");

function keyView(active) {
  if (!active) return { present: false };
  return {
    present: true,
    prefix: state.keyPrefix(active.key),
    source: active.source,
    name: active.name,
    environment: active.environment,
    scopes: active.scopes,
    live: state.isLiveKey(active.key),
    liveAllowed: state.liveKeyAllowed()
  };
}

function attestationView() {
  var apple = state.appAttestConfig();
  var android = state.androidAttestConfig();
  return {
    appAttest: {
      ready: apple.ready,
      missing: apple.missing,
      teamId: apple.teamId || null,
      bundleId: apple.bundleId || null,
      production: apple.production
    },
    androidAttest: {
      ready: android.ready,
      missing: android.missing,
      packageName: android.packageName || null,
      binding: android.binding,
      appIdLocation: android.appIdLocation
    }
  };
}

function deviceView(d) {
  return {
    deviceId: d.deviceId,
    paymentInstrumentId: d.paymentInstrumentId,
    apiDeviceId: d.apiDeviceId || null,
    customerId: d.customerId,
    platform: d.platform,
    currency: d.currency,
    origin: d.origin,
    fingerprint: d.fingerprint,
    publicKey: d.publicKey,
    createdAt: d.createdAt,
    revokedAt: d.revokedAt,
    credential: d.credential,
    credentialClaims: d.credential ? credential.claims(d.credential) : null,
    credentialExpiresAt: d.credentialExpiresAt,
    refreshCount: d.refreshCount || 0
  };
}

function publicView() {
  var runtime = state.readRuntime();
  var attestation = attestationView();
  return {
    apiBase: state.apiBase(),
    appId: state.appId(),
    openssl: hardware.haveOpenssl(),
    appAttest: attestation.appAttest,
    androidAttest: attestation.androidAttest,
    credentialTtlSeconds: simulator.CREDENTIAL_TTL_SECONDS,
    key: keyView(state.activeKey()),
    account: runtime.account,
    customer: runtime.customer,
    devices: runtime.devices.map(deviceView)
  };
}

module.exports = { publicView: publicView, deviceView: deviceView };

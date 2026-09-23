"use strict";

var state = require("./state.js");
var simulator = require("./simulator.js");
var credential = require("./credential.js");
var ble = require("./ble.js");

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

function authorizationView(d) {
  var auth = d.authorization;
  if (!auth) return null;
  var spent = (d.chain || []).reduce(function (total, entry) {
    var decoded = ble.decodeRecord(entry.record);
    return total + decoded.transaction.amount;
  }, 0);
  var cap = Number(auth.cap);
  return {
    authorizationId: auth.authorizationId,
    cap: cap,
    currency: auth.currency,
    status: auth.status,
    origin: auth.origin,
    expiresAt: auth.expiresAt,
    spent: spent,
    remaining: cap - spent
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
    refreshCount: d.refreshCount || 0,
    authorization: authorizationView(d),
    chainLength: Array.isArray(d.chain) ? d.chain.length : 0
  };
}

function publicView() {
  var runtime = state.readRuntime();
  var attestation = attestationView();
  return {
    apiBase: state.apiBase(),
    appId: state.appId(),
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

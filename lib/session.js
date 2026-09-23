"use strict";

var crypto = require("crypto");

var state = require("./state.js");
var hardware = require("./hardware.js");
var credential = require("./credential.js");

var NONCE_KEEP_MS = 10 * 60 * 1000;

function pruneNonces(runtime) {
  var now = Date.now();
  Object.keys(runtime.nonces).forEach(function (nonce) {
    var rec = runtime.nonces[nonce];
    if (new Date(rec.expiresAt).getTime() < now - NONCE_KEEP_MS) delete runtime.nonces[nonce];
  });
  return runtime;
}

function recordNonce(nonce, platform, expiresAt) {
  var runtime = pruneNonces(state.readRuntime());
  runtime.nonces[nonce] = {
    platform: platform,
    issuedAt: new Date().toISOString(),
    expiresAt: expiresAt,
    consumedAt: null
  };
  state.writeRuntime(runtime);
  return runtime.nonces[nonce];
}

function nonceRecord(nonce) {
  return state.readRuntime().nonces[nonce] || null;
}

function consumeNonce(nonce) {
  var runtime = state.readRuntime();
  if (runtime.nonces[nonce]) {
    runtime.nonces[nonce].consumedAt = new Date().toISOString();
    state.writeRuntime(runtime);
  }
}

function findDevice(runtime, deviceId) {
  var found = null;
  runtime.devices.forEach(function (d) {
    if (d.deviceId === deviceId) found = d;
  });
  return found;
}

function saveDevice(input) {
  var data = input.data;
  var runtime = state.readRuntime();

  var parsed = credential.parse(data.deviceCredential);
  var record = {
    deviceId:
      data.deviceId ||
      (parsed && parsed.deviceId) ||
      data._id ||
      data.id ||
      crypto.randomBytes(16).toString("hex"),
    paymentInstrumentId: data.paymentInstrumentId || null,
    customerId: data.customerId || input.customerId,
    platform: input.platform,
    currency: input.currency,
    origin: input.origin,

    apiDeviceId:
      data.paymentInstrumentId || data.deviceId || (parsed && parsed.paymentInstrumentId) || null,
    publicKey: input.deviceKey.spkiB64,
    privatePem: input.deviceKey.privatePem,
    fingerprint: hardware.fingerprint(input.deviceKey.privatePem),
    createdAt: new Date().toISOString(),
    revokedAt: null,
    refreshCount: 0,
    credential: data.deviceCredential || null,
    credentialExpiresAt:
      data.credentialExpiresAt || data.expiresAt || (parsed && parsed.expiresAt) || null
  };
  runtime.devices.push(record);
  state.writeRuntime(runtime);
  return record;
}

function applyRefresh(deviceId, data) {
  var runtime = state.readRuntime();
  var device = findDevice(runtime, deviceId);
  if (!device) return;
  var parsed = credential.parse(data.deviceCredential);
  device.credential = data.deviceCredential || device.credential;
  device.credentialExpiresAt =
    data.credentialExpiresAt ||
    data.expiresAt ||
    (parsed && parsed.expiresAt) ||
    device.credentialExpiresAt;
  device.refreshCount = (device.refreshCount || 0) + 1;
  state.writeRuntime(runtime);
}

function markRevoked(deviceId, at) {
  var runtime = state.readRuntime();
  var device = findDevice(runtime, deviceId);
  if (!device) return;
  device.revokedAt = at;
  state.writeRuntime(runtime);
}

function requireKey() {
  var active = state.activeKey();
  if (!active) {
    return {
      error: {
        status: 409,
        message:
          "No API key yet. Register a business account first, or paste an existing key " +
          "into .env.local as PAYRIT_API_KEY."
      }
    };
  }
  if (state.isLiveKey(active.key) && !state.liveKeyAllowed()) {
    return {
      error: {
        status: 400,
        message:
          "That is a pk_live_ key. Set PAYRIT_ALLOW_LIVE=yes in .env.local if you really " +
          "mean to use it here."
      }
    };
  }
  return { key: active.key };
}

function setAuthorization(deviceId, authorization) {
  var runtime = state.readRuntime();
  var device = findDevice(runtime, deviceId);
  if (!device) return null;
  device.authorization = authorization;
  device.chain = [];
  state.writeRuntime(runtime);
  return device.authorization;
}

function updateAuthorization(deviceId, patch) {
  var runtime = state.readRuntime();
  var device = findDevice(runtime, deviceId);
  if (!device || !device.authorization) return null;
  Object.keys(patch).forEach(function (k) {
    device.authorization[k] = patch[k];
  });
  state.writeRuntime(runtime);
  return device.authorization;
}

function appendChainEntry(deviceId, entry) {
  var runtime = state.readRuntime();
  var device = findDevice(runtime, deviceId);
  if (!device) return null;
  if (!Array.isArray(device.chain)) device.chain = [];
  device.chain.push(entry);
  state.writeRuntime(runtime);
  return device.chain;
}

function deviceByAnyId(runtime, id) {
  var found = null;
  runtime.devices.forEach(function (d) {
    if (d.deviceId === id || d.apiDeviceId === id || d.paymentInstrumentId === id) found = d;
  });
  return found;
}

module.exports = {
  recordNonce: recordNonce,
  nonceRecord: nonceRecord,
  consumeNonce: consumeNonce,
  findDevice: findDevice,
  saveDevice: saveDevice,
  applyRefresh: applyRefresh,
  markRevoked: markRevoked,
  requireKey: requireKey,
  setAuthorization: setAuthorization,
  updateAuthorization: updateAuthorization,
  appendChainEntry: appendChainEntry,
  deviceByAnyId: deviceByAnyId
};

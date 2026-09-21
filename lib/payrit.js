"use strict";

var httpc = require("./http.js");
var state = require("./state.js");
var events = require("./events.js");

function call(spec) {
  var base = state.apiBase();
  var url = base + spec.path;
  var headers = {};
  if (spec.key) headers["x-api-key"] = spec.key;

  return httpc.request(url, { method: spec.method, headers: headers, body: spec.body }).then(
    function (res) {
      events.record({
        kind: res.ok ? "api" : "api-error",
        label: spec.label,
        origin: "live",
        method: spec.method,
        url: spec.path,
        status: res.status,
        ms: res.ms,
        request: spec.body === undefined ? null : httpc.forLog(spec.body),
        response: httpc.forLog(res.json !== null ? res.json : { raw: res.text.slice(0, 400) }),
        note: spec.note || null
      });
      return res;
    },
    function (err) {
      events.record({
        kind: "api-error",
        label: spec.label,
        origin: "live",
        method: spec.method,
        url: spec.path,
        status: null,
        request: spec.body === undefined ? null : httpc.forLog(spec.body),
        response: { error: err.message },
        note: "the request never completed"
      });
      throw err;
    }
  );
}

function hello() {
  return call({ method: "GET", path: "/v1", label: "Health check" });
}

function registerAccount(body) {
  return call({ method: "POST", path: "/v1/accounts", label: "Register business account", body: body });
}

function generateFirstKey(accountId, body) {
  return call({
    method: "POST",
    path: "/v1/accounts/" + encodeURIComponent(accountId) + "/api-keys",
    label: "Mint bootstrap API key",
    body: body,
    note: "allowed without x-api-key only while the account has zero active keys"
  });
}

function createCustomer(key, body) {
  return call({ method: "POST", path: "/v1/customers", label: "Create customer", key: key, body: body });
}

function enrollChallenge(key, platform) {
  return call({
    method: "POST",
    path: "/v1/enroll/challenge",
    label: "Request enrollment nonce",
    key: key,
    body: { platform: platform }
  });
}

function enroll(key, body) {
  return call({ method: "POST", path: "/v1/enroll", label: "Enroll device", key: key, body: body });
}

function refresh(key, body) {
  return call({
    method: "POST",
    path: "/v1/enroll/refresh",
    label: "Refresh device credential",
    key: key,
    body: body
  });
}

function revoke(key, deviceId) {
  return call({
    method: "POST",
    path: "/v1/devices/" + encodeURIComponent(deviceId) + "/revoke",
    label: "Revoke device",
    key: key
  });
}

module.exports = {
  hello: hello,
  registerAccount: registerAccount,
  generateFirstKey: generateFirstKey,
  createCustomer: createCustomer,
  enrollChallenge: enrollChallenge,
  enroll: enroll,
  refresh: refresh,
  revoke: revoke
};

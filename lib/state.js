"use strict";

var fs = require("fs");
var path = require("path");

var ROOT = path.join(__dirname, "..");
var ENV_FILE = path.join(ROOT, ".env.local");
var RUNTIME_FILE = path.join(ROOT, ".runtime.json");

var DEFAULT_BASE = "https://payrit-ble-backend.vercel.app";
var PLACEHOLDERS = ["pk_test_replace_me", "replace_me", ""];

function readEnvFile() {
  var out = {};
  var text;
  try {
    text = fs.readFileSync(ENV_FILE, "utf8");
  } catch (e) {
    return out;
  }
  text.split(/\r?\n/).forEach(function (line) {
    var trimmed = line.trim();
    if (!trimmed || trimmed.charAt(0) === "#") return;
    var eq = trimmed.indexOf("=");
    if (eq === -1) return;
    var k = trimmed.slice(0, eq).trim();
    var v = trimmed.slice(eq + 1).trim();
    if (v.length >= 2 && (v.charAt(0) === '"' || v.charAt(0) === "'") && v.slice(-1) === v.charAt(0)) {
      v = v.slice(1, -1);
    }
    out[k] = v;
  });
  return out;
}

function env(name, fallback) {
  if (process.env[name] !== undefined && process.env[name] !== "") return process.env[name];
  var file = readEnvFile();
  if (file[name] !== undefined && file[name] !== "") return file[name];
  return fallback;
}

function apiBase() {
  return String(env("PAYRIT_API_BASE", DEFAULT_BASE)).replace(/\/+$/, "");
}

function port() {
  return Number(env("PORT", "4546")) || 4546;
}

function appId() {
  return env("PAYRIT_APP_ID", "com.payrit.harness");
}

function readRuntime() {
  try {
    var parsed = JSON.parse(fs.readFileSync(RUNTIME_FILE, "utf8"));
    if (!parsed || typeof parsed !== "object") throw new Error("not an object");
    if (!Array.isArray(parsed.devices)) parsed.devices = [];
    if (!parsed.nonces || typeof parsed.nonces !== "object") parsed.nonces = {};
    return parsed;
  } catch (e) {
    return { account: null, apiKey: null, customer: null, devices: [], nonces: {} };
  }
}

function writeRuntime(state) {
  fs.writeFileSync(RUNTIME_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  return state;
}

function resetRuntime() {
  try {
    fs.unlinkSync(RUNTIME_FILE);
  } catch (e) {
  }
  return readRuntime();
}

function activeKey() {
  var configured = env("PAYRIT_API_KEY", "");
  if (configured && PLACEHOLDERS.indexOf(configured) === -1) {
    return { key: configured, source: "env", name: "configured key", environment: null, scopes: null };
  }
  var runtime = readRuntime();
  if (runtime.apiKey && runtime.apiKey.key) {
    return {
      key: runtime.apiKey.key,
      source: "bootstrap",
      name: runtime.apiKey.name || null,
      environment: runtime.apiKey.environment || null,
      scopes: runtime.apiKey.scopes || null
    };
  }
  return null;
}

function keyPrefix(key) {
  if (!key) return null;
  return key.slice(0, 11) + "…";
}

function liveKeyAllowed() {
  return String(env("PAYRIT_ALLOW_LIVE", "")).toLowerCase() === "yes";
}

function isLiveKey(key) {
  return typeof key === "string" && key.indexOf("pk_live_") === 0;
}

function readMaybeFile(value) {
  if (!value) return null;
  var trimmed = String(value).trim();
  if (trimmed.indexOf("-----BEGIN") === 0 || trimmed.charAt(0) === "{") return trimmed;
  try {
    return fs.readFileSync(path.resolve(ROOT, trimmed), "utf8").trim();
  } catch (e) {
    return null;
  }
}

function androidAttestConfig() {
  var certPem = readMaybeFile(env("PAYRIT_ANDROID_ROOT_CERT", ".harness-pki/android-root.pem"));
  var jwkText = readMaybeFile(env("PAYRIT_ANDROID_ROOT_JWK", ".harness-pki/android-root.jwk"));
  var packageName = env("ANDROID_APP_PACKAGE", "");
  var digest = env("ANDROID_SIGNING_CERT_DIGEST", "");

  var jwk = null;
  if (jwkText) {
    try {
      jwk = JSON.parse(jwkText);
    } catch (e) {
      jwk = null;
    }
  }

  var missing = [];
  if (!certPem) missing.push("PAYRIT_ANDROID_ROOT_CERT");
  if (!jwk) missing.push("PAYRIT_ANDROID_ROOT_JWK");
  if (!packageName) missing.push("ANDROID_APP_PACKAGE");
  if (!digest) missing.push("ANDROID_SIGNING_CERT_DIGEST");

  return {
    ready: missing.length === 0,
    missing: missing,
    rootCertPem: certPem,
    rootJwk: jwk,
    packageName: packageName,
    signingCertDigest: digest,

    binding: env("PAYRIT_ANDROID_BINDING", "raw"),
    appIdLocation: env("PAYRIT_ANDROID_APPID_LOCATION", "tee")
  };
}

function appAttestConfig() {
  var certPem = readMaybeFile(env("PAYRIT_APPATTEST_ROOT_CERT", ""));
  var jwkText = readMaybeFile(env("PAYRIT_APPATTEST_ROOT_JWK", ""));
  var teamId = env("PAYRIT_TEAM_ID", "");
  var bundleId = env("PAYRIT_BUNDLE_ID", "");

  var jwk = null;
  if (jwkText) {
    try {
      jwk = JSON.parse(jwkText);
    } catch (e) {
      jwk = null;
    }
  }

  var missing = [];
  if (!certPem) missing.push("PAYRIT_APPATTEST_ROOT_CERT");
  if (!jwk) missing.push("PAYRIT_APPATTEST_ROOT_JWK");
  if (!teamId) missing.push("PAYRIT_TEAM_ID");
  if (!bundleId) missing.push("PAYRIT_BUNDLE_ID");

  return {
    ready: missing.length === 0,
    missing: missing,
    rootCertPem: certPem,
    rootJwk: jwk,
    teamId: teamId,
    bundleId: bundleId,
    production: String(env("PAYRIT_APPATTEST_PRODUCTION", "")).toLowerCase() === "yes",
    includeRootInChain: String(env("PAYRIT_APPATTEST_X5C_ROOT", "yes")).toLowerCase() !== "no"
  };
}

module.exports = {
  env: env,
  apiBase: apiBase,
  port: port,
  appId: appId,
  readRuntime: readRuntime,
  writeRuntime: writeRuntime,
  resetRuntime: resetRuntime,
  activeKey: activeKey,
  keyPrefix: keyPrefix,
  liveKeyAllowed: liveKeyAllowed,
  isLiveKey: isLiveKey,
  appAttestConfig: appAttestConfig,
  androidAttestConfig: androidAttestConfig
};

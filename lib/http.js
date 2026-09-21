"use strict";

var http = require("http");
var https = require("https");
var urllib = require("url");

var SECRET_KEYS = ["key", "x-api-key", "privateKey", "apiKey"];

function maskValue(value) {
  if (typeof value !== "string" || value.length === 0) return value;
  if (value.length <= 11) return value.slice(0, 4) + "…";
  return value.slice(0, 11) + "…" + String(value.length) + "chars";
}

function redact(value, depth) {
  var d = depth || 0;
  if (d > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return value.map(function (item) {
      return redact(item, d + 1);
    });
  }
  var out = {};
  Object.keys(value).forEach(function (k) {
    if (SECRET_KEYS.indexOf(k) !== -1 || SECRET_KEYS.indexOf(k.toLowerCase()) !== -1) {
      out[k] = maskValue(value[k]);
      return;
    }
    out[k] = redact(value[k], d + 1);
  });
  return out;
}

function abridge(value, depth) {
  var d = depth || 0;
  if (typeof value === "string") {
    if (value.length > 120) return value.slice(0, 60) + "…[" + value.length + " chars]";
    return value;
  }
  if (d > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return value.map(function (item) {
      return abridge(item, d + 1);
    });
  }
  var out = {};
  Object.keys(value).forEach(function (k) {
    out[k] = abridge(value[k], d + 1);
  });
  return out;
}

function forLog(value) {
  return redact(value);
}

function request(target, options) {
  var opts = options || {};
  return new Promise(function (resolve, reject) {
    var parsed = urllib.parse(target);
    var isHttps = parsed.protocol === "https:";
    var lib = isHttps ? https : http;
    var body = opts.body === undefined ? null : JSON.stringify(opts.body);
    var headers = Object.assign({ accept: "application/json" }, opts.headers || {});
    if (body !== null) {
      headers["content-type"] = "application/json";
      headers["content-length"] = Buffer.byteLength(body);
    }

    var started = Date.now();
    var req = lib.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.path,
        method: opts.method || "GET",
        headers: headers
      },
      function (res) {
        var chunks = [];
        res.on("data", function (c) {
          chunks.push(c);
        });
        res.on("end", function () {
          var text = Buffer.concat(chunks).toString("utf8");
          var json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = null;
          }
          resolve({
            status: res.statusCode,
            ok: res.statusCode >= 200 && res.statusCode < 300,
            headers: res.headers,
            json: json,
            text: text,
            ms: Date.now() - started
          });
        });
      }
    );

    req.setTimeout(opts.timeout || 30000, function () {
      req.destroy(new Error("timeout after " + (opts.timeout || 30000) + "ms"));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

module.exports = { request: request, forLog: forLog, redact: redact, abridge: abridge };

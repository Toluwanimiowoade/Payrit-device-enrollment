"use strict";

var http = require("http");
var fs = require("fs");
var path = require("path");
var urllib = require("url");

var state = require("./lib/state.js");
var hardware = require("./lib/hardware.js");
var routes = require("./lib/routes.js");

var PUBLIC_DIR = path.join(__dirname, "public");
var MAX_BODY_BYTES = 512 * 1024;

var MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function readBody(req) {
  return new Promise(function (resolve, reject) {
    var chunks = [];
    var size = 0;
    req.on("data", function (c) {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        var tooBig = new Error("request body too large");
        tooBig.clientError = true;
        reject(tooBig);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", function () {
      var text = Buffer.concat(chunks).toString("utf8");
      if (!text) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch (e) {
        var err = new Error("body is not valid JSON");
        err.clientError = true;
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function serveStatic(res, pathname) {
  var rel = pathname === "/" ? "/index.html" : pathname;
  var target = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^([.]{2}[\/\\])+/, ""));
  if (target.indexOf(PUBLIC_DIR) !== 0) {
    res.writeHead(403, { "content-type": "text/plain" });
    return res.end("forbidden");
  }
  fs.readFile(target, function (err, data) {
    if (err) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      return res.end("not found");
    }
    res.writeHead(200, {
      "content-type": MIME[path.extname(target)] || "application/octet-stream",
      "content-length": data.length,
      "cache-control": "no-store"
    });
    res.end(data);
  });
}

var server = http.createServer(function (req, res) {
  var parsed = urllib.parse(req.url, true);
  var pathname = parsed.pathname;

  if (pathname.indexOf("/api/") !== 0) {
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "content-type": "text/plain" });
      return res.end("method not allowed");
    }
    return serveStatic(res, pathname);
  }

  var route = routes.lookup(req.method, pathname);
  if (!route) return routes.sendJson(res, 404, { message: "no such route" });

  var run = route.body
    ? readBody(req).then(function (body) {
        return route.handler(req, res, body, parsed.query);
      })
    : Promise.resolve().then(function () {
        return route.handler(req, res, null, parsed.query);
      });

  run.catch(function (err) {
    if (res.headersSent) return;
    routes.sendJson(res, err.clientError ? 400 : 500, { message: err.message });
  });
});

function startupBanner(port) {
  var active = state.activeKey();
  var apple = state.appAttestConfig();
  var android = state.androidAttestConfig();

  var keyLine = active
    ? state.keyPrefix(active.key) + "  (" + active.source + ")"
    : "none yet — register an account in the UI";
  var opensslLine = hardware.haveOpenssl()
    ? "present (android attestation path available)"
    : "missing (use the ios path)";

  console.log("");
  console.log("  Payrit device-enrollment harness");
  console.log("  http://localhost:" + port);
  console.log("");
  console.log("  API base   " + state.apiBase());
  console.log("  API key    " + keyLine);
  console.log("  openssl    " + opensslLine);
  console.log("  live iOS   " + (apple.ready ? "ready" : "needs " + apple.missing.join(", ")));
  console.log("  live droid " + (android.ready ? "ready" : "needs " + android.missing.join(", ")));

  if (active && state.isLiveKey(active.key)) {
    var liveNote = state.liveKeyAllowed()
      ? " and PAYRIT_ALLOW_LIVE=yes is set"
      : " — refusing to use it until PAYRIT_ALLOW_LIVE=yes";
    console.log("");
    console.log("  !! that is a pk_live_ key" + liveNote);
  }
  console.log("");
}

if (require.main === module) {
  var port = state.port();
  server.listen(port, function () {
    startupBanner(port);
  });
}

module.exports = server;

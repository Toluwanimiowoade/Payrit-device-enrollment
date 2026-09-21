"use strict";

var state = require("./state.js");
var payrit = require("./payrit.js");
var hardware = require("./hardware.js");
var simulator = require("./simulator.js");
var attestation = require("./attestation.js");
var session = require("./session.js");
var events = require("./events.js");
var httpc = require("./http.js");
var view = require("./view.js");

function sendJson(res, status, body) {
  var text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store"
  });
  res.end(text);
}

function upstreamMessage(res, fallback) {
  if (res.json && res.json.message) return res.json.message;
  if (res.text) return res.text.slice(0, 300);
  return fallback;
}

function liveFailureExplanation(r) {
  var msg = upstreamMessage(r, "");
  if (r.status === 422 && /trusted root|attestation|integrity/i.test(msg)) {
    return (
      "The attestation was rejected. If the deployment's trust anchors are not configured, " +
      "enrollment fails closed with a 422 until they are; if they are, check that the harness " +
      "is signing with the same test root. Simulated mode verifies locally instead."
    );
  }
  if (r.status === 401) {
    return "The API key was rejected. Check PAYRIT_API_KEY, or reset and bootstrap a new account.";
  }
  if (r.status === 403) return "The key is missing the devices:write scope.";
  if (r.status === 400) return "The payload was rejected before attestation was even checked.";
  return null;
}

function guardKey(res) {
  var guard = session.requireKey();
  if (guard.error) {
    sendJson(res, guard.error.status, { message: guard.error.message });
    return null;
  }
  return guard.key;
}

function routeState(req, res) {
  sendJson(res, 200, view.publicView());
}

function routeHealth(req, res) {
  return payrit.hello().then(
    function (r) {
      sendJson(res, 200, { reachable: r.ok, status: r.status, body: r.json, apiBase: state.apiBase() });
    },
    function (err) {
      sendJson(res, 200, { reachable: false, status: null, error: err.message, apiBase: state.apiBase() });
    }
  );
}

function routeEvents(req, res, body, query) {
  var raw = !!(query && (query.raw === "1" || query.raw === "true"));
  sendJson(res, 200, { events: events.all(query && query.since, raw) });
}

function routeReset(req, res) {
  state.resetRuntime();
  events.clear();
  events.record({ kind: "device", origin: "simulated", label: "Session reset", note: "local state cleared" });
  sendJson(res, 200, view.publicView());
}

function routeBootstrap(req, res, body) {
  var name = String(body.name || "").trim();
  if (!name) return sendJson(res, 400, { message: "An institution name is required." });

  var runtime = state.readRuntime();
  if (runtime.account && runtime.apiKey) {
    return sendJson(res, 409, {
      message: "This harness already holds an account and a key. Reset the session to start over."
    });
  }

  var payload = { name: name };
  if (body.email) payload.email = String(body.email).trim();

  return payrit.registerAccount(payload).then(function (accountRes) {
    if (!accountRes.ok) {
      return sendJson(res, 502, {
        message: upstreamMessage(accountRes, "Registration failed"),
        status: accountRes.status
      });
    }
    var account = accountRes.json.data;
    return payrit
      .generateFirstKey(account._id, { name: "Harness bootstrap key", environment: "test" })
      .then(function (keyRes) {
        if (!keyRes.ok) {
          var partial = state.readRuntime();
          partial.account = account;
          state.writeRuntime(partial);
          return sendJson(res, 502, {
            message: upstreamMessage(keyRes, "Key minting failed"),
            status: keyRes.status
          });
        }
        var next = state.readRuntime();
        next.account = account;
        next.apiKey = keyRes.json.data;
        state.writeRuntime(next);
        sendJson(res, 201, view.publicView());
      });
  });
}

function routeCustomer(req, res, body) {
  var key = guardKey(res);
  if (!key) return;

  var firstName = String(body.firstName || "").trim();
  if (!firstName) return sendJson(res, 400, { message: "A first name is required." });

  var payload = { firstName: firstName };
  ["lastName", "email", "phoneNumber", "externalRef"].forEach(function (field) {
    if (body[field]) payload[field] = String(body[field]).trim();
  });
  if (body.type === "business" || body.type === "individual") payload.type = body.type;

  return payrit.createCustomer(key, payload).then(function (r) {
    if (!r.ok) {
      return sendJson(res, 502, {
        message: upstreamMessage(r, "Customer creation failed"),
        status: r.status
      });
    }
    var runtime = state.readRuntime();
    runtime.customer = r.json.data;
    state.writeRuntime(runtime);
    sendJson(res, 201, view.publicView());
  });
}

function askForNonce(res, key, platform) {
  return payrit.enrollChallenge(key, platform).then(function (r) {
    if (!r.ok) {
      sendJson(res, 502, {
        step: "challenge",
        message: upstreamMessage(r, "Could not get a nonce"),
        status: r.status
      });
      return null;
    }
    session.recordNonce(r.json.data.nonce, platform, r.json.data.expiresAt);
    return r.json.data.nonce;
  });
}

function routeEnroll(req, res, body) {
  var key = guardKey(res);
  if (!key) return;

  var runtime = state.readRuntime();
  if (!runtime.customer) {
    return sendJson(res, 409, { message: "Create a customer before enrolling a device." });
  }

  var platform = body.platform === "ios" ? "ios" : "android";

  var currency = String(body.currency || "NGN").toUpperCase();
  var mode = body.mode === "live" ? "live" : "simulated";

  return askForNonce(res, key, platform).then(function (nonce) {
    if (!nonce) return;

    var deviceKey = hardware.createDeviceKey();
    var built;
    try {
      built = attestation.build(platform, deviceKey, nonce, mode);
    } catch (err) {
      return sendJson(res, 500, { step: "attestation", message: err.message });
    }

    events.record({
      kind: "device",
      origin: "simulated",
      label: "Generate device key + attestation",
      note: built.note,
      response: Object.assign(
        {
          platform: platform,
          publicKey: httpc.abridge(deviceKey.spkiB64),
          fingerprint: hardware.fingerprint(deviceKey.privatePem),
          nonce: nonce
        },
        built.detail || {}
      )
    });

    var enrollBody = Object.assign(
      {
        customerId: runtime.customer._id,
        platform: platform,
        publicKey: deviceKey.spkiB64,
        nonce: nonce
      },
      built.attestation
    );

    function keep(data, origin) {
      var record = session.saveDevice({
        data: data,
        deviceKey: deviceKey,
        platform: platform,
        currency: currency,
        customerId: runtime.customer._id,
        origin: origin
      });
      return view.deviceView(record);
    }

    if (mode === "live") {
      return payrit.enroll(key, enrollBody).then(function (r) {
        session.consumeNonce(nonce);
        if (!r.ok) {
          return sendJson(res, 200, {
            mode: "live",
            ok: false,
            status: r.status,
            message: upstreamMessage(r, "Enrollment rejected"),
            explanation: liveFailureExplanation(r),
            state: view.publicView()
          });
        }
        sendJson(res, 200, {
          mode: "live",
          ok: true,
          status: r.status,
          device: keep(r.json.data, "live"),
          state: view.publicView()
        });
      });
    }

    var result = simulator.enroll({ body: enrollBody, nonceRecord: session.nonceRecord(nonce) });
    session.consumeNonce(nonce);
    if (!result.ok) {
      return sendJson(res, 200, {
        mode: "simulated",
        ok: false,
        status: result.status,
        message: result.body.message,
        state: view.publicView()
      });
    }
    sendJson(res, 200, {
      mode: "simulated",
      ok: true,
      status: result.status,
      device: keep(result.body.data, "simulated"),
      state: view.publicView()
    });
  });
}

function findOr404(res, deviceId) {
  var device = session.findDevice(state.readRuntime(), String(deviceId || ""));
  if (!device) {
    sendJson(res, 404, { message: "No such device in this session." });
    return null;
  }
  return device;
}

function simulatedOnlyNote(device, action) {
  if (device.origin !== "simulated") return null;
  return (
    "This device only exists in the harness simulator, so the live deployment has never heard " +
    "of it. A live " + action + " can only succeed for a device the live deployment enrolled."
  );
}

function routeRefresh(req, res, body) {
  var key = guardKey(res);
  if (!key) return;

  var device = findOr404(res, body.deviceId);
  if (!device) return;

  var mode = body.mode === "live" ? "live" : "simulated";

  return askForNonce(res, key, device.platform).then(function (nonce) {
    if (!nonce) return;

    var signature = hardware.signNonce(device.privatePem, nonce);
    events.record({
      kind: "device",
      origin: "simulated",
      label: "Sign the nonce with the device key",
      note: "raw ES256 (ieee-p1363) over the UTF-8 nonce bytes, as RefreshCredentialDto documents",
      response: { deviceId: device.deviceId, nonce: nonce, signature: httpc.abridge(signature) }
    });

    var refreshBody = {
      deviceId: mode === "live" ? device.apiDeviceId || device.deviceId : device.deviceId,
      nonce: nonce,
      signature: signature
    };

    if (mode === "live") {
      return payrit.refresh(key, refreshBody).then(function (r) {
        session.consumeNonce(nonce);
        if (!r.ok) {
          return sendJson(res, 200, {
            mode: "live",
            ok: false,
            status: r.status,
            message: upstreamMessage(r, "Refresh rejected"),
            explanation: simulatedOnlyNote(device, "refresh"),
            state: view.publicView()
          });
        }
        session.applyRefresh(device.deviceId, r.json.data);
        sendJson(res, 200, { mode: "live", ok: true, status: r.status, state: view.publicView() });
      });
    }

    var result = simulator.refresh({
      body: refreshBody,
      device: device,
      nonceRecord: session.nonceRecord(nonce)
    });
    session.consumeNonce(nonce);
    if (!result.ok) {
      return sendJson(res, 200, {
        mode: "simulated",
        ok: false,
        status: result.status,
        message: result.body.message,
        state: view.publicView()
      });
    }
    session.applyRefresh(device.deviceId, result.body.data);
    sendJson(res, 200, { mode: "simulated", ok: true, status: result.status, state: view.publicView() });
  });
}

function routeRevoke(req, res, body) {
  var key = guardKey(res);
  if (!key) return;

  var device = findOr404(res, body.deviceId);
  if (!device) return;

  var mode = body.mode === "live" ? "live" : "simulated";

  if (mode === "live") {
    return payrit.revoke(key, device.apiDeviceId || device.deviceId).then(function (r) {
      if (!r.ok) {
        return sendJson(res, 200, {
          mode: "live",
          ok: false,
          status: r.status,
          message: upstreamMessage(r, "Revoke rejected"),
          explanation: simulatedOnlyNote(device, "revoke"),
          state: view.publicView()
        });
      }
      session.markRevoked(device.deviceId, new Date().toISOString());
      sendJson(res, 200, { mode: "live", ok: true, status: r.status, state: view.publicView() });
    });
  }

  var result = simulator.revoke({ device: device, deviceId: device.deviceId });
  if (!result.ok) {
    return sendJson(res, 200, {
      mode: "simulated",
      ok: false,
      status: result.status,
      message: result.body.message,
      state: view.publicView()
    });
  }
  session.markRevoked(device.deviceId, result.revokedAt);
  sendJson(res, 200, { mode: "simulated", ok: true, status: result.status, state: view.publicView() });
}

var table = [
  { method: "GET", path: "/api/state", handler: routeState },
  { method: "GET", path: "/api/health", handler: routeHealth },
  { method: "GET", path: "/api/events", handler: routeEvents },
  { method: "POST", path: "/api/reset", handler: routeReset },
  { method: "POST", path: "/api/bootstrap", handler: routeBootstrap, body: true },
  { method: "POST", path: "/api/customer", handler: routeCustomer, body: true },
  { method: "POST", path: "/api/enroll", handler: routeEnroll, body: true },
  { method: "POST", path: "/api/refresh", handler: routeRefresh, body: true },
  { method: "POST", path: "/api/revoke", handler: routeRevoke, body: true }
];

function lookup(method, pathname) {
  var found = null;
  table.forEach(function (route) {
    if (route.method === method && route.path === pathname) found = route;
  });
  return found;
}

module.exports = { lookup: lookup, sendJson: sendJson };

"use strict";

var app = {
  mode: "simulated",
  state: null,
  banner: null,
  busy: null,
  lastSeq: 0,
  eventCount: 0,
  screen: null,
  selectedDeviceId: null,
  handshake: null,
  raw: false,
  pollTimer: null,
  pollDelay: 1200
};

var $ = function (id) { return document.getElementById(id); };

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function short(value, head, tail) {
  var s = String(value || "");
  var h = head || 8;
  var t = tail || 4;
  if (s.length <= h + t + 1) return s;
  return s.slice(0, h) + "…" + s.slice(-t);
}

function api(path, options) {
  var opts = options || {};
  return fetch(path, {
    method: opts.method || "GET",
    headers: opts.body ? { "content-type": "application/json" } : undefined,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  }).then(function (res) {
    if (opts.method === "POST") {
      app.pollDelay = POLL_MIN_MS;
      schedulePoll(150);
    }
    return res.json().then(function (json) {
      return { status: res.status, ok: res.ok, json: json };
    });
  });
}

function refreshState() {
  return api("/api/state").then(function (r) {
    app.state = r.json;
    render();
  });
}

function devices() {
  return (app.state && app.state.devices) || [];
}

function liveDevices() {
  return devices().filter(function (d) {
    return !d.revokedAt;
  });
}

function activeDevice() {
  var list = devices();
  if (!list.length) return null;
  var picked = null;
  list.forEach(function (d) {
    if (d.deviceId === app.selectedDeviceId) picked = d;
  });
  return picked || list[list.length - 1];
}

function currentScreen() {
  var s = app.state;
  if (!s || !s.key.present) return "waiting";
  if (!s.customer) return "signup";
  if (!devices().length) return "secure";
  if (app.screen === "enroll") return "secure";
  if (app.screen === "pay") return "pay";
  if (app.screen === "device") return "device";
  return "devices";
}

function goTo(screen, deviceId) {
  app.screen = screen;
  if (deviceId) app.selectedDeviceId = deviceId;
  app.banner = null;
  try {
    location.hash = screen === "devices" ? "" : screen + (deviceId ? "/" + deviceId : "");
  } catch (e) {
  }
  render();
}

function readHash() {
  var raw = String(location.hash || "").replace(/^#/, "");
  if (!raw) return;
  var parts = raw.split("/");
  if (["device", "pay", "enroll"].indexOf(parts[0]) === -1) return;
  app.screen = parts[0];
  if (parts[1]) app.selectedDeviceId = parts[1];
}

function setBusy(name) {
  app.busy = name;
  render();
}

function fail(message, explanation, status) {
  app.banner = { kind: "err", message: message, explanation: explanation || null, status: status || null };
}

function inform(kind, message, explanation) {
  app.banner = { kind: kind, message: message, explanation: explanation || null, status: null };
}

function bootstrap(event) {
  event.preventDefault();
  app.banner = null;
  setBusy("bootstrap");
  api("/api/bootstrap", {
    method: "POST",
    body: { name: $("acct-name").value, email: $("acct-email").value }
  })
    .then(function (r) {
      app.busy = null;
      if (!r.ok) {
        fail(r.json.message || "Registration failed", null, r.status);
        return refreshState();
      }
      app.state = r.json;
      inform("good", "Account registered and the bootstrap key is minted.", "That key is the only one the public route will ever hand out for this account.");
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function createCustomer(form) {
  app.banner = null;
  setBusy("customer");
  api("/api/customer", {
    method: "POST",
    body: {
      firstName: form.firstName,
      lastName: form.lastName,
      email: form.email,
      phoneNumber: form.phoneNumber
    }
  })
    .then(function (r) {
      app.busy = null;
      if (!r.ok) {
        fail(r.json.message || "Could not create the customer", null, r.status);
        return refreshState();
      }
      app.state = r.json;
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function enroll(platform, currency) {
  app.banner = null;
  setBusy("enroll");
  api("/api/enroll", { method: "POST", body: { mode: app.mode, platform: platform, currency: currency } })
    .then(function (r) {
      app.busy = null;
      if (!r.ok) {
        fail(r.json.message || "Enrollment could not start", null, r.status);
        return refreshState();
      }
      if (r.json.state) app.state = r.json.state;
      if (!r.json.ok) {
        fail(r.json.message, r.json.explanation, r.json.status);
      } else {
        inform("good", "Device enrolled. A Payrit-signed credential is on the device.");
      }
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function lifecycle(action, deviceId) {
  app.banner = null;
  setBusy(action);
  api("/api/" + action, { method: "POST", body: { mode: app.mode, deviceId: deviceId } })
    .then(function (r) {
      app.busy = null;
      if (!r.ok) {
        fail(r.json.message || "Request failed", null, r.status);
        return refreshState();
      }
      if (r.json.state) app.state = r.json.state;
      if (!r.json.ok) {
        fail(r.json.message, r.json.explanation, r.json.status);
      } else if (action === "refresh") {
        inform("good", "Credential re-issued without re-attesting — the device just proved it still holds its key.");
      } else {
        inform("info", "Device revoked. Its credential can no longer be refreshed.");
      }
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function requestPreauth(deviceId, cap, currency) {
  app.banner = null;
  setBusy("preauth");
  api("/api/preauth", { method: "POST", body: { mode: app.mode, deviceId: deviceId, cap: cap, currency: currency } })
    .then(function (r) {
      app.busy = null;
      if (r.json.state) app.state = r.json.state;
      if (!r.ok || r.json.ok === false) {
        fail(r.json.message || "Could not reserve the cap", r.json.explanation, r.json.status);
      } else {
        inform("good", "Spend cap reserved and signed.");
      }
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function revokePreauth(deviceId) {
  app.banner = null;
  setBusy("preauth-revoke");
  api("/api/preauth/revoke", { method: "POST", body: { deviceId: deviceId } })
    .then(function (r) {
      app.busy = null;
      if (r.json.state) app.state = r.json.state;
      if (!r.ok || r.json.ok === false) fail(r.json.message || "Could not release the hold", null, r.json.status);
      else inform("info", "Hold released. The unconsumed amount goes back to the wallet.");
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function runHandshake(payerDeviceId, payeeDeviceId, amount) {
  app.banner = null;
  app.handshake = null;
  setBusy("handshake");
  api("/api/handshake", {
    method: "POST",
    body: { payerDeviceId: payerDeviceId, payeeDeviceId: payeeDeviceId, amount: amount }
  })
    .then(function (r) {
      app.busy = null;
      if (r.json.state) app.state = r.json.state;
      if (!r.ok) {
        fail(r.json.message || "The handshake could not run", null, r.status);
      } else {
        app.handshake = r.json;
      }
      render();
    })
    .catch(function (err) {
      app.busy = null;
      fail(err.message);
      render();
    });
}

function resetSession() {
  app.banner = null;
  api("/api/reset", { method: "POST" }).then(function (r) {
    app.state = r.json;
    app.lastSeq = 0;
    app.eventCount = 0;
    $("log").innerHTML = '<div class="empty">Session reset. Register the institution to start again.</div>';
    render();
  });
}

function renderPhone() {
  var content = $("content");
  var screen = currentScreen();
  var html = "";

  if (app.banner) html += bannerHtml(app.banner);

  if (screen === "waiting") {
    html += [
      "<h3>Almost there</h3>",
      '<p class="lead">This app is waiting for Kanto Microfinance to finish its Payrit setup. Register the institution in the panel on the right, and this screen moves on.</p>',
      '<div class="biometric"><div class="fingerprint">' + fingerprintSvg() + "</div><span>no API key yet</span></div>"
    ].join("");
  }

  if (screen === "signup") {
    html += [
      "<h3>Open your account</h3>",
      '<p class="lead">Your details are held by Kanto. Payrit only ever sees the customer record your bank creates for you.</p>',
      '<div class="row2">',
      field("first", "First name", "Ada"),
      field("last", "Last name", "Lovelace"),
      "</div>",
      field("email", "Email", "ada@example.com", "email"),
      field("phone", "Phone", "+2348012345678", "tel"),
      '<button type="button" class="cta accent" id="do-signup"' + (app.busy === "customer" ? " disabled" : "") + ">" +
        (app.busy === "customer" ? "Creating your account…" : "Create my account") +
        "</button>"
    ].join("");
  }

  if (screen === "secure") {
    var working = app.busy === "enroll";
    html += [
      "<h3>Secure this device</h3>",
      '<p class="lead">Kanto will create a payment key inside this phone\'s secure hardware. It never leaves the device, and it lets you pay even with no signal.</p>',
      '<div class="biometric' + (working ? " working" : "") + '"><div class="fingerprint">' + fingerprintSvg() + "</div><span>" +
        (working ? "Generating key, attesting device…" : "Uses your fingerprint or face to unlock") +
        "</span></div>",
      '<ul class="checklist">',
      '<li><span class="tick">✓</span><span>A P-256 key is generated on this device and cannot be exported.</span></li>',
      '<li><span class="tick">✓</span><span>Payrit checks the phone is genuine before trusting it.</span></li>',
      '<li><span class="tick">✓</span><span>The credential you get back is short-lived and can be revoked instantly.</span></li>',
      "</ul>",
      '<div class="row2">',
      select("platform", "This phone", [["android", "Android"], ["ios", "iPhone"]]),
      select("currency", "Wallet currency", [["NGN", "NGN"], ["KES", "KES"], ["GHS", "GHS"], ["USD", "USD"]]),
      "</div>",
      '<button type="button" class="cta accent" id="do-enroll"' + (working ? " disabled" : "") + ">" +
        (working ? "Securing…" : "Secure this device") +
        "</button>"
    ].join("");
  }

  if (screen === "devices") {
    var list = devices();
    html += [
      "<h3>Your devices</h3>",
      '<p class="lead">' + list.length + (list.length === 1 ? " device is" : " devices are") +
        " enrolled to this customer. Each holds its own hardware key and its own spend cap.</p>",
      '<div class="devlist">',
      list
        .map(function (d) {
          return deviceRow(d);
        })
        .join(""),
      "</div>",
      '<div class="ctas">',
      '<button type="button" class="cta accent" id="do-add">Add another device</button>',
      liveDevices().length >= 2
        ? '<button type="button" class="cta secondary" id="do-pay">Pay another device</button>'
        : "",
      "</div>"
    ].join("");
  }

  if (screen === "device") {
    var device = activeDevice();
    html += [
      '<button type="button" class="backlink" id="do-back">‹ All devices</button>',
      credentialCard(device),
      '<div class="meta">',
      kv("Device", short(device.deviceId, 8, 4)),
      kv("Instrument", device.paymentInstrumentId ? short(device.paymentInstrumentId, 8, 4) : "—"),
      kv("Platform", device.platform),
      kv("Key fingerprint", short(device.fingerprint, 10, 6)),
      "</div>",
      preauthPanel(device)
    ].join("");

    if (!device.revokedAt) {
      html += [
        '<div class="ctas">',
        '<button type="button" class="cta secondary" id="do-refresh"' + (app.busy === "refresh" ? " disabled" : "") + ">" +
          (app.busy === "refresh" ? "Refreshing…" : "Refresh credential") + "</button>",
        '<button type="button" class="cta danger" id="do-revoke"' + (app.busy === "revoke" ? " disabled" : "") + ">" +
          (app.busy === "revoke" ? "Revoking…" : "Report this device lost") + "</button>",
        "</div>"
      ].join("");
    } else {
      html += '<div class="ctas"><button type="button" class="cta accent" id="do-add">Set up a new device</button></div>';
    }
  }

  if (screen === "pay") {
    var payer = activeDevice();
    var others = liveDevices().filter(function (d) {
      return d.deviceId !== payer.deviceId;
    });
    html += [
      '<button type="button" class="backlink" id="do-back">‹ All devices</button>',
      "<h3>Tap to pay</h3>",
      '<p class="lead">Both phones are offline. They exchange signed messages over Bluetooth and verify each other with no network at all.</p>',
      '<div class="field"><label for="f-payee">Pay which device</label><select id="f-payee">' +
        others
          .map(function (d) {
            return '<option value="' + esc(d.deviceId) + '">' + esc(d.platform) + " · " + esc(short(d.deviceId, 8, 4)) + "</option>";
          })
          .join("") +
        "</select></div>",
      '<div class="field"><label for="f-amount">Amount (minor units)</label><input id="f-amount" type="number" min="1" value="2500"></div>',
      payer.authorization
        ? '<p class="hintline">' + payer.authorization.remaining + " of " + payer.authorization.cap + " " +
          esc(payer.authorization.currency) + " left on this device\'s cap</p>"
        : '<p class="hintline">This device needs a pre-authorization before it can pay.</p>',
      app.handshake ? handshakeReport(app.handshake) : "",
      '<button type="button" class="cta accent" id="do-handshake"' + (app.busy === "handshake" ? " disabled" : "") + ">" +
        (app.busy === "handshake" ? "Handshaking…" : "Start the handshake") + "</button>"
    ].join("");
  }

  content.innerHTML = html;
  wirePhone(screen);
  updateHint(screen);
}

function phoneSvg() {
  return [
    '<svg viewBox="0 0 24 24" aria-hidden="true" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8">',
    '<rect x="6" y="2" width="12" height="20" rx="2.5"/>',
    '<path d="M10.5 18.5h3"/>',
    "</svg>"
  ].join("");
}

function deviceRow(d) {
  var auth = d.authorization;
  var status = d.revokedAt
    ? '<span class="pillsm bad">revoked</span>'
    : '<span class="pillsm ok">active</span>';
  var cap = auth
    ? '<span class="pillsm">' + auth.remaining + "/" + auth.cap + " " + esc(auth.currency) + "</span>"
    : '<span class="pillsm muted">no cap</span>';
  return [
    '<button type="button" class="devrow" data-device="' + esc(d.deviceId) + '">',
    '<span class="devicon">' + phoneSvg() + "</span>",
    '<span class="devmain">',
    "<b>" + esc(d.platform === "ios" ? "iPhone" : "Android") + "</b>",
    "<small>" + esc(short(d.deviceId, 8, 4)) + " · " + esc(d.origin) + "</small>",
    "</span>",
    '<span class="devtags">' + status + cap + "</span>",
    "</button>"
  ].join("");
}

function preauthPanel(device) {
  var auth = device.authorization;
  if (device.revokedAt) return "";

  if (!auth || auth.status !== "active") {
    return [
      '<div class="panel">',
      '<div class="panelhead">Spend cap</div>',
      '<p class="hintline">A device needs a signed cap reserved against the wallet before it can transact offline.</p>',
      '<div class="row2">',
      '<div class="field"><label for="f-cap">Cap (minor units)</label><input id="f-cap" type="number" min="1" value="10000"></div>',
      select("currency", "Currency", [["NGN", "NGN"], ["USDC", "USDC"], ["USDT", "USDT"], ["KES", "KES"], ["GHS", "GHS"]]),
      "</div>",
      '<button type="button" class="cta secondary" id="do-preauth"' + (app.busy === "preauth" ? " disabled" : "") + ">" +
        (app.busy === "preauth" ? "Reserving…" : "Reserve a spend cap") + "</button>",
      "</div>"
    ].join("");
  }

  var pct = auth.cap ? Math.round((auth.spent / auth.cap) * 100) : 0;
  return [
    '<div class="panel">',
    '<div class="panelhead">Spend cap <span class="pillsm' + (auth.origin === "live" ? " ok" : "") + '">' + esc(auth.origin) + "</span></div>",
    '<div class="capbar"><span style="width:' + pct + '%"></span></div>',
    '<div class="capnums"><b>' + auth.remaining + "</b> of " + auth.cap + " " + esc(auth.currency) + " left</div>",
    '<div class="meta">',
    kv("Authorization", short(auth.authorizationId, 8, 4)),
    kv("Transactions", String(device.chainLength || 0)),
    "</div>",
    '<button type="button" class="cta danger" id="do-preauth-revoke"' + (app.busy === "preauth-revoke" ? " disabled" : "") + ">" +
      (app.busy === "preauth-revoke" ? "Releasing…" : "Release the hold") + "</button>",
    "</div>"
  ].join("");
}

function handshakeReport(result) {
  var rows = result.steps
    .map(function (s) {
      return [
        '<li class="' + (s.ok ? "ok" : "bad") + '">',
        '<span class="mark">' + (s.ok ? "✓" : "✕") + "</span>",
        "<span><b>" + esc(s.step) + "</b>",
        s.real ? "" : ' <span class="pillsm muted">not verifiable here</span>',
        "<small>" + esc(s.detail) + "</small></span>",
        "</li>"
      ].join("");
    })
    .join("");

  var head = result.ok
    ? '<div class="banner good"><b>Payment accepted offline.</b><span>' +
      result.summary.amount + " " + esc(result.summary.currency) + " · sequence " +
      result.summary.sequenceNumber + " · " + result.summary.remainingAfter + " left on the cap</span></div>"
    : '<div class="banner err"><b>Handshake refused.</b><span>' + esc(result.reason || "") + "</span></div>";

  return head + '<ol class="steps-list">' + rows + "</ol>";
}

function bannerHtml(banner) {
  var parts = ['<div class="banner ' + banner.kind + '">'];
  parts.push("<span><b>" + esc(banner.message) + "</b>" + (banner.status ? " <code>" + banner.status + "</code>" : "") + "</span>");
  if (banner.explanation) parts.push("<span>" + esc(banner.explanation) + "</span>");
  parts.push("</div>");
  return parts.join("");
}

function credentialCard(device) {
  var revoked = !!device.revokedAt;
  var claims = device.credentialClaims || {};
  return [
    '<div class="credcard' + (revoked ? " revoked" : "") + '">',
    '<div class="top">',
    '<div><div class="label">Payrit device credential</div><div class="big">' +
      esc(device.currency) + " wallet</div></div>",
    '<span class="chip' + (device.origin === "live" ? " live" : "") + '">' + esc(device.origin) + "</span>",
    "</div>",
    revoked
      ? '<div><div class="label">Revoked</div><div class="value">' + esc(device.revokedAt) + "</div></div>"
      : '<div><div class="label">Expires in</div><div class="value countdown big" data-exp="' +
        esc(device.credentialExpiresAt || "") +
        '">—</div></div>',
    '<div><div class="label">Credential</div><div class="value">' +
      esc(device.credential ? short(credentialBody(device.credential), 34, 12) : "none") +
      "</div></div>",
    '<div class="top" style="font-size:11px;opacity:.75">',
    "<span>refreshed " + (device.refreshCount || 0) + "×</span>",
    "<span>" + (claims.iss ? esc(claims.iss) : "") + "</span>",
    "</div>",
    "</div>"
  ].join("");
}

function credentialBody(raw) {
  try {
    var parsed = JSON.parse(raw);
    if (parsed && typeof parsed.credential === "string") return parsed.credential;
  } catch (e) {
  }
  return raw;
}

function field(id, label, placeholder, type) {
  return [
    '<div class="field">',
    '<label for="f-' + id + '">' + esc(label) + "</label>",
    '<input id="f-' + id + '" type="' + (type || "text") + '" placeholder="' + esc(placeholder) + '" value="' + esc(placeholder) + '">',
    "</div>"
  ].join("");
}

function select(id, label, options) {
  return [
    '<div class="field">',
    '<label for="f-' + id + '">' + esc(label) + "</label>",
    '<select id="f-' + id + '">',
    options
      .map(function (o) {
        return '<option value="' + esc(o[0]) + '">' + esc(o[1]) + "</option>";
      })
      .join(""),
    "</select>",
    "</div>"
  ].join("");
}

function kv(k, v) {
  return '<div class="kv"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v) + "</span></div>";
}

function fingerprintSvg() {
  return [
    '<svg viewBox="0 0 24 24" aria-hidden="true">',
    '<path d="M12 2a9 9 0 0 0-9 9v3"/>',
    '<path d="M21 14v-3a9 9 0 0 0-4.5-7.8"/>',
    '<path d="M7 20a12 12 0 0 1-1-5v-4a6 6 0 0 1 12 0v5"/>',
    '<path d="M10.5 21a9 9 0 0 1-.5-3v-7a2 2 0 0 1 4 0v7"/>',
    '<path d="M14 21v-3"/>',
    "</svg>"
  ].join("");
}

function wirePhone(screen) {
  if (screen === "signup") {
    $("do-signup").addEventListener("click", function () {
      createCustomer({
        firstName: $("f-first").value.trim(),
        lastName: $("f-last").value.trim(),
        email: $("f-email").value.trim(),
        phoneNumber: $("f-phone").value.trim()
      });
    });
  }

  if (screen === "secure") {
    $("do-enroll").addEventListener("click", function () {
      app.screen = null;
      enroll($("f-platform").value, $("f-currency").value);
    });
  }

  if (screen === "devices") {
    Array.prototype.forEach.call(document.querySelectorAll(".devrow"), function (row) {
      row.addEventListener("click", function () {
        goTo("device", row.getAttribute("data-device"));
      });
    });
    $("do-add").addEventListener("click", function () {
      goTo("enroll");
    });
    var pay = $("do-pay");
    if (pay) {
      pay.addEventListener("click", function () {
        app.handshake = null;
        goTo("pay");
      });
    }
  }

  if (screen === "device") {
    var device = activeDevice();
    var back = $("do-back");
    if (back) back.addEventListener("click", function () { goTo("devices"); });

    var refresh = $("do-refresh");
    if (refresh) refresh.addEventListener("click", function () { lifecycle("refresh", device.deviceId); });

    var revoke = $("do-revoke");
    if (revoke) revoke.addEventListener("click", function () { lifecycle("revoke", device.deviceId); });

    var add = $("do-add");
    if (add) add.addEventListener("click", function () { goTo("enroll"); });

    var pre = $("do-preauth");
    if (pre) {
      pre.addEventListener("click", function () {
        requestPreauth(device.deviceId, $("f-cap").value, $("f-currency").value);
      });
    }
    var preRevoke = $("do-preauth-revoke");
    if (preRevoke) {
      preRevoke.addEventListener("click", function () { revokePreauth(device.deviceId); });
    }
  }

  if (screen === "pay") {
    var payer = activeDevice();
    $("do-back").addEventListener("click", function () {
      app.handshake = null;
      goTo("devices");
    });
    $("do-handshake").addEventListener("click", function () {
      runHandshake(payer.deviceId, $("f-payee").value, Number($("f-amount").value));
    });
  }
}

function updateHint(screen) {
  var hints = {
    waiting: "The phone is idle until the institution has an API key — every enrollment call is authenticated as the institution, never as the customer.",
    signup: "POST /v1/customers. Devices enroll against a customer, so this record has to exist first.",
    secure: "One tap runs POST /v1/enroll/challenge, generates the key, builds the attestation, then POST /v1/enroll.",
    devices: "One customer, many devices. Each has its own hardware key, its own credential and its own spend cap.",
    device: "Refresh proves possession over a fresh nonce. The cap is POST /v1/authorizations, reserved against the wallet.",
    pay: "No network here. Payrit's role ended when the cap was issued — the two devices verify each other with signatures alone."
  };
  $("stage-hint").textContent = hints[screen] || "";
}

function renderSetup() {
  var s = app.state;
  var account = s && s.account;
  var key = s && s.key.present ? s.key : null;
  var customer = s && s.customer;
  var device = activeDevice();

  var configuredKey = key && key.source === "env";

  var rows = [
    {
      title: "Register a business account",
      route: "POST /v1/accounts",
      value: account
        ? account.name + " · " + short(account._id, 8, 4)
        : configuredKey
        ? "not needed — a key is configured"
        : null
    },
    {
      title: configuredKey ? "API key from configuration" : "Mint the bootstrap API key",
      route: configuredKey ? "PAYRIT_API_KEY" : "POST /v1/accounts/{id}/api-keys",
      value: key
        ? key.prefix + (key.environment ? " · " + key.environment : "") + (key.scopes ? " · " + key.scopes.length + " scopes" : "")
        : null
    },
    {
      title: "Create a customer",
      route: "POST /v1/customers",
      value: customer ? [customer.firstName, customer.lastName].filter(Boolean).join(" ") + " · " + short(customer._id, 8, 4) : null
    },
    {
      title: "Enroll a device",
      route: "POST /v1/enroll/challenge → POST /v1/enroll",
      value: device ? device.origin + " · " + short(device.deviceId, 8, 4) + (device.revokedAt ? " · revoked" : "") : null
    }
  ];

  var firstPending = -1;
  rows.forEach(function (r, i) {
    if (firstPending === -1 && !r.value) firstPending = i;
  });

  $("setup-steps").innerHTML = rows
    .map(function (r, i) {
      var cls = r.value ? "done" : i === firstPending ? "active" : "";
      return [
        '<div class="step ' + cls + '">',
        '<div class="num">' + (r.value ? "✓" : i + 1) + "</div>",
        '<div class="what"><b>' + esc(r.title) + "</b>",
        "<small>" + esc(r.route) + "</small>",
        r.value ? '<div class="val">' + esc(r.value) + "</div>" : "",
        "</div></div>"
      ].join("");
    })
    .join("");

  var done = rows.filter(function (r) { return r.value; }).length;
  var label = $("setup-state");
  label.textContent = done === 0 ? "not started" : done + " of 4 done";
  label.className = "pill" + (done === 4 ? " ok" : "");

  $("bootstrap-form").style.display = key ? "none" : "flex";
  $("bootstrap-btn").disabled = app.busy === "bootstrap";
  $("bootstrap-btn").textContent = app.busy === "bootstrap" ? "Registering…" : "Register & mint key";

  var keyLabel = $("key-label");
  var keyPill = $("pill-key");
  if (key) {
    keyLabel.textContent = key.prefix + (key.live ? " LIVE" : "");
    keyPill.className = "pill" + (key.live && !key.liveAllowed ? " bad" : "");
    keyPill.title = "source: " + key.source + (key.scopes ? " · " + key.scopes.join(", ") : "");
  } else {
    keyLabel.textContent = "none";
    keyPill.className = "pill";
  }

  if (s) {
    $("app-name").textContent = account ? account.name : "Kanto Microfinance";
    $("app-initial").textContent = (account ? account.name : "K").trim().charAt(0).toUpperCase();
  }
}

function highlight(value) {
  var json = JSON.stringify(value, null, 2);
  return esc(json)
    .replace(/&quot;([^&]*?)&quot;(\s*:)/g, '<span class="k">&quot;$1&quot;</span>$2')
    .replace(/:\s&quot;((?:[^&]|&(?!quot;))*)&quot;/g, ': <span class="s">&quot;$1&quot;</span>')
    .replace(/:\s(-?\d+(?:\.\d+)?|true|false|null)/g, ': <span class="n">$1</span>');
}

function entryHtml(row) {
  var statusClass = row.status ? "s" + String(row.status).charAt(0) : "";
  var parts = [
    '<details class="entry">',
    "<summary>",
    '<span class="tag ' + esc(row.origin) + '">' + (row.origin === "live" ? "live" : "sim") + "</span>",
    row.method ? '<span class="verb">' + esc(row.method) + "</span>" : "",
    '<span class="name">' + esc(row.label) + (row.url ? " · " + esc(row.url) : "") + "</span>",
    row.status ? '<span class="status ' + statusClass + '">' + row.status + "</span>" : "",
    row.ms !== null && row.ms !== undefined ? '<span class="ms">' + row.ms + "ms</span>" : "",
    "</summary>",
    '<div class="detail">'
  ];
  if (row.note) parts.push('<div class="note">' + esc(row.note) + "</div>");
  if (row.request) parts.push("<h4>request</h4><pre>" + highlight(row.request) + "</pre>");
  if (row.response) parts.push("<h4>response</h4><pre>" + highlight(row.response) + "</pre>");
  parts.push("</div></details>");
  return parts.join("");
}

function reloadEvents() {
  app.lastSeq = 0;
  app.eventCount = 0;
  $("log").innerHTML = "";
  api("/api/events" + (app.raw ? "?raw=1" : "")).then(function (r) {
    var rows = r.json.events || [];
    var log = $("log");
    if (!rows.length) {
      log.innerHTML = '<div class="empty">Nothing yet.</div>';
      return;
    }
    rows.forEach(function (row) {
      app.lastSeq = Math.max(app.lastSeq, row.seq);
      app.eventCount += 1;
      log.insertAdjacentHTML("afterbegin", entryHtml(row));
    });
    $("event-count").textContent = app.eventCount + (app.eventCount === 1 ? " call" : " calls");
  });
}

var POLL_MIN_MS = 1200;
var POLL_MAX_MS = 6000;

function schedulePoll(delay) {
  clearTimeout(app.pollTimer);
  app.pollTimer = setTimeout(pollEvents, delay);
}

function pollEvents() {
  if (document.hidden) return schedulePoll(POLL_MAX_MS);

  api("/api/events?since=" + app.lastSeq + (app.raw ? "&raw=1" : ""))
    .then(function (r) {
      var rows = r.json.events || [];
      if (!rows.length) {
        app.pollDelay = Math.min(POLL_MAX_MS, Math.round(app.pollDelay * 1.5));
        return schedulePoll(app.pollDelay);
      }
      app.pollDelay = POLL_MIN_MS;
      schedulePoll(app.pollDelay);

      var log = $("log");
      var empty = log.querySelector(".empty");
      if (empty) empty.remove();
      rows.forEach(function (row) {
        app.lastSeq = Math.max(app.lastSeq, row.seq);
        app.eventCount += 1;
        log.insertAdjacentHTML("afterbegin", entryHtml(row));
      });
      $("event-count").textContent = app.eventCount + (app.eventCount === 1 ? " call" : " calls");
    })
    .catch(function () {
      app.pollDelay = POLL_MAX_MS;
      schedulePoll(app.pollDelay);
    });
}

function tick() {
  var now = new Date();
  $("clock").textContent = now.toTimeString().slice(0, 5);

  var el = document.querySelector(".countdown");
  if (el) {
    var exp = el.getAttribute("data-exp");
    if (exp) {
      var left = Math.floor((new Date(exp).getTime() - Date.now()) / 1000);
      if (left <= 0) {
        el.textContent = "expired";
        el.style.opacity = ".7";
      } else {
        var h = Math.floor(left / 3600);
        var m = Math.floor((left % 3600) / 60);
        var sec = left % 60;
        el.textContent = h > 0 ? h + "h " + m + "m" : m + "m " + (sec < 10 ? "0" : "") + sec + "s";
      }
    }
  }
}

function render() {
  renderSetup();
  renderPhone();
  tick();
}

function setMode(mode) {
  app.mode = mode;
  $("mode-simulated").setAttribute("aria-pressed", String(mode === "simulated"));
  $("mode-live").setAttribute("aria-pressed", String(mode === "live"));
  if (mode === "live") {
    inform(
      "info",
      "Live mode: enrollment goes to the real deployment.",
      "It will reject this harness's attestation with a 422 — that is the documented fail-closed behaviour, not a bug in the harness."
    );
  } else {
    app.banner = null;
  }
  render();
}

function checkHealth() {
  api("/api/health").then(function (r) {
    var reachable = r.json.reachable;
    $("dot-api").className = "dot " + (reachable ? "ok" : "bad");
    var base = String(r.json.apiBase || "").replace(/^https?:\/\//, "");
    $("api-label").textContent = reachable ? base.split(".")[0].slice(0, 28) + "… reachable" : "deployment unreachable";
    $("pill-api").title = r.json.apiBase + (reachable ? "" : " — " + (r.json.error || r.json.status));
  });
}

$("mode-simulated").addEventListener("click", function () { setMode("simulated"); });
$("mode-live").addEventListener("click", function () { setMode("live"); });
$("bootstrap-form").addEventListener("submit", bootstrap);
$("reset").addEventListener("click", resetSession);
$("toggle-raw").addEventListener("click", function () {
  app.raw = !app.raw;
  this.setAttribute("aria-pressed", String(app.raw));
  this.textContent = app.raw ? "Trim values" : "Full values";
  reloadEvents();
});
$("clear-log").addEventListener("click", function () {
  $("log").innerHTML = '<div class="empty">Cleared. New calls will appear here.</div>';
  app.eventCount = 0;
  $("event-count").textContent = "0 calls";
});

readHash();
refreshState().then(checkHealth);
schedulePoll(POLL_MIN_MS);
document.addEventListener("visibilitychange", function () {
  if (!document.hidden) {
    app.pollDelay = POLL_MIN_MS;
    schedulePoll(200);
  }
});
setInterval(tick, 1000);

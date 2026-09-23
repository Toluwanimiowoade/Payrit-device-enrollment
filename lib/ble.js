"use strict";

var crypto = require("crypto");

var pb = require("./protobuf.js");
var preauth = require("./preauth.js");
var hardware = require("./hardware.js");
var credential = require("./credential.js");

var MODE_OFFLINE_BOTH = 1;

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function step(name, detail, ok, real) {
  return { step: name, ok: ok, real: real, detail: detail };
}

function buildTransaction(input) {
  return pb.encode({
    1: { type: "string", value: input.transactionId },
    2: { type: "string", value: input.senderInstitutionId },
    3: { type: "string", value: input.senderUserRef },
    4: { type: "string", value: input.receiverInstitutionId },
    5: { type: "string", value: input.receiverUserRef },
    6: { type: "uint", value: input.amount },
    7: { type: "string", value: input.currency },
    8: { type: "uint", value: input.timestamp },
    9: { type: "enum", value: MODE_OFFLINE_BOTH },
    11: { type: "string", value: input.preauthId },
    12: { type: "string", value: input.senderDeviceId },
    13: { type: "string", value: input.receiverDeviceId }
  });
}

function buildRecord(transactionBytes, sequenceNumber, previousRecordHash, runningConsumed) {
  return pb.encode({
    1: { type: "message", value: transactionBytes },
    2: { type: "uint", value: sequenceNumber },
    3: { type: "bytes", value: previousRecordHash },
    4: { type: "uint", value: runningConsumed }
  });
}

function decodeRecord(recordB64) {
  var fields = pb.decode(Buffer.from(recordB64, "base64"));
  var txn = fields[1] ? pb.decode(fields[1]) : {};
  function text(src, n) {
    return Buffer.isBuffer(src[n]) ? src[n].toString("utf8") : null;
  }
  return {
    transactionBytes: fields[1] || Buffer.alloc(0),
    sequenceNumber: fields[2] || 0,
    previousRecordHash: fields[3] || Buffer.alloc(0),
    runningConsumed: fields[4] || 0,
    transaction: {
      transactionId: text(txn, 1),
      senderInstitutionId: text(txn, 2),
      senderUserRef: text(txn, 3),
      receiverInstitutionId: text(txn, 4),
      receiverUserRef: text(txn, 5),
      amount: txn[6] || 0,
      currency: text(txn, 7),
      timestamp: txn[8] || 0,
      preauthId: text(txn, 11),
      senderDeviceId: text(txn, 12),
      receiverDeviceId: text(txn, 13)
    }
  };
}

function signWithDevice(device, bytes) {
  return crypto
    .sign("sha256", bytes, { key: crypto.createPrivateKey(device.privatePem), dsaEncoding: "ieee-p1363" })
    .toString("base64");
}

function verifyWithDevice(spkiB64, bytes, signatureB64) {
  try {
    var lines = spkiB64.match(/.{1,64}/g) || [];
    var pem = "-----BEGIN PUBLIC KEY-----\n" + lines.join("\n") + "\n-----END PUBLIC KEY-----\n";
    return crypto.verify(
      "sha256",
      bytes,
      { key: crypto.createPublicKey({ key: pem, format: "pem", type: "spki" }), dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureB64, "base64")
    );
  } catch (e) {
    return false;
  }
}

function credentialSignatureCheck(device) {
  var parsed = credential.parse(device.credential);
  if (!parsed) {
    return step(
      "Verify the Payrit signature on the credential",
      "credential is not in the expected {credential, signature} form",
      false,
      true
    );
  }
  if (device.origin === "live") {
    return step(
      "Verify the Payrit signature on the credential",
      "structure and expiry checked. The signature itself cannot be verified here: the Payrit CA " +
        "public key is embedded in the real SDK and is not published, so a real implementation " +
        "verifies this and the harness cannot.",
      true,
      false
    );
  }
  var bytes = Buffer.from(JSON.parse(device.credential).credential, "base64");
  var ok = preauth.verifySignature(bytes, JSON.parse(device.credential).signature);
  return step(
    "Verify the Payrit signature on the credential",
    ok ? "signature verified against the harness issuer key" : "signature did not verify",
    ok,
    true
  );
}

function expiryCheck(device) {
  var exp = device.credentialExpiresAt ? new Date(device.credentialExpiresAt).getTime() : 0;
  var ok = !device.revokedAt && exp > Date.now();
  return step(
    "Check credential expiry and status",
    device.revokedAt
      ? "device is revoked"
      : exp > Date.now()
      ? "credential valid until " + device.credentialExpiresAt
      : "credential has expired",
    ok,
    true
  );
}

function possessionCheck(label, device) {
  var nonce = crypto.randomBytes(32);
  var signature = signWithDevice(device, nonce);
  var ok = verifyWithDevice(device.publicKey, nonce, signature);
  return step(
    label,
    ok
      ? "32-byte random nonce signed with the device key and verified against its enrolled public key"
      : "signature did not verify",
    ok,
    true
  );
}

function preAuthorizationCheck(payer) {
  var auth = payer.authorization;
  if (!auth) {
    return step("Verify the payer's PreAuthorization", "the payer holds no pre-authorization", false, true);
  }
  var parsed = preauth.parse(auth.preAuthorization);
  var problems = [];

  if (auth.origin === "simulated") {
    if (!preauth.verifySignature(Buffer.from(auth.preAuthorization, "base64"), auth.signature)) {
      problems.push("Payrit signature did not verify");
    }
  }
  if (new Date(auth.expiresAt).getTime() < Date.now()) problems.push("authorization has expired");
  if (auth.status === "revoked") problems.push("authorization is revoked");
  if (parsed && parsed.deviceId && parsed.deviceId !== (payer.apiDeviceId || payer.deviceId)) {
    problems.push("device id in the authorization does not match the presenting device");
  }

  var detail =
    auth.origin === "live"
      ? "expiry, status, device id, currency and cap checked. The Payrit signature is not verifiable " +
        "here — the CA public key is not published."
      : "Payrit signature, expiry, status, device id, currency and cap all checked";

  return step(
    "Verify the payer's PreAuthorization",
    problems.length ? problems.join("; ") : detail,
    problems.length === 0,
    auth.origin !== "live"
  );
}

// Replays the payer's chain the way the receiving device would: every signature,
// every link back to the PreAuthorization, and the running total.
function replayChain(payer, chain) {
  var auth = payer.authorization;
  var anchor = sha256(Buffer.from(auth.preAuthorization, "base64"));
  var expectedPrevious = anchor;
  var consumed = 0;
  var problems = [];

  chain.forEach(function (entry, index) {
    var decoded = decodeRecord(entry.record);
    var bytes = Buffer.from(entry.record, "base64");

    if (decoded.sequenceNumber !== index + 1) {
      problems.push("record " + (index + 1) + ": sequence number is " + decoded.sequenceNumber);
    }
    if (decoded.previousRecordHash.toString("hex") !== expectedPrevious.toString("hex")) {
      problems.push("record " + (index + 1) + ": previous_record_hash does not match the chain");
    }
    if (!verifyWithDevice(payer.publicKey, bytes, entry.payerSignature)) {
      problems.push("record " + (index + 1) + ": payer signature did not verify");
    }
    consumed += decoded.transaction.amount;
    if (decoded.runningConsumed !== consumed) {
      problems.push(
        "record " + (index + 1) + ": running_consumed is " + decoded.runningConsumed + ", replay says " + consumed
      );
    }
    expectedPrevious = sha256(bytes);
  });

  return { problems: problems, consumed: consumed, nextPreviousHash: expectedPrevious };
}

// The handshake, as the docs describe it. Nothing here touches the network.
function handshake(input) {
  var payer = input.payer;
  var payee = input.payee;
  var amount = Number(input.amount);
  var chain = input.chain || [];
  var steps = [];

  steps.push(
    step(
      "Exchange Device Credentials",
      payer.platform + " device and " + payee.platform + " device swapped credentials and signatures",
      !!(payer.credential && payee.credential),
      true
    )
  );
  steps.push(credentialSignatureCheck(payer));
  steps.push(credentialSignatureCheck(payee));
  steps.push(expiryCheck(payer));
  steps.push(expiryCheck(payee));
  steps.push(possessionCheck("Payer proves possession of its hardware key", payer));
  steps.push(possessionCheck("Payee proves possession of its hardware key", payee));
  steps.push(preAuthorizationCheck(payer));

  var auth = payer.authorization;
  if (!auth) {
    return { ok: false, steps: steps, reason: "The payer needs a pre-authorization before it can spend." };
  }

  var replay = replayChain(payer, chain);
  steps.push(
    step(
      "Replay the payer's transaction chain",
      replay.problems.length
        ? replay.problems.join("; ")
        : chain.length === 0
        ? "no prior transactions under this authorization; the chain anchors to the PreAuthorization itself"
        : chain.length + " prior record(s) replayed, every signature and link checked, " +
          replay.consumed + " minor units already spent",
      replay.problems.length === 0,
      true
    )
  );

  var cap = Number(auth.cap);
  var remaining = cap - replay.consumed;
  var fits = amount > 0 && amount <= remaining;
  steps.push(
    step(
      "Confirm the new transaction fits inside the cap",
      fits
        ? amount + " fits in the " + remaining + " remaining of a " + cap + " " + auth.currency + " cap"
        : "requested " + amount + " but only " + remaining + " remains of the " + cap + " cap",
      fits,
      true
    )
  );

  var failed = steps.filter(function (s) {
    return !s.ok;
  });
  if (failed.length) {
    return { ok: false, steps: steps, reason: failed[0].step + ": " + failed[0].detail };
  }

  var transactionId = crypto.randomUUID();
  var transactionBytes = buildTransaction({
    transactionId: transactionId,
    senderInstitutionId: input.accountId,
    senderUserRef: payer.customerId,
    receiverInstitutionId: input.accountId,
    receiverUserRef: payee.customerId,
    amount: amount,
    currency: auth.currency,
    timestamp: Date.now(),
    preauthId: auth.authorizationId,
    senderDeviceId: payer.apiDeviceId || payer.deviceId,
    receiverDeviceId: payee.apiDeviceId || payee.deviceId
  });

  var sequenceNumber = chain.length + 1;
  var recordBytes = buildRecord(
    transactionBytes,
    sequenceNumber,
    replay.nextPreviousHash,
    replay.consumed + amount
  );
  var payerSignature = signWithDevice(payer, recordBytes);
  var receiverSignature = signWithDevice(
    payee,
    Buffer.concat([recordBytes, Buffer.from(payerSignature, "base64")])
  );

  steps.push(
    step(
      "Payer signs the TransactionRecord",
      "sequence " + sequenceNumber + ", chained to " + replay.nextPreviousHash.toString("hex").slice(0, 16) + "…",
      true,
      true
    )
  );
  steps.push(
    step(
      "Payee countersigns the record and the payer's signature",
      "the countersignature covers the record bytes plus the payer signature, binding it to that exact signature",
      true,
      true
    )
  );

  return {
    ok: true,
    steps: steps,
    transactionId: transactionId,
    entry: {
      record: recordBytes.toString("base64"),
      payerSignature: payerSignature,
      receiverSignature: receiverSignature
    },
    summary: {
      amount: amount,
      currency: auth.currency,
      cap: cap,
      consumedBefore: replay.consumed,
      consumedAfter: replay.consumed + amount,
      remainingAfter: cap - (replay.consumed + amount),
      sequenceNumber: sequenceNumber
    }
  };
}

module.exports = {
  handshake: handshake,
  replayChain: replayChain,
  decodeRecord: decodeRecord,
  buildTransaction: buildTransaction,
  buildRecord: buildRecord
};

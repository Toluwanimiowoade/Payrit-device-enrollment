"use strict";

var simulator = require("./simulator.js");

function readVarint(buf, i) {
  var result = 0;
  var shift = 0;
  var byte;
  do {
    if (i >= buf.length) return null;
    byte = buf[i++];
    result += (byte & 0x7f) * Math.pow(2, shift);
    shift += 7;
  } while (byte & 0x80);
  return { value: result, next: i };
}

function walk(buf) {
  var fields = {};
  var i = 0;
  while (i < buf.length) {
    var key = readVarint(buf, i);
    if (!key) break;
    var field = Math.floor(key.value / 8);
    var wire = key.value % 8;
    i = key.next;
    if (wire === 2) {
      var len = readVarint(buf, i);
      if (!len) break;
      i = len.next;
      fields[field] = buf.slice(i, i + len.value);
      i += len.value;
    } else if (wire === 0) {
      var v = readVarint(buf, i);
      if (!v) break;
      i = v.next;
      fields[field] = v.value;
    } else {
      break;
    }
  }
  return fields;
}

function asText(value) {
  return Buffer.isBuffer(value) ? value.toString("utf8") : null;
}

function asIso(value) {
  if (typeof value !== "number" || !value) return null;
  return new Date(value).toISOString();
}

function parse(raw) {
  if (!raw || typeof raw !== "string") return null;
  var outer;
  try {
    outer = JSON.parse(raw);
  } catch (e) {
    return null;
  }
  if (!outer || typeof outer.credential !== "string") return null;

  var fields;
  try {
    fields = walk(Buffer.from(outer.credential, "base64"));
  } catch (e) {
    return null;
  }

  return {
    format: "payrit-protobuf",
    deviceId: asText(fields[1]),
    paymentInstrumentId: asText(fields[2]),
    customerId: asText(fields[3]),
    accountId: asText(fields[4]),
    publicKey: Buffer.isBuffer(fields[5]) ? fields[5].toString("base64") : null,
    issuedAt: asIso(fields[7]),
    expiresAt: asIso(fields[8]),
    signature: typeof outer.signature === "string" ? outer.signature : null
  };
}

function claims(raw) {
  var payrit = parse(raw);
  if (payrit) {
    return {
      iss: "payrit",
      sub: payrit.deviceId,
      customerId: payrit.customerId,
      paymentInstrumentId: payrit.paymentInstrumentId,
      publicKey: payrit.publicKey,
      iat: payrit.issuedAt,
      exp: payrit.expiresAt
    };
  }
  return simulator.decodeCredential(raw);
}

module.exports = { parse: parse, claims: claims };

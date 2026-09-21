"use strict";

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  var bytes = [];
  var v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function tlv(tag, content) {
  var tagBuf = Buffer.isBuffer(tag) ? tag : Buffer.from([tag]);
  return Buffer.concat([tagBuf, encodeLength(content.length), content]);
}

function integer(value) {
  if (value === 0) return tlv(0x02, Buffer.from([0x00]));
  var bytes = [];
  var v = value;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }

  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return tlv(0x02, Buffer.from(bytes));
}

function enumerated(value) {
  return tlv(0x0a, Buffer.from([value]));
}

function octetString(buf) {
  return tlv(0x04, Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "utf8"));
}

function sequence(items) {
  return tlv(0x30, Buffer.concat(items));
}

function set(items) {
  return tlv(0x31, Buffer.concat(items));
}

function contextTagBytes(number) {
  if (number < 31) return Buffer.from([0xa0 | number]);
  var parts = [];
  var v = number;
  parts.unshift(v & 0x7f);
  v = Math.floor(v / 128);
  while (v > 0) {
    parts.unshift(0x80 | (v & 0x7f));
    v = Math.floor(v / 128);
  }
  return Buffer.concat([Buffer.from([0xbf]), Buffer.from(parts)]);
}

function explicit(number, content) {
  return tlv(contextTagBytes(number), content);
}

module.exports = {
  integer: integer,
  enumerated: enumerated,
  octetString: octetString,
  sequence: sequence,
  set: set,
  explicit: explicit,
  tlv: tlv
};

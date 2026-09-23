"use strict";

function varint(value) {
  var out = [];
  var v = value;
  while (v > 127) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v & 0x7f);
  return Buffer.from(out);
}

function key(field, wire) {
  return varint(field * 8 + wire);
}

function bytesField(field, buf) {
  var value = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), "utf8");
  return Buffer.concat([key(field, 2), varint(value.length), value]);
}

function stringField(field, text) {
  if (text === undefined || text === null || text === "") return Buffer.alloc(0);
  return bytesField(field, Buffer.from(String(text), "utf8"));
}

function uintField(field, value) {
  if (!value) return Buffer.alloc(0);
  return Buffer.concat([key(field, 0), varint(Number(value))]);
}

function enumField(field, value) {
  return uintField(field, value);
}

function encode(fields) {
  var parts = [];
  Object.keys(fields)
    .map(Number)
    .sort(function (a, b) {
      return a - b;
    })
    .forEach(function (num) {
      var spec = fields[num];
      if (spec === undefined || spec === null) return;
      if (spec.type === "string") parts.push(stringField(num, spec.value));
      else if (spec.type === "bytes") parts.push(bytesField(num, spec.value));
      else if (spec.type === "uint") parts.push(uintField(num, spec.value));
      else if (spec.type === "enum") parts.push(enumField(num, spec.value));
      else if (spec.type === "message") parts.push(bytesField(num, spec.value));
    });
  return Buffer.concat(parts);
}

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

function decode(buf) {
  var fields = {};
  var i = 0;
  while (i < buf.length) {
    var k = readVarint(buf, i);
    if (!k) break;
    var field = Math.floor(k.value / 8);
    var wire = k.value % 8;
    i = k.next;
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

module.exports = { encode: encode, decode: decode, varint: varint };

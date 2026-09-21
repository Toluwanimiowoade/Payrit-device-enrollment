"use strict";

function head(major, value) {
  var mt = major << 5;
  if (value < 24) return Buffer.from([mt | value]);
  if (value < 0x100) return Buffer.from([mt | 24, value]);
  if (value < 0x10000) {
    var b2 = Buffer.alloc(3);
    b2[0] = mt | 25;
    b2.writeUInt16BE(value, 1);
    return b2;
  }
  if (value < 0x100000000) {
    var b4 = Buffer.alloc(5);
    b4[0] = mt | 26;
    b4.writeUInt32BE(value, 1);
    return b4;
  }
  var b8 = Buffer.alloc(9);
  b8[0] = mt | 27;
  b8.writeUInt32BE(Math.floor(value / 0x100000000), 1);
  b8.writeUInt32BE(value >>> 0, 5);
  return b8;
}

function encode(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);

  if (typeof value === "string") {
    var utf8 = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, utf8.length), utf8]);
  }

  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error("cbor: only non-negative integers are supported, got " + value);
    }
    return Buffer.concat([head(0, value)]);
  }

  if (Array.isArray(value)) {
    var items = value.map(encode);
    return Buffer.concat([head(4, value.length)].concat(items));
  }

  if (value && typeof value === "object") {
    var keys = Object.keys(value);
    var pairs = keys.map(function (k) {
      return Buffer.concat([encode(k), encode(value[k])]);
    });
    return Buffer.concat([head(5, keys.length)].concat(pairs));
  }

  throw new Error("cbor: unsupported value " + Object.prototype.toString.call(value));
}

module.exports = { encode: encode };

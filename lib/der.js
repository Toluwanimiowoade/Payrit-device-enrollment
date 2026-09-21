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


function oid(dotted) {
  var parts = String(dotted).split(".").map(Number);
  var bytes = [parts[0] * 40 + parts[1]];
  parts.slice(2).forEach(function (part) {
    var chunk = [];
    var v = part;
    chunk.unshift(v & 0x7f);
    v = Math.floor(v / 128);
    while (v > 0) {
      chunk.unshift(0x80 | (v & 0x7f));
      v = Math.floor(v / 128);
    }
    bytes = bytes.concat(chunk);
  });
  return tlv(0x06, Buffer.from(bytes));
}

function bitString(buf) {
  return tlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
}

function boolean(value) {
  return tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function utf8String(text) {
  return tlv(0x0c, Buffer.from(text, "utf8"));
}

function utcTime(date) {
  function pad(n) {
    return (n < 10 ? "0" : "") + n;
  }
  var text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    "Z";
  return tlv(0x17, Buffer.from(text, "ascii"));
}

function raw(buf) {
  return Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
}

function readLength(buf, i) {
  var first = buf[i];
  if (first < 0x80) return { value: first, next: i + 1 };
  var count = first & 0x7f;
  var value = 0;
  for (var k = 0; k < count; k++) value = value * 256 + buf[i + 1 + k];
  return { value: value, next: i + 1 + count };
}

function readTlv(buf, offset) {
  var i = offset || 0;
  var tagStart = i;
  if ((buf[i] & 0x1f) === 0x1f) {
    i++;
    while (buf[i] & 0x80) i++;
    i++;
  } else {
    i++;
  }
  var len = readLength(buf, i);
  var contentStart = len.next;
  var end = contentStart + len.value;
  return {
    tag: buf.slice(tagStart, i),
    header: buf.slice(tagStart, contentStart),
    content: buf.slice(contentStart, end),
    full: buf.slice(tagStart, end),
    end: end
  };
}

function children(buf) {
  var out = [];
  var i = 0;
  while (i < buf.length) {
    var node = readTlv(buf, i);
    out.push(node);
    i = node.end;
  }
  return out;
}

module.exports = {
  integer: integer,
  oid: oid,
  bitString: bitString,
  boolean: boolean,
  utf8String: utf8String,
  utcTime: utcTime,
  raw: raw,
  readTlv: readTlv,
  children: children,
  enumerated: enumerated,
  octetString: octetString,
  sequence: sequence,
  set: set,
  explicit: explicit,
  tlv: tlv
};

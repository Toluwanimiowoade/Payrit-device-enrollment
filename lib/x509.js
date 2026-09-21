"use strict";

var crypto = require("crypto");
var der = require("./der.js");

var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var OID_CN = "2.5.4.3";
var OID_O = "2.5.4.10";
var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_KEY_USAGE = "2.5.29.15";

var ALG_ECDSA_SHA256 = der.sequence([der.oid(OID_ECDSA_SHA256)]);

function name(fields) {
  var rdns = [];
  if (fields.CN) rdns.push(der.set([der.sequence([der.oid(OID_CN), der.utf8String(fields.CN)])]));
  if (fields.O) rdns.push(der.set([der.sequence([der.oid(OID_O), der.utf8String(fields.O)])]));
  return der.sequence(rdns);
}

function extension(oidText, critical, valueDer) {
  var parts = [der.oid(oidText)];
  if (critical) parts.push(der.boolean(true));
  parts.push(der.octetString(valueDer));
  return der.sequence(parts);
}

function basicConstraints(isCa) {
  return extension(
    OID_BASIC_CONSTRAINTS,
    true,
    isCa ? der.sequence([der.boolean(true)]) : der.sequence([])
  );
}

function keyUsage(bits) {
  var unused = 0;
  var byte = bits;
  while (unused < 8 && !((byte >> unused) & 1)) unused++;
  return extension(
    OID_KEY_USAGE,
    true,
    der.tlv(0x03, Buffer.from([unused, bits]))
  );
}

function spkiOf(publicKey) {
  return crypto.createPublicKey(publicKey).export({ type: "spki", format: "der" });
}

function serialBytes(value) {
  var buf = value ? Buffer.from(value, "hex") : crypto.randomBytes(8);
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  return der.tlv(0x02, buf);
}

function issue(options) {
  var notBefore = options.notBefore || new Date(Date.now() - 60 * 1000);
  var notAfter = options.notAfter || new Date(Date.now() + 365 * 24 * 3600 * 1000);

  var extensions = [];
  if (options.isCa) {
    extensions.push(basicConstraints(true));
    extensions.push(keyUsage(0x06));
  } else {
    extensions.push(basicConstraints(false));
    extensions.push(keyUsage(0x80));
  }
  (options.extensions || []).forEach(function (ext) {
    extensions.push(extension(ext.oid, !!ext.critical, ext.value));
  });

  var tbs = der.sequence([
    der.explicit(0, der.integer(2)),
    serialBytes(options.serial),
    ALG_ECDSA_SHA256,
    options.issuerNameDer ? der.raw(options.issuerNameDer) : name(options.issuer),
    der.sequence([der.utcTime(notBefore), der.utcTime(notAfter)]),
    name(options.subject),
    der.raw(spkiOf(options.subjectPublicKey)),
    der.explicit(3, der.sequence(extensions))
  ]);

  var signature = crypto.sign("sha256", tbs, crypto.createPrivateKey(options.issuerPrivateKey));

  return der.sequence([tbs, ALG_ECDSA_SHA256, der.bitString(signature)]);
}

function selfSign(options) {
  return issue({
    subject: options.subject,
    issuer: options.subject,
    subjectPublicKey: options.privateKey,
    issuerPrivateKey: options.privateKey,
    isCa: options.isCa,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    serial: options.serial,
    extensions: options.extensions
  });
}

function subjectNameDer(cert) {
  var certDer = Buffer.isBuffer(cert) ? cert : fromPem(cert);
  return parse(certDer).subject;
}

function toPem(certDer) {
  var lines = certDer.toString("base64").match(/.{1,64}/g) || [];
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") + "\n-----END CERTIFICATE-----\n";
}

function fromPem(pem) {
  var body = String(pem)
    .replace(/-----[^-]+-----/g, "")
    .replace(/\\n/g, "")
    .replace(/[^A-Za-z0-9+/=]/g, "");
  return Buffer.from(body, "base64");
}

function parse(certDer) {
  var cert = der.readTlv(certDer);
  var parts = der.children(cert.content);
  var tbs = parts[0];
  var signature = parts[2];
  var fields = der.children(tbs.content);

  var offset = fields[0].tag[0] === 0xa0 ? 1 : 0;
  var issuerNode = fields[offset + 2];
  var subjectNode = fields[offset + 4];
  var spkiNode = fields[offset + 5];

  var extensionsNode = null;
  fields.forEach(function (f) {
    if (f.tag[0] === 0xa3) extensionsNode = f;
  });

  return {
    tbs: tbs.full,
    issuer: issuerNode.full,
    subject: subjectNode.full,
    spki: spkiNode.full,
    signature: signature.content.slice(1),
    extensions: extensionsNode ? der.children(der.readTlv(extensionsNode.content).content) : []
  };
}

function commonName(nameDer) {
  var found = null;
  der.children(der.readTlv(nameDer).content).forEach(function (rdn) {
    der.children(rdn.content).forEach(function (atv) {
      var pair = der.children(atv.content);
      if (pair.length === 2 && pair[0].content.toString("hex") === "550403") {
        found = pair[1].content.toString("utf8");
      }
    });
  });
  return found;
}

function findExtension(cert, oidText) {
  var wanted = der.oid(oidText).slice(2).toString("hex");
  var value = null;
  cert.extensions.forEach(function (ext) {
    var parts = der.children(ext.content);
    if (parts[0].content.toString("hex") !== wanted) return;
    value = parts[parts.length - 1].content;
  });
  return value;
}

// Verifies that `child` was signed by `issuer`'s key, and that the names line up.
function verifySignedBy(childDer, issuerDer) {
  var child = parse(childDer);
  var issuer = parse(issuerDer);
  if (child.issuer.toString("hex") !== issuer.subject.toString("hex")) return false;
  var key = crypto.createPublicKey({ key: issuer.spki, format: "der", type: "spki" });
  try {
    return crypto.verify("sha256", child.tbs, key, child.signature);
  } catch (e) {
    return false;
  }
}

module.exports = {
  issue: issue,
  selfSign: selfSign,
  toPem: toPem,
  fromPem: fromPem,
  parse: parse,
  subjectNameDer: subjectNameDer,
  commonName: commonName,
  findExtension: findExtension,
  verifySignedBy: verifySignedBy,
  spkiOf: spkiOf
};

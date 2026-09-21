"use strict";

var der = require("./der.js");

var OID = "1.3.6.1.4.1.11129.2.1.17";

var SECURITY_LEVEL = { software: 0, trustedEnvironment: 1, strongBox: 2 };

var TAG_PURPOSE = 1;
var TAG_ALGORITHM = 2;
var TAG_KEY_SIZE = 3;
var TAG_DIGEST = 5;
var TAG_EC_CURVE = 10;
var TAG_NO_AUTH_REQUIRED = 503;
var TAG_ORIGIN = 702;
var TAG_ATTESTATION_APPLICATION_ID = 709;

var PURPOSE_SIGN = 2;
var PURPOSE_VERIFY = 3;
var ALGORITHM_EC = 3;
var DIGEST_SHA256 = 4;
var EC_CURVE_P256 = 1;
var ORIGIN_GENERATED = 0;

function attestationApplicationId(packageName, packageVersion, signatureDigests) {
  var packageInfo = der.sequence([
    der.octetString(Buffer.from(packageName, "utf8")),
    der.integer(packageVersion || 1)
  ]);
  var digests = signatureDigests.map(function (d) {
    return der.octetString(Buffer.isBuffer(d) ? d : Buffer.from(d, "hex"));
  });
  return der.sequence([der.set([packageInfo]), der.set(digests)]);
}

function teeEnforcedList(options) {
  var where = (options && options.appIdLocation) || "software";
  var extra = where === "tee" || where === "both" ? [appIdEntry(options)] : [];
  return der.sequence([
    der.explicit(TAG_PURPOSE, der.set([der.integer(PURPOSE_SIGN), der.integer(PURPOSE_VERIFY)])),
    der.explicit(TAG_ALGORITHM, der.integer(ALGORITHM_EC)),
    der.explicit(TAG_KEY_SIZE, der.integer(256)),
    der.explicit(TAG_DIGEST, der.set([der.integer(DIGEST_SHA256)])),
    der.explicit(TAG_EC_CURVE, der.integer(EC_CURVE_P256)),
    der.explicit(TAG_NO_AUTH_REQUIRED, der.tlv(0x05, Buffer.alloc(0))),
    der.explicit(TAG_ORIGIN, der.integer(ORIGIN_GENERATED))
  ].concat(extra));
}

function appIdEntry(options) {
  return der.explicit(
    TAG_ATTESTATION_APPLICATION_ID,
    der.octetString(
      attestationApplicationId(options.packageName, options.packageVersion, options.signatureDigests)
    )
  );
}

function softwareEnforcedList(options) {
  var where = options.appIdLocation || "software";
  if (where === "tee") return der.sequence([]);
  return der.sequence([appIdEntry(options)]);
}

function buildExtension(options) {
  var challenge = Buffer.isBuffer(options.challenge)
    ? options.challenge
    : Buffer.from(options.challenge, "utf8");

  var level =
    typeof options.securityLevel === "number"
      ? options.securityLevel
      : SECURITY_LEVEL[options.securityLevel || "trustedEnvironment"];

  return der.sequence([
    der.integer(options.attestationVersion || 3),
    der.enumerated(level),
    der.integer(options.keymasterVersion || 4),
    der.enumerated(level),
    der.octetString(challenge),
    der.octetString(Buffer.alloc(0)),
    softwareEnforcedList(options),
    teeEnforcedList(options)
  ]);
}

module.exports = {
  buildExtension: buildExtension,
  OID: OID
};

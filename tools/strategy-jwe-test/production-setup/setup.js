// strategy-jwe-prototype/vendor/jose/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var strictDecoder = new TextDecoder("utf-8", { fatal: true });
var MAX_INT32 = 2 ** 32;
var NON_ASCII = /[^\x00-\x7f]/;
function encode(string) {
  if (typeof string == "string" && string.length >= 128) {
    if (NON_ASCII.test(string))
      throw new TypeError("non-ASCII string encountered in encode()");
    return encoder.encode(string);
  }
  const bytes2 = new Uint8Array(string.length);
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i);
    if (code > 127)
      throw new TypeError("non-ASCII string encountered in encode()");
    bytes2[i] = code;
  }
  return bytes2;
}
function encodeBase64(input, url = false) {
  if (Uint8Array.prototype.toBase64)
    return input.toBase64({ alphabet: url ? "base64url" : "base64", omitPadding: url });
  const CHUNK_SIZE = 32768, arr = [];
  for (let i = 0; i < input.length; i += CHUNK_SIZE)
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
  const encoded = btoa(arr.join(""));
  return url ? encoded.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_") : encoded;
}
function decodeBase64(encoded, url = false) {
  if (Uint8Array.fromBase64)
    return Uint8Array.fromBase64(encoded, { alphabet: url ? "base64url" : "base64" });
  if (url) {
    if (encoded.includes("+") || encoded.includes("/"))
      throw new TypeError("Invalid base64url");
    encoded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  }
  const binary = atob(encoded), bytes2 = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes2[i] = binary.charCodeAt(i);
  return bytes2;
}
async function digest(algorithm, data) {
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
}

// strategy-jwe-prototype/vendor/jose/util/errors.js
var JOSEError = class extends Error {
  static code = "ERR_JOSE_GENERIC";
  code = "ERR_JOSE_GENERIC";
  constructor(message2, options) {
    super(message2, options), this.name = this.constructor.name, Error.captureStackTrace?.(this, this.constructor);
  }
};
var JOSENotSupported = class extends JOSEError {
  static code = "ERR_JOSE_NOT_SUPPORTED";
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWKInvalid = class extends JOSEError {
  static code = "ERR_JWK_INVALID";
  code = "ERR_JWK_INVALID";
};

// strategy-jwe-prototype/vendor/jose/util/base64url.js
var invalid = "The input to be decoded is not correctly encoded.";
function decode(input) {
  try {
    return decodeBase64(typeof input == "string" ? input : decoder.decode(input), true);
  } catch (cause) {
    throw new TypeError(invalid, { cause });
  }
}
function encode2(input) {
  return encodeBase64(typeof input == "string" ? encoder.encode(input) : input, true);
}

// strategy-jwe-prototype/vendor/jose/lib/validate.js
function isObject(input) {
  if (typeof input != "object" || input === null || Object.prototype.toString.call(input) !== "[object Object]")
    return false;
  const prototype = Object.getPrototypeOf(input);
  return prototype === null || Object.getPrototypeOf(prototype) === null;
}

// strategy-jwe-prototype/vendor/jose/lib/key.js
var isCryptoKey = (key) => {
  if (key?.[Symbol.toStringTag] === "CryptoKey")
    return true;
  try {
    return key instanceof CryptoKey;
  } catch {
    return false;
  }
};
var isKeyObject = (key) => key?.[Symbol.toStringTag] === "KeyObject";
var isKeyLike = (key) => isCryptoKey(key) || isKeyObject(key);
function message(msg, actual, ...types) {
  if (types.length > 2) {
    const last = types.pop();
    msg += `one of type ${types.join(", ")}, or ${last}.`;
  } else types.length === 2 ? msg += `one of type ${types[0]} or ${types[1]}.` : msg += `of type ${types[0]}.`;
  return actual == null ? msg += ` Received ${actual}` : typeof actual == "function" && actual.name ? msg += ` Received function ${actual.name}` : typeof actual == "object" && actual != null && actual.constructor?.name && (msg += ` Received an instance of ${actual.constructor.name}`), msg;
}
var invalidKeyInput = (actual, ...types) => message("Key must be ", actual, ...types);
function snapshotJwk(jwk) {
  return { __proto__: null, ...jwk };
}
function normalizeJwk(jwk) {
  const normalized = snapshotJwk(jwk);
  if (normalized.ext !== void 0 && typeof normalized.ext != "boolean")
    throw new TypeError('"ext" (Extractable) Parameter must be a boolean');
  if (normalized.key_ops !== void 0) {
    const value = normalized.key_ops, keyOps = Array.isArray(value) ? [...value] : void 0;
    if (!keyOps || keyOps.some((operation) => typeof operation != "string") || new Set(keyOps).size !== keyOps.length)
      throw new TypeError('"key_ops" (Key Operations) Parameter must be an array of unique strings');
    normalized.key_ops = keyOps;
  }
  return normalized;
}
function validateExtractableOption(extractable) {
  if (extractable !== void 0 && typeof extractable != "boolean")
    throw new TypeError('"extractable" option must be a boolean');
  return extractable;
}
async function jwkToKey(entry, jwk, extractable) {
  if (!entry.kty.includes(jwk.kty))
    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  const algorithm = entry.resolve?.({ kty: jwk.kty, crv: jwk.crv }) ?? entry.subtle, isPrivate = !!(jwk.d || jwk.priv), keyData = { ...jwk, ext: extractable ?? jwk.ext };
  return keyData.kty !== "AKP" && delete keyData.alg, delete keyData.use, crypto.subtle.importKey("jwk", keyData, algorithm, keyData.ext ?? !isPrivate, jwk.key_ops ?? entry.usages[isPrivate ? 1 : 0]);
}

// strategy-jwe-prototype/vendor/jose/lib/key_descriptor.js
function table(entries) {
  const out = { __proto__: null };
  for (const alg in entries)
    out[alg] = { ...entries[alg], alg };
  return out;
}

// strategy-jwe-prototype/vendor/jose/lib/jwe_algorithms.js
var wrap = [
  ["encrypt", "wrapKey"],
  ["decrypt", "unwrapKey"]
];
var derive = [[], ["deriveBits"]];
var none = [[], []];
function rsaes(bits) {
  return {
    kty: ["RSA"],
    mode: "key-encryption",
    subtle: { name: "RSA-OAEP", hash: `SHA-${bits}` },
    usages: wrap,
    ops: ["wrapKey", "unwrapKey"]
  };
}
function ecdh(mode) {
  return {
    kty: ["EC", "OKP"],
    mode,
    subtle: { name: "ECDH" },
    resolve: ({ kty, crv, asymmetricKeyType }) => {
      if (crv === "X25519" || asymmetricKeyType === "x25519")
        return { name: "X25519" };
      if (kty === "OKP")
        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      return { name: "ECDH", namedCurve: crv };
    },
    usages: derive,
    ops: [void 0, "deriveBits"]
  };
}
function aeskw(bits, gcm = false) {
  return {
    kty: ["oct"],
    mode: "key-wrapping",
    secret: true,
    subtle: { name: gcm ? "AES-GCM" : "AES-KW", length: bits },
    usages: none,
    ops: gcm ? ["encrypt", "decrypt"] : ["wrapKey", "unwrapKey"]
  };
}
function pbes2() {
  return {
    kty: ["oct"],
    mode: "key-wrapping",
    secret: true,
    subtle: { name: "PBKDF2" },
    usages: none,
    ops: ["deriveBits", "deriveBits"]
  };
}
var JWE = table({
  dir: {
    kty: ["oct"],
    mode: "direct-encryption",
    secret: true,
    subtle: { name: "AES-GCM" },
    usages: none,
    ops: ["encrypt", "decrypt"]
  },
  "RSA-OAEP": rsaes(1),
  "RSA-OAEP-256": rsaes(256),
  "RSA-OAEP-384": rsaes(384),
  "RSA-OAEP-512": rsaes(512),
  "ECDH-ES": ecdh("direct-key-agreement"),
  "ECDH-ES+A128KW": ecdh("key-agreement-with-key-wrapping"),
  "ECDH-ES+A192KW": ecdh("key-agreement-with-key-wrapping"),
  "ECDH-ES+A256KW": ecdh("key-agreement-with-key-wrapping"),
  A128KW: aeskw(128),
  A192KW: aeskw(192),
  A256KW: aeskw(256),
  A128GCMKW: aeskw(128, true),
  A192GCMKW: aeskw(192, true),
  A256GCMKW: aeskw(256, true),
  "PBES2-HS256+A128KW": pbes2(),
  "PBES2-HS384+A192KW": pbes2(),
  "PBES2-HS512+A256KW": pbes2()
});
var contentOps = ["encrypt", "decrypt"];
function contentEncryption(bits, cbc = false) {
  return {
    kty: ["oct"],
    secret: true,
    subtle: { name: cbc ? "AES-CBC" : "AES-GCM", length: bits },
    usages: none,
    ops: contentOps,
    cekBits: bits,
    ivBits: cbc ? 128 : 96,
    cbc
  };
}
var ENC = table({
  A128GCM: contentEncryption(128),
  A192GCM: contentEncryption(192),
  A256GCM: contentEncryption(256),
  "A128CBC-HS256": contentEncryption(256, true),
  "A192CBC-HS384": contentEncryption(384, true),
  "A256CBC-HS512": contentEncryption(512, true)
});

// strategy-jwe-prototype/vendor/jose/lib/jws_algorithms.js
var sig = [["verify"], ["sign"]];
function hmac(bits) {
  const subtle = { name: "HMAC", hash: `SHA-${bits}` };
  return { kty: ["oct"], secret: true, subtle, signing: subtle, usages: sig };
}
function rsa(bits, saltLength) {
  const subtle = { name: saltLength ? "RSA-PSS" : "RSASSA-PKCS1-v1_5", hash: `SHA-${bits}` };
  return {
    kty: ["RSA"],
    subtle,
    signing: saltLength ? { ...subtle, saltLength } : subtle,
    usages: sig,
    minRsaBits: 2048
  };
}
function ecdsa(crv, bits) {
  return {
    kty: ["EC"],
    crv,
    subtle: { name: "ECDSA", namedCurve: crv },
    signing: { name: "ECDSA", hash: `SHA-${bits}` },
    usages: sig
  };
}
function eddsa() {
  const subtle = { name: "Ed25519" };
  return {
    kty: ["OKP"],
    crv: "Ed25519",
    subtle,
    signing: subtle,
    usages: sig
  };
}
function mldsa(bits) {
  const subtle = { name: `ML-DSA-${bits}` };
  return {
    kty: ["AKP"],
    subtle,
    signing: subtle,
    usages: sig
  };
}
var JWS = table({
  HS256: hmac(256),
  HS384: hmac(384),
  HS512: hmac(512),
  RS256: rsa(256),
  RS384: rsa(384),
  RS512: rsa(512),
  PS256: rsa(256, 32),
  PS384: rsa(384, 48),
  PS512: rsa(512, 64),
  ES256: ecdsa("P-256", 256),
  ES384: ecdsa("P-384", 384),
  ES512: ecdsa("P-521", 512),
  EdDSA: eddsa(),
  Ed25519: eddsa(),
  "ML-DSA-44": mldsa(44),
  "ML-DSA-65": mldsa(65),
  "ML-DSA-87": mldsa(87)
});

// strategy-jwe-prototype/vendor/jose/lib/key_algorithm.js
var algArgument = '"alg" (Algorithm)';
function unsupportedAlg(source = 'JWK "alg" (Algorithm) Parameter') {
  throw new JOSENotSupported(`Invalid or unsupported ${source} value`);
}
function keyAlgorithm(alg, source) {
  return (typeof alg == "string" ? JWS[alg] ?? JWE[alg] : void 0) ?? unsupportedAlg(source);
}

// strategy-jwe-prototype/vendor/jose/lib/asn1.js
var formatPEM = (b642, descriptor) => {
  const newlined = (b642.match(/.{1,64}/g) || []).join(`
`);
  return `-----BEGIN ${descriptor}-----
${newlined}
-----END ${descriptor}-----`;
};
var genericExport = async (keyType, keyFormat, key) => {
  if (isKeyObject(key)) {
    if (key.type !== keyType)
      throw new TypeError(`key is not a ${keyType} key`);
    return key.export({ format: "pem", type: keyFormat });
  }
  if (!isCryptoKey(key))
    throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject"));
  if (!key.extractable)
    throw new TypeError("CryptoKey is not extractable");
  if (key.type !== keyType)
    throw new TypeError(`key is not a ${keyType} key`);
  return formatPEM(encodeBase64(new Uint8Array(await crypto.subtle.exportKey(keyFormat, key))), `${keyType.toUpperCase()} KEY`);
};
var toPKCS8 = (key) => genericExport("private", "pkcs8", key);
var bytesEqual = (a, b) => {
  if (a.byteLength !== b.length)
    return false;
  for (let i = 0; i < a.byteLength; i++)
    if (a[i] !== b[i])
      return false;
  return true;
};
var createASN1State = (data) => ({ data, pos: 0 });
var readByte = (state) => {
  const byte = state.data[state.pos++];
  if (byte === void 0)
    throw new Error("Unexpected end of ASN.1 input");
  return byte;
};
var parseLength = (state) => {
  const first = readByte(state);
  if (first & 128) {
    const lengthOfLen = first & 127;
    let length = 0;
    for (let i = 0; i < lengthOfLen; i++)
      length = length << 8 | readByte(state);
    return length;
  }
  return first;
};
var expectTag = (state, expectedTag, errorMessage) => {
  if (readByte(state) !== expectedTag)
    throw new Error(errorMessage);
};
var getSubarray = (state, length) => {
  if (length < 0 || state.pos + length > state.data.length)
    throw new Error("Unexpected end of ASN.1 input");
  const result = state.data.subarray(state.pos, state.pos + length);
  return state.pos += length, result;
};
var parseAlgorithmOID = (state) => {
  expectTag(state, 6, "Expected algorithm OID");
  const oidLen = parseLength(state);
  return getSubarray(state, oidLen);
};
function parseKeyHeader(state, keyFormat) {
  if (expectTag(state, 48, `Invalid ${keyFormat === "spki" ? "SPKI" : "PKCS#8"} structure`), parseLength(state), keyFormat === "pkcs8") {
    expectTag(state, 2, "Expected version field");
    const length = parseLength(state);
    state.pos += length;
  }
  expectTag(state, 48, "Expected algorithm identifier"), parseLength(state);
}
var parseECAlgorithmIdentifier = (state) => {
  const algOid = parseAlgorithmOID(state);
  if (bytesEqual(algOid, [43, 101, 110]))
    return "X25519";
  if (!bytesEqual(algOid, [42, 134, 72, 206, 61, 2, 1]))
    throw new Error("Unsupported key algorithm");
  expectTag(state, 6, "Expected curve OID");
  const curveOidLen = parseLength(state), curveOid = getSubarray(state, curveOidLen);
  if (bytesEqual(curveOid, [42, 134, 72, 206, 61, 3, 1, 7]))
    return "P-256";
  if (bytesEqual(curveOid, [43, 129, 4, 0, 34]))
    return "P-384";
  if (bytesEqual(curveOid, [43, 129, 4, 0, 35]))
    return "P-521";
  throw new Error("Unsupported named curve");
};
var genericImport = async (keyFormat, keyData, alg, options) => {
  const extractable = validateExtractableOption(options?.extractable), entry = keyAlgorithm(alg, algArgument);
  entry.secret && unsupportedAlg(algArgument);
  const isPublic = keyFormat === "spki";
  let algorithm;
  if (entry.resolve)
    try {
      const state = createASN1State(keyData);
      parseKeyHeader(state, keyFormat), algorithm = entry.resolve({ crv: parseECAlgorithmIdentifier(state) });
    } catch {
      throw new JOSENotSupported("Invalid or unsupported key format");
    }
  else
    algorithm = entry.subtle;
  return crypto.subtle.importKey(keyFormat, keyData, algorithm, extractable ?? isPublic, entry.usages[isPublic ? 0 : 1]);
};
var processPEMData = (pem, pattern) => decodeBase64(pem.replace(pattern, ""));
var fromPKCS8 = (pem, alg, options) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g);
  return genericImport("pkcs8", keyData, alg, options);
};

// strategy-jwe-prototype/vendor/jose/key/export.js
function exportPKCS8(key) {
  return toPKCS8(key);
}
async function exportJWK(key) {
  if (isKeyObject(key))
    if (key.type === "secret")
      key = key.export();
    else
      return key.export({ format: "jwk" });
  if (key instanceof Uint8Array)
    return {
      kty: "oct",
      k: encode2(key)
    };
  if (!isCryptoKey(key))
    throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject", "Uint8Array"));
  if (!key.extractable)
    throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
  const jwk = await crypto.subtle.exportKey("jwk", key);
  delete jwk.ext, delete jwk.key_ops, delete jwk.use, jwk.kty !== "AKP" && delete jwk.alg;
  for (const parameter of Object.keys(jwk))
    jwk[parameter] === void 0 && delete jwk[parameter];
  return jwk;
}

// strategy-jwe-prototype/vendor/jose/jwk/thumbprint.js
var check = (value, description) => {
  if (typeof value != "string" || !value)
    throw new JWKInvalid(`${description} missing or invalid`);
};
async function calculateJwkThumbprint(key, digestAlgorithm) {
  let jwk;
  if (isObject(key)) {
    if (jwk = snapshotJwk(key), typeof jwk.kty != "string")
      throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject", "JSON Web Key"));
  } else if (isKeyLike(key))
    jwk = snapshotJwk(await exportJWK(key));
  else
    throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject", "JSON Web Key"));
  if (digestAlgorithm ??= "sha256", digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384" && digestAlgorithm !== "sha512")
    throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
  let components;
  switch (jwk.kty) {
    case "AKP":
      check(jwk.alg, '"alg" (Algorithm) Parameter'), check(jwk.pub, '"pub" (Public key) Parameter'), components = { alg: jwk.alg, kty: jwk.kty, pub: jwk.pub };
      break;
    case "EC":
      check(jwk.crv, '"crv" (Curve) Parameter'), check(jwk.x, '"x" (X Coordinate) Parameter'), check(jwk.y, '"y" (Y Coordinate) Parameter'), components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case "OKP":
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter'), check(jwk.x, '"x" (Public Key) Parameter'), components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    case "RSA":
      check(jwk.e, '"e" (Exponent) Parameter'), check(jwk.n, '"n" (Modulus) Parameter'), components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case "oct":
      if (typeof jwk.k != "string")
        throw new JWKInvalid('"k" (Key Value) Parameter missing or invalid');
      components = { k: jwk.k, kty: jwk.kty };
      break;
    default:
      throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
  }
  const data = encode(JSON.stringify(components));
  return encode2(await digest(digestAlgorithm, data));
}

// strategy-jwe-prototype/vendor/jose/jwks/remote.js
var USER_AGENT;
(typeof navigator > "u" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) && (USER_AGENT = "jose/v6.2.12");

// strategy-jwe-prototype/vendor/jose/key/import.js
async function importPKCS8(pkcs8, alg, options) {
  if (typeof pkcs8 != "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0)
    throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
  return fromPKCS8(pkcs8, alg, options);
}
async function importJWK(jwk, alg, options) {
  if (!isObject(jwk))
    throw new TypeError("JWK must be an object");
  const normalized = normalizeJwk(jwk), extractable = validateExtractableOption(options?.extractable), { alg: jwkAlg } = normalized;
  if (alg ??= jwkAlg, normalized.kty !== "oct" && !alg)
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  switch (normalized.kty) {
    case "oct":
      if (typeof normalized.k != "string")
        throw new TypeError('missing "k" (Key Value) Parameter value');
      return decode(normalized.k);
    case "AKP": {
      if (typeof jwkAlg != "string" || !jwkAlg)
        throw new TypeError('missing "alg" (Algorithm) Parameter value');
      if (alg !== jwkAlg)
        throw new TypeError("JWK alg and alg option value mismatch");
      return jwkToKey(keyAlgorithm(alg), normalized, extractable);
    }
    case "RSA":
    case "EC":
    case "OKP":
      return jwkToKey(keyAlgorithm(alg), normalized, extractable);
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}

// strategy-jwe-prototype/vendor/jose/key/generate_key_pair.js
function getModulusLengthOption(options) {
  const modulusLength = options?.modulusLength ?? 2048;
  if (typeof modulusLength != "number" || !Number.isInteger(modulusLength) || modulusLength < 2048)
    throw new JOSENotSupported("Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used");
  return modulusLength;
}
async function generateKeyPair(alg, options) {
  const extractable = validateExtractableOption(options?.extractable), entry = keyAlgorithm(alg, algArgument);
  entry.secret && unsupportedAlg(algArgument);
  let algorithm;
  if (entry.resolve) {
    const crv = options?.crv ?? "P-256";
    if (!["P-256", "P-384", "P-521", "X25519"].includes(crv))
      throw new JOSENotSupported("Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, and X25519");
    algorithm = entry.resolve({ crv });
  } else {
    if (entry.crv !== void 0 && options?.crv !== void 0 && options.crv !== entry.crv)
      throw new JOSENotSupported(`Invalid or unsupported crv option provided, the only supported value for ${alg} is ${entry.crv}`);
    algorithm = entry.kty[0] === "RSA" ? {
      ...entry.subtle,
      publicExponent: Uint8Array.of(1, 0, 1),
      modulusLength: getModulusLengthOption(options)
    } : entry.subtle;
  }
  return crypto.subtle.generateKey(algorithm, extractable ?? false, [
    ...entry.usages[1],
    ...entry.usages[0]
  ]);
}

// strategy-jwe-prototype/production/crypto.mjs
var LIMITS = Object.freeze({ plaintext: 12e4, jwe: 2e5, backup: 12e3, public: 2e3 });
var E = new TextEncoder();
var D = new TextDecoder("utf-8", { fatal: true });
var EXACT = (x, keys) => x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).sort().join(",") === [...keys].sort().join(",");
var fail = (code) => {
  throw new Error(code);
};
var bytes = (x) => E.encode(JSON.stringify(x));
var b64 = (b) => btoa(String.fromCharCode(...b)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
var unb64 = (x) => {
  if (typeof x !== "string" || !/^[A-Za-z0-9_-]+$/.test(x)) fail("ENCODING_INVALID");
  return Uint8Array.from(atob(x.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
};
var validKid = (x) => typeof x === "string" && /^[A-Za-z0-9_-]{43}$/.test(x);
async function publicKey(config, pinnedKid) {
  if (bytes(config).length > LIMITS.public || !EXACT(config, ["format", "version", "kid", "jwk"]) || config.format !== "strategy-public-key" || config.version !== 1 || !validKid(config.kid)) fail("PUBLIC_CONFIG_INVALID");
  const k = config.jwk;
  if (!EXACT(k, ["kty", "n", "e"]) || k.kty !== "RSA" || k.e !== "AQAB" || typeof k.n !== "string" || !/^[A-Za-z0-9_-]{512}$/.test(k.n)) fail("PUBLIC_JWK_INVALID");
  const n = unb64(k.n);
  if (n.length !== 384 || n[0] < 128) fail("PUBLIC_JWK_INVALID");
  const kid = await calculateJwkThumbprint(k, "sha256");
  if (kid !== config.kid || kid !== pinnedKid) fail("PUBLIC_KEY_PIN_MISMATCH");
  return importJWK(k, "RSA-OAEP-256");
}
function checkPassword(password, creating = false) {
  if (typeof password !== "string" || password.length > 1024 || !password.length || creating && [...password].length < 16) fail("PASSPHRASE_INVALID");
}
async function derive2(password, salt) {
  checkPassword(password);
  const key = await crypto.subtle.importKey("raw", E.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", iterations: 6e5, salt }, key, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function createOwnerBundle(password) {
  checkPassword(password, true);
  const pair = await generateKeyPair("RSA-OAEP-256", { modulusLength: 3072, extractable: true });
  const jwk = await exportJWK(pair.publicKey), kid = await calculateJwkThumbprint(jwk, "sha256");
  const config = { format: "strategy-public-key", version: 1, kid, jwk };
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derive2(password, salt), plain = E.encode(await exportPKCS8(pair.privateKey));
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: E.encode("strategy-key-backup:1:" + kid) }, key, plain);
    return { config, backup: { format: "strategy-key-backup", version: 1, kid, kdf: { name: "PBKDF2", hash: "SHA-256", iterations: 6e5, salt: b64(salt) }, cipher: { name: "AES-GCM", iv: b64(iv), data: b64(new Uint8Array(ciphertext)) } } };
  } finally {
    plain.fill(0);
  }
}
function validateBackup(backup, expectedKid) {
  if (bytes(backup).length > LIMITS.backup || !EXACT(backup, ["format", "version", "kid", "kdf", "cipher"]) || backup.format !== "strategy-key-backup" || backup.version !== 1 || !validKid(backup.kid) || backup.kid !== expectedKid) fail("BACKUP_FORMAT_INVALID");
  const k = backup.kdf, c = backup.cipher;
  if (!EXACT(k, ["name", "hash", "iterations", "salt"]) || k.name !== "PBKDF2" || k.hash !== "SHA-256" || k.iterations !== 6e5 || typeof k.salt !== "string" || k.salt.length !== 22 || !EXACT(c, ["name", "iv", "data"]) || c.name !== "AES-GCM" || typeof c.iv !== "string" || c.iv.length !== 16 || typeof c.data !== "string" || c.data.length > 11e3) fail("BACKUP_FORMAT_INVALID");
  const salt = unb64(k.salt), iv = unb64(c.iv), data = unb64(c.data);
  if (salt.length !== 16 || iv.length !== 12 || data.length < 128 || data.length > 8192) fail("BACKUP_FORMAT_INVALID");
  return { salt, iv, data };
}
async function unlockOwnerBundle(backup, password, config, pinnedKid) {
  const pub = await publicKey(config, pinnedKid), { salt, iv, data } = validateBackup(backup, pinnedKid);
  checkPassword(password);
  const kek = await derive2(password, salt);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: E.encode("strategy-key-backup:1:" + pinnedKid) }, kek, data);
  } catch {
    fail("BACKUP_UNLOCK_FAILED");
  }
  let privateKey;
  try {
    privateKey = await importPKCS8(D.decode(plain), "RSA-OAEP-256", { extractable: false });
  } finally {
    new Uint8Array(plain).fill(0);
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  try {
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, challenge), result = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrapped));
    if (result.length !== challenge.length || result.some((v, i) => v !== challenge[i])) fail("KEY_PAIR_MISMATCH");
  } catch {
    fail("KEY_PAIR_MISMATCH");
  }
  return privateKey;
}

// strategy-jwe-prototype/production/storage.mjs
var DATABASE = "company-report-strategy-encrypted-backups-v1";
var STORE = "encryptedBackups";
async function database() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DATABASE, 1);
    r.onupgradeneeded = () => {
      r.result.createObjectStore(STORE);
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(new Error("LOCAL_STORAGE_UNAVAILABLE"));
  });
}
async function saveEncryptedBackup(backup, kid) {
  validateBackup(backup, kid);
  const db = await database();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(backup, kid);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(new Error("LOCAL_STORAGE_FAILED"));
      tx.onabort = () => reject(new Error("LOCAL_STORAGE_FAILED"));
    });
  } finally {
    db.close();
  }
}

// strategy-jwe-prototype/production/synthetic-setup.mjs
var $ = (id) => document.getElementById(id);
var ENABLE_ENROLLMENT = true;
var bundle;
var status = (text) => $("status").textContent = text;
function download(name, value) {
  const u = URL.createObjectURL(new Blob([JSON.stringify(value)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1e3);
}
if (!ENABLE_ENROLLMENT) {
  $("create").disabled = true;
  status("\uC124\uC815 \uAE30\uB2A5\uC740 \uAC80\uC218 \uC911\uC785\uB2C8\uB2E4. \uC2E4\uC81C \uBE44\uBC00\uBC88\uD638\uB098 \uBCF5\uAD6C \uD0A4\uB97C \uC785\uB825\uD558\uC9C0 \uB9C8\uC138\uC694.");
}
$("setup-form").onsubmit = async (event) => {
  event.preventDefault();
  if (!ENABLE_ENROLLMENT) return;
  const a = $("password").value, b = $("password-again").value;
  $("password").value = $("password-again").value = "";
  if (a !== "PUBLIC SYNTHETIC fixture password 2026") {
    status("\uC774 \uAC00\uC0C1 \uD14C\uC2A4\uD2B8\uB294 \uD45C\uC2DC\uB41C \uACF5\uAC1C \uC554\uD638\uB9CC \uD5C8\uC6A9\uD569\uB2C8\uB2E4.");
    $("create").disabled = false;
    return;
  }
  if (a !== b) {
    status("\uB450 \uBE44\uBC00\uBC88\uD638\uAC00 \uC77C\uCE58\uD558\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.");
    return;
  }
  if (!$("consent").checked) {
    status("\uD0A4 \uC0DD\uC131\xB7\uBCF4\uAD00 \uC548\uB0B4\uB97C \uD655\uC778\uD574 \uC8FC\uC138\uC694.");
    return;
  }
  $("create").disabled = true;
  try {
    bundle = await createOwnerBundle(a);
    await unlockOwnerBundle(bundle.backup, a, bundle.config, bundle.config.kid);
    $("fingerprint").textContent = bundle.config.kid;
    $("public-json").value = JSON.stringify(bundle.config);
    $("ready").hidden = false;
    status("\uD0A4\uB97C \uB9CC\uB4E4\uACE0 \uBCF5\uAD6C \uC2DC\uD5D8\uC744 \uB9C8\uCCE4\uC2B5\uB2C8\uB2E4. \uBCF5\uAD6C \uD30C\uC77C\uC744 \uC548\uC804\uD55C \uACF3\uC5D0 \uC800\uC7A5\uD558\uACE0 \uACF5\uAC1C\uD0A4\uB9CC \uC804\uB2EC\uD558\uC138\uC694.");
  } catch {
    bundle = void 0;
    status("\uD0A4\uB97C \uC900\uBE44\uD558\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4. 16\uC790 \uC774\uC0C1\uC758 \uAE34 \uBE44\uBC00\uBC88\uD638\uC640 \uBE0C\uB77C\uC6B0\uC800 \uC9C0\uC6D0\uC744 \uD655\uC778\uD558\uC138\uC694.");
    $("create").disabled = false;
  }
};
$("backup").onclick = () => {
  if (bundle) download("strategy-encrypted-recovery.json", bundle.backup);
};
$("public").onclick = () => {
  if (bundle) download("strategy-public-key.json", bundle.config);
};
$("save").onclick = async () => {
  if (!ENABLE_ENROLLMENT || !bundle || !$("backed-up").checked || !$("remember").checked) {
    status("\uBCF5\uAD6C \uD30C\uC77C \uBCF4\uAD00\uACFC \uC774 \uBE0C\uB77C\uC6B0\uC800 \uC800\uC7A5 \uB3D9\uC758\uB97C \uD655\uC778\uD574 \uC8FC\uC138\uC694.");
    return;
  }
  try {
    await saveEncryptedBackup(bundle.backup, bundle.config.kid);
    status("\uC554\uD638\uD654 \uBCF5\uAD6C \uD0A4\uB97C \uC800\uC7A5\uD588\uC2B5\uB2C8\uB2E4. \uACF5\uAC1C\uD0A4\uB97C \uC804\uB2EC\uD558\uBA74 \uC0C8 \uC804\uB7B5\uC740 \uC554\uD638 \uC785\uB825 \uC5C6\uC774 \uCD94\uAC00\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.");
  } catch {
    status("\uBE0C\uB77C\uC6B0\uC800 \uC800\uC7A5\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4. \uB2E4\uC6B4\uB85C\uB4DC\uD55C \uBCF5\uAD6C \uD30C\uC77C\uC744 \uBCF4\uAD00\uD558\uC138\uC694.");
  }
};

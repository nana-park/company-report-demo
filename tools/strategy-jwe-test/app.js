// vendor/jose/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var strictDecoder = new TextDecoder("utf-8", { fatal: true });
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0), buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers)
    buf.set(buffer, i), i += buffer.length;
  return buf;
}
function writeUInt32BE(buf, value, offset) {
  if (value < 0 || value >= MAX_INT32)
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32), low = value % MAX_INT32, buf = new Uint8Array(8);
  return writeUInt32BE(buf, high, 0), writeUInt32BE(buf, low, 4), buf;
}
function uint32be(value) {
  const buf = new Uint8Array(4);
  return writeUInt32BE(buf, value), buf;
}
var NON_ASCII = /[^\x00-\x7f]/;
function encode(string) {
  if (typeof string == "string" && string.length >= 128) {
    if (NON_ASCII.test(string))
      throw new TypeError("non-ASCII string encountered in encode()");
    return encoder.encode(string);
  }
  const bytes = new Uint8Array(string.length);
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i);
    if (code > 127)
      throw new TypeError("non-ASCII string encountered in encode()");
    bytes[i] = code;
  }
  return bytes;
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
  const binary = atob(encoded), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function digest(algorithm, data) {
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
}

// vendor/jose/util/errors.js
var JOSEError = class extends Error {
  static code = "ERR_JOSE_GENERIC";
  code = "ERR_JOSE_GENERIC";
  constructor(message2, options) {
    super(message2, options), this.name = this.constructor.name, Error.captureStackTrace?.(this, this.constructor);
  }
};
var JOSEAlgNotAllowed = class extends JOSEError {
  static code = "ERR_JOSE_ALG_NOT_ALLOWED";
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
};
var JOSENotSupported = class extends JOSEError {
  static code = "ERR_JOSE_NOT_SUPPORTED";
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWEDecryptionFailed = class extends JOSEError {
  static code = "ERR_JWE_DECRYPTION_FAILED";
  code = "ERR_JWE_DECRYPTION_FAILED";
  constructor(message2 = "decryption operation failed", options) {
    super(message2, options);
  }
};
var JWEInvalid = class extends JOSEError {
  static code = "ERR_JWE_INVALID";
  code = "ERR_JWE_INVALID";
};
var JWKInvalid = class extends JOSEError {
  static code = "ERR_JWK_INVALID";
  code = "ERR_JWK_INVALID";
};

// vendor/jose/util/base64url.js
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

// vendor/jose/lib/validate.js
function isObject(input) {
  if (typeof input != "object" || input === null || Object.prototype.toString.call(input) !== "[object Object]")
    return false;
  const prototype = Object.getPrototypeOf(input);
  return prototype === null || Object.getPrototypeOf(prototype) === null;
}
function isDisjoint(...headers) {
  const parameters = /* @__PURE__ */ new Set();
  for (const header of headers)
    if (header)
      for (const parameter of Object.keys(header)) {
        if (parameters.has(parameter))
          return false;
        parameters.add(parameter);
      }
  return true;
}
function decodeBase64url(value, label, ErrorClass) {
  try {
    return decode(value);
  } catch {
    throw new ErrorClass(`Failed to base64url decode the ${label}`);
  }
}
function encodeBase64url(value, label, ErrorClass) {
  try {
    return encode(value);
  } catch {
    throw new ErrorClass(`The ${label} is not a valid base64url string`);
  }
}
function parseJoseHeader(b64, ErrorClass, message2) {
  let parsed;
  try {
    parsed = JSON.parse(strictDecoder.decode(decode(b64)));
  } catch {
    throw new ErrorClass(message2);
  }
  if (!isObject(parsed))
    throw new ErrorClass(message2);
  return parsed;
}
var JWE_RECOGNIZED = { __proto__: null };
function validateAlgorithms(option, algorithms) {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s != "string")))
    throw new TypeError(`"${option}" option must be an array of strings`);
  return algorithms === void 0 ? void 0 : new Set(algorithms);
}
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0)
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  if (!protectedHeader || protectedHeader.crit === void 0)
    return [];
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input != "string" || input.length === 0))
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  const recognized = recognizedOption === void 0 ? recognizedDefault : { __proto__: null, ...recognizedOption, ...recognizedDefault };
  for (const parameter of protectedHeader.crit) {
    if (!(parameter in recognized))
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    if (!Object.hasOwn(joseHeader, parameter) || joseHeader[parameter] === void 0)
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    if (recognized[parameter] && (!Object.hasOwn(protectedHeader, parameter) || protectedHeader[parameter] === void 0))
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
  }
  return protectedHeader.crit;
}

// vendor/jose/lib/key.js
var tag = (key) => key[Symbol.toStringTag];
var jwkMatchesOp = (entry, key, usage) => {
  const { alg } = entry;
  if (key.use !== void 0) {
    const expected = usage === "sign" || usage === "verify" ? "sig" : "enc";
    if (key.use !== expected)
      throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
  }
  if (key.alg !== void 0 && key.alg !== alg)
    throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
  if (Array.isArray(key.key_ops)) {
    const expectedKeyOp = usage === "encrypt" || usage === "decrypt" ? entry.ops?.[usage === "encrypt" ? 0 : 1] : usage;
    if (expectedKeyOp && !key.key_ops.includes(expectedKeyOp))
      throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
  }
};
async function prepareKey(entry, key, usage) {
  const { alg, secret } = entry, privateKey2 = usage === "decrypt" || usage === "sign";
  if (secret && key instanceof Uint8Array)
    return key;
  let normalized, keyObject;
  if (isObject(key)) {
    if (normalized = normalizeJwk(key), typeof normalized.kty != "string")
      throw invalidKeyType(alg, key, secret);
    if (!(secret ? normalized.kty === "oct" && typeof normalized.k == "string" : normalized.kty !== "oct" && (privateKey2 ? normalized.kty === "AKP" && typeof normalized.priv == "string" || typeof normalized.d == "string" : normalized.d === void 0 && normalized.priv === void 0)))
      throw new TypeError(secret ? 'JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present' : `JSON Web Key for this operation must be a ${privateKey2 ? "private" : "public"} JWK`);
    if (jwkMatchesOp(entry, normalized, usage), normalized.kty === "oct")
      return decode(normalized.k);
    if (!Object.isFrozen(key)) {
      const { key_ops } = key;
      Array.isArray(key_ops) && Object.freeze(key_ops), Object.freeze(key);
    }
  } else {
    if (!isKeyLike(key))
      throw invalidKeyType(alg, key, secret);
    const expectedType = secret ? "secret" : privateKey2 ? "private" : "public";
    if (key.type !== expectedType && (secret || ["secret", "public", "private"].includes(key.type)))
      throw new TypeError(`${tag(key)} instances must be of type "${expectedType}" for the ${alg} algorithm`);
    if (isCryptoKey(key))
      return key;
    if (keyObject = key, keyObject.type === "secret")
      return keyObject.export();
  }
  cache ||= /* @__PURE__ */ new WeakMap();
  const cacheKey = key;
  let cached = cache.get(cacheKey);
  if (cached?.[alg])
    return cached[alg];
  if (cached || cache.set(cacheKey, cached = {}), keyObject && typeof keyObject.toCryptoKey == "function") {
    const isPublic = keyObject.type === "public", crv = nist[keyObject.asymmetricKeyDetails?.namedCurve], params = entry.resolve?.({ crv, asymmetricKeyType: keyObject.asymmetricKeyType }) ?? entry.subtle;
    return cached[alg] = keyObject.toCryptoKey(params, isPublic, entry.usages[isPublic ? 0 : 1]);
  }
  return normalized ??= keyObject.export({ format: "jwk" }), normalized.alg = alg, cached[alg] = await jwkToKey(entry, normalized);
}
var cache;
var nist = {
  __proto__: null,
  prime256v1: "P-256",
  secp384r1: "P-384",
  secp521r1: "P-521"
};
function assertCryptoKey(key) {
  if (!isCryptoKey(key))
    throw new Error("CryptoKey instance expected");
}
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
function invalidKeyType(alg, actual, secret) {
  const types = ["CryptoKey", "KeyObject", "JSON Web Key"];
  return secret && types.push("Uint8Array"), new TypeError(message(`Key for the ${alg} algorithm must be `, actual, ...types));
}
var unusable = (name, prop = "algorithm.name") => new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
function checkUsage(key, usage) {
  if (usage && !key.usages.includes(usage))
    throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
}
function checkModulusLength(alg, key) {
  const { modulusLength } = key.algorithm;
  if (typeof modulusLength != "number" || modulusLength < 2048)
    throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
}
function checkCryptoKey(key, expected, usage) {
  const algorithm = key.algorithm;
  if (algorithm.name !== expected.name)
    throw unusable(expected.name);
  if (expected.hash && algorithm.hash?.name !== expected.hash)
    throw unusable(expected.hash, "algorithm.hash");
  if (expected.namedCurve && algorithm.namedCurve !== expected.namedCurve)
    throw unusable(expected.namedCurve, "algorithm.namedCurve");
  if (expected.length !== void 0 && algorithm.length !== expected.length)
    throw unusable(expected.length, "algorithm.length");
  checkUsage(key, usage);
}
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
async function rawKey(key, expected, usage, extractable = false) {
  return key instanceof Uint8Array && (key = await crypto.subtle.importKey("raw", key, expected, extractable, [usage])), checkCryptoKey(key, expected, usage), key;
}

// vendor/jose/lib/content_encryption.js
var generateCek = (enc2) => crypto.getRandomValues(new Uint8Array(enc2.cekBits >> 3));
function checkCekLength(cek, expected) {
  const actual = cek.byteLength << 3;
  if (actual !== expected)
    throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
}
function checkIvLength(enc2, iv) {
  if (iv.length << 3 !== enc2.ivBits)
    throw new JWEInvalid("Invalid Initialization Vector length");
}
async function cbcKeySetup(enc2, cek, usage) {
  if (!(cek instanceof Uint8Array))
    throw new TypeError(invalidKeyInput(cek, "Uint8Array"));
  const keySize = enc2.cekBits >> 1, encKey = await crypto.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, [usage]), macKey = await crypto.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  return [encKey, macKey, keySize];
}
async function cbcHmacTag(macKey, macData, keySize) {
  return new Uint8Array((await crypto.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
}
async function timingSafeEqual(a, b) {
  const algorithm = { name: "HMAC", hash: "SHA-256" }, key = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]), aHmac = await crypto.subtle.sign(algorithm, key, a);
  return crypto.subtle.verify(algorithm, key, aHmac, b);
}
async function cbcDecrypt(enc2, cek, ciphertext2, iv, tag2, aad) {
  const [encKey, macKey, keySize] = await cbcKeySetup(enc2, cek, "decrypt"), macData = concat(aad, iv, ciphertext2, uint64be(aad.length * 8)), expectedTag = await cbcHmacTag(macKey, macData, keySize);
  try {
    if (await timingSafeEqual(tag2, expectedTag))
      return new Uint8Array(await crypto.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext2));
  } catch {
  }
  throw new JWEDecryptionFailed();
}
async function decrypt(enc2, cek, ciphertext2, iv, tag2, aad) {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array))
    throw new TypeError(invalidKeyInput(cek, "CryptoKey", "KeyObject", "Uint8Array", "JSON Web Key"));
  if (!iv)
    throw new JWEInvalid("JWE Initialization Vector missing");
  if (!tag2)
    throw new JWEInvalid("JWE Authentication Tag missing");
  if (!enc2.cbc && tag2.length !== 16)
    throw new JWEInvalid("Invalid Authentication Tag length");
  if (checkIvLength(enc2, iv), cek instanceof Uint8Array && checkCekLength(cek, enc2.cekBits), enc2.cbc)
    return cbcDecrypt(enc2, cek, ciphertext2, iv, tag2, aad);
  const encKey = await rawKey(cek, enc2.subtle, "decrypt");
  try {
    return new Uint8Array(await crypto.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext2, tag2)));
  } catch {
    throw new JWEDecryptionFailed();
  }
}

// vendor/jose/lib/key_descriptor.js
function table(entries) {
  const out = { __proto__: null };
  for (const alg in entries)
    out[alg] = { ...entries[alg], alg };
  return out;
}

// vendor/jose/lib/jwe_algorithms.js
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
function unsupported(parameter, name) {
  throw new JOSENotSupported(`Invalid or unsupported "${parameter}" (JWE ${name}) header value`);
}
function jweAlgorithm(alg) {
  return (typeof alg == "string" ? JWE[alg] : void 0) ?? unsupported("alg", "Algorithm");
}
function isJWECEKTransport(algorithm) {
  return algorithm.mode === "key-wrapping" || algorithm.mode === "key-encryption" || algorithm.mode === "key-agreement-with-key-wrapping";
}
function jweEncryption(enc2) {
  return (typeof enc2 == "string" ? ENC[enc2] : void 0) ?? unsupported("enc", "Encryption Algorithm");
}

// vendor/jose/lib/key_management.js
function checkEcdhCryptoKey(key, usage) {
  if (key.algorithm.name !== "ECDH" && key.algorithm.name !== "X25519")
    throw new TypeError("CryptoKey does not support this operation, its algorithm.name must be ECDH or X25519");
  checkUsage(key, usage);
}
async function aeskwUnwrap(alg, key, encryptedKey) {
  const cryptoKey = await rawKey(key, jweAlgorithm(alg).subtle, "unwrapKey", true), cryptoKeyCek = await crypto.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", { hash: "SHA-256", name: "HMAC" }, true, ["sign"]);
  return new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKeyCek));
}
function checkRsaKey(alg, key, usage) {
  checkCryptoKey(key, jweAlgorithm(alg).subtle, usage), checkModulusLength(alg, key);
}
async function deriveKey(p2s, alg, p2c, key) {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8)
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  if (!Number.isSafeInteger(p2c) || Math.sign(p2c) !== 1)
    throw new JWEInvalid("PBES2 Count Input must be a positive integer");
  const salt = concat(encode(alg), Uint8Array.of(0), p2s), keylen = parseInt(alg.slice(13, 16), 10), subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  }, cryptoKey = await rawKey(key, jweAlgorithm(alg).subtle, "deriveBits");
  return new Uint8Array(await crypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(Z, L, OtherInfo) {
  const dkLen = L >> 3, hashLen = 32, reps = Math.ceil(dkLen / hashLen), dk = new Uint8Array(reps * hashLen);
  for (let i = 1; i <= reps; i++) {
    const hashResult = await digest("sha256", concat(uint32be(i), Z, OtherInfo));
    dk.set(hashResult, (i - 1) * hashLen);
  }
  return dk.slice(0, dkLen);
}
async function ecdhesDeriveKey(publicKey, privateKey2, algorithm, keyLength, apu = new Uint8Array(), apv = new Uint8Array()) {
  checkEcdhCryptoKey(publicKey), checkEcdhCryptoKey(privateKey2, "deriveBits");
  const otherInfo = concat(lengthAndInput(encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength)), Z = new Uint8Array(await crypto.subtle.deriveBits({
    name: publicKey.algorithm.name,
    public: publicKey
  }, privateKey2, publicKey.algorithm.name === "X25519" ? 256 : Math.ceil(parseInt(publicKey.algorithm.namedCurve.slice(-3), 10) / 8) << 3));
  return concatKdf(Z, keyLength, otherInfo);
}
function assertEcdhKey(key) {
  assertCryptoKey(key);
  const curve = key.algorithm.namedCurve;
  if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521" && key.algorithm.name !== "X25519")
    throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
}
function partyInfo(joseHeader, name) {
  const value = joseHeader[name];
  if (value !== void 0) {
    if (typeof value != "string")
      throw new JWEInvalid(`JOSE Header "${name}" (Agreement Party${name === "apu" ? "U" : "V"}Info) invalid`);
    return decodeBase64url(value, name, JWEInvalid);
  }
}
function checkPartyInfo(apu, apv) {
  if (!(apu === void 0 || apv === void 0 || apu.byteLength !== apv.byteLength)) {
    for (let i = 0; i < apu.byteLength; i++)
      if (apu[i] !== apv[i])
        return;
    throw new JWEInvalid('JOSE Header "apu" and "apv" values must be distinct');
  }
}
function assertEncryptedKey(encryptedKey) {
  if (encryptedKey === void 0)
    throw new JWEInvalid("JWE Encrypted Key missing");
}
function assertNoEncryptedKey(encryptedKey) {
  if (encryptedKey !== void 0)
    throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
}
function validateMaxPBES2Count(value) {
  if (value !== void 0 && value !== 1 / 0 && (!Number.isSafeInteger(value) || value < 1))
    throw new TypeError("maxPBES2Count must be a positive safe integer or Infinity");
}
async function decryptKeyManagement(entry, enc2, key, encryptedKey, joseHeader, maxPBES2Count) {
  const { alg } = entry, mode = entry.mode;
  if (mode === "direct-encryption")
    return assertNoEncryptedKey(encryptedKey), key;
  const direct = mode === "direct-key-agreement";
  switch (direct ? assertNoEncryptedKey(encryptedKey) : assertEncryptedKey(encryptedKey), entry.subtle.name) {
    case "ECDH": {
      const { epk } = joseHeader;
      if (!isObject(epk) || ["d", "k", "p", "q", "dp", "dq", "qi", "oth", "priv"].some((parameter) => Object.hasOwn(epk, parameter)))
        throw new JWEInvalid('JOSE Header "epk" (Ephemeral Public Key) missing or invalid');
      assertEcdhKey(key);
      const ephemeralPublicKey = await jwkToKey(entry, epk), partyUInfo = partyInfo(joseHeader, "apu"), partyVInfo = partyInfo(joseHeader, "apv");
      checkPartyInfo(partyUInfo, partyVInfo);
      const sharedSecret = await ecdhesDeriveKey(ephemeralPublicKey, key, direct ? enc2.alg : alg, direct ? enc2.cekBits : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (direct)
        return sharedSecret;
      key = sharedSecret;
      break;
    }
    case "RSA-OAEP":
      return assertCryptoKey(key), checkRsaKey(alg, key, "decrypt"), new Uint8Array(await crypto.subtle.decrypt("RSA-OAEP", key, encryptedKey));
    case "PBKDF2": {
      if (typeof joseHeader.p2c != "number")
        throw new JWEInvalid('JOSE Header "p2c" (PBES2 Count) missing or invalid');
      validateMaxPBES2Count(maxPBES2Count);
      const p2cLimit = maxPBES2Count ?? 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid('JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds');
      if (typeof joseHeader.p2s != "string")
        throw new JWEInvalid('JOSE Header "p2s" (PBES2 Salt) missing or invalid');
      const p2s = decodeBase64url(joseHeader.p2s, "p2s", JWEInvalid);
      key = await deriveKey(p2s, alg, joseHeader.p2c, key);
      break;
    }
    case "AES-GCM": {
      if (typeof joseHeader.iv != "string")
        throw new JWEInvalid('JOSE Header "iv" (Initialization Vector) missing or invalid');
      if (typeof joseHeader.tag != "string")
        throw new JWEInvalid('JOSE Header "tag" (Authentication Tag) missing or invalid');
      const iv = decodeBase64url(joseHeader.iv, "iv", JWEInvalid), tag2 = decodeBase64url(joseHeader.tag, "tag", JWEInvalid);
      if (iv.byteLength !== 12)
        throw new JWEInvalid("Invalid Initialization Vector length");
      if (tag2.byteLength !== 16)
        throw new JWEInvalid("Invalid Authentication Tag length");
      return decrypt(jweEncryption(alg.slice(0, -2)), key, encryptedKey, iv, tag2, new Uint8Array());
    }
  }
  return aeskwUnwrap(alg.slice(-6), key, encryptedKey);
}

// vendor/jose/lib/deflate.js
function validateZip(joseHeader, protectedHeader) {
  if (joseHeader.zip !== void 0 && joseHeader.zip !== "DEF")
    throw new JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value.');
  if (joseHeader.zip !== void 0 && !protectedHeader?.zip)
    throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header Parameter MUST be in a protected header.');
}
function supported(name) {
  if (typeof globalThis[name] > "u")
    throw new JOSENotSupported(`JWE "zip" (Compression Algorithm) Header Parameter requires the ${name} API.`);
}
async function transform(stream, input, maxLength = 1 / 0) {
  const writer = stream.writable.getWriter();
  writer.write(input).catch(() => {
  }), writer.close().catch(() => {
  });
  const chunks = [];
  let length = 0;
  const reader = stream.readable.getReader();
  for (; ; ) {
    const { value, done } = await reader.read();
    if (done)
      break;
    if (chunks.push(value), length += value.byteLength, maxLength !== 1 / 0 && length > maxLength)
      throw new JWEInvalid("Decompressed plaintext exceeded the configured limit");
  }
  return concat(...chunks);
}
async function decompress(input, maxLength) {
  return supported("DecompressionStream"), transform(new DecompressionStream("deflate-raw"), input, maxLength);
}

// vendor/jose/lib/jwe_decrypt.js
function shareJWE(jwe) {
  const { protected: encodedProtected, ciphertext: ciphertext2, iv, tag: tag2, aad } = jwe;
  let parsedProt;
  return encodedProtected !== void 0 && (parsedProt = parseJoseHeader(encodedProtected, JWEInvalid, "JWE Protected Header is invalid")), [
    parsedProt,
    decodeBase64url(ciphertext2, "ciphertext", JWEInvalid),
    iv !== void 0 ? decodeBase64url(iv, "iv", JWEInvalid) : void 0,
    tag2 !== void 0 ? decodeBase64url(tag2, "tag", JWEInvalid) : void 0,
    encodeBase64url((encodedProtected ?? "") + (aad !== void 0 ? `.${aad}` : ""), "aad", JWEInvalid)
  ];
}
function prepareDecrypt(options) {
  return [
    options && validateAlgorithms("keyManagementAlgorithms", options.keyManagementAlgorithms),
    options && validateAlgorithms("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms),
    options?.crit,
    options?.maxPBES2Count,
    options?.maxDecompressedLength
  ];
}
async function decryptJWE(jwe, shared, key, token = shareJWE(jwe)) {
  const [parsedProt, ciphertext2, iv, tag2, additionalData] = token, { header, unprotected, aad } = jwe;
  let joseHeader;
  if (header !== void 0 || unprotected !== void 0) {
    if (!isDisjoint(parsedProt, header, unprotected))
      throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
    joseHeader = { ...parsedProt, ...header, ...unprotected };
  } else
    joseHeader = parsedProt ?? {};
  const [keyManagementAlgorithms, contentEncryptionAlgorithms, crit, maxPBES2Count, maxDecompressedLength] = shared, { encrypted_key: encodedKey } = jwe;
  validateCrit(JWEInvalid, JWE_RECOGNIZED, crit, parsedProt, joseHeader), validateZip(joseHeader, parsedProt);
  const { alg, enc: enc2 } = joseHeader;
  if (typeof alg != "string" || !alg)
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  const selected = JWE[alg];
  if (encodedKey === "" && (!selected || !isJWECEKTransport(selected)))
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  const integrated = selected?.mode === "integrated-encryption";
  if (!integrated && (typeof enc2 != "string" || !enc2))
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg) || !keyManagementAlgorithms && alg.startsWith("PBES2"))
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  let encEntry;
  if (integrated) {
    if (enc2 !== void 0)
      throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must not be present for integrated encryption');
    if (iv?.byteLength)
      throw new JWEInvalid("JWE Initialization Vector must be empty for integrated encryption");
    if (tag2?.byteLength)
      throw new JWEInvalid("JWE Authentication Tag must be empty for integrated encryption");
  } else {
    if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc2))
      throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
    encEntry = jweEncryption(enc2);
  }
  let encryptedKey;
  if (encodedKey !== void 0)
    try {
      encryptedKey = decodeBase64url(encodedKey, "encrypted_key", JWEInvalid);
    } catch (error) {
      if (!selected || !isJWECEKTransport(selected))
        throw error;
      encryptedKey = new Uint8Array();
    }
  let resolvedKey = false;
  typeof key == "function" && (key = await key(parsedProt, jwe), resolvedKey = true);
  const algEntry = selected ?? jweAlgorithm(alg);
  isJWECEKTransport(algEntry) && encryptedKey === void 0 && (encryptedKey = new Uint8Array());
  const k = await prepareKey(algEntry.mode === "direct-encryption" ? encEntry : algEntry, key, "decrypt");
  let plaintext;
  if (algEntry.mode === "integrated-encryption")
    plaintext = await algEntry.decrypt(k, encryptedKey, ciphertext2, additionalData, parsedProt, joseHeader);
  else {
    const encryption = encEntry;
    let cek;
    try {
      cek = await decryptKeyManagement(algEntry, encryption, k, encryptedKey, joseHeader, maxPBES2Count), isJWECEKTransport(algEntry) && cek instanceof Uint8Array && cek.byteLength << 3 !== encryption.cekBits && (cek = generateCek(encryption));
    } catch (err) {
      if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported)
        throw err;
      cek = generateCek(encryption);
    }
    plaintext = await decrypt(encryption, cek, ciphertext2, iv, tag2, additionalData);
  }
  if (joseHeader.zip === "DEF") {
    const decompressionLimit = maxDecompressedLength ?? 25e4;
    if (decompressionLimit === 0)
      throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
    if (decompressionLimit !== 1 / 0 && (!Number.isSafeInteger(decompressionLimit) || decompressionLimit < 1))
      throw new TypeError("maxDecompressedLength must be 0, a positive safe integer, or Infinity");
    plaintext = await decompress(plaintext, decompressionLimit).catch((cause) => {
      throw cause instanceof JWEInvalid ? cause : new JWEInvalid("Failed to decompress plaintext", { cause });
    });
  }
  return {
    plaintext,
    ...parsedProt && { protectedHeader: parsedProt },
    ...aad !== void 0 && {
      additionalAuthenticatedData: decodeBase64url(aad, "aad", JWEInvalid)
    },
    ...unprotected && { sharedUnprotectedHeader: unprotected },
    ...header && { unprotectedHeader: header },
    ...resolvedKey && { key: k }
  };
}
async function decryptCompact(jwe, shared, key) {
  if (jwe instanceof Uint8Array && (jwe = decoder.decode(jwe)), typeof jwe != "string")
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext2, 4: tag2, length } = jwe.split(".");
  if (length !== 5)
    throw new JWEInvalid("Invalid Compact JWE");
  return decryptJWE({
    ciphertext: ciphertext2,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag2 || void 0,
    encrypted_key: encryptedKey || void 0
  }, shared, key);
}

// vendor/jose/jwe/compact/decrypt.js
async function compactDecrypt(jwe, key, options) {
  return decryptCompact(jwe, prepareDecrypt(options), key);
}

// vendor/jose/lib/jws_algorithms.js
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

// vendor/jose/lib/key_algorithm.js
var algArgument = '"alg" (Algorithm)';
function unsupportedAlg(source = 'JWK "alg" (Algorithm) Parameter') {
  throw new JOSENotSupported(`Invalid or unsupported ${source} value`);
}
function keyAlgorithm(alg, source) {
  return (typeof alg == "string" ? JWS[alg] ?? JWE[alg] : void 0) ?? unsupportedAlg(source);
}

// vendor/jose/lib/asn1.js
var formatPEM = (b64, descriptor) => {
  const newlined = (b64.match(/.{1,64}/g) || []).join(`
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
var readByte = (state2) => {
  const byte = state2.data[state2.pos++];
  if (byte === void 0)
    throw new Error("Unexpected end of ASN.1 input");
  return byte;
};
var parseLength = (state2) => {
  const first = readByte(state2);
  if (first & 128) {
    const lengthOfLen = first & 127;
    let length = 0;
    for (let i = 0; i < lengthOfLen; i++)
      length = length << 8 | readByte(state2);
    return length;
  }
  return first;
};
var expectTag = (state2, expectedTag, errorMessage) => {
  if (readByte(state2) !== expectedTag)
    throw new Error(errorMessage);
};
var getSubarray = (state2, length) => {
  if (length < 0 || state2.pos + length > state2.data.length)
    throw new Error("Unexpected end of ASN.1 input");
  const result = state2.data.subarray(state2.pos, state2.pos + length);
  return state2.pos += length, result;
};
var parseAlgorithmOID = (state2) => {
  expectTag(state2, 6, "Expected algorithm OID");
  const oidLen = parseLength(state2);
  return getSubarray(state2, oidLen);
};
function parseKeyHeader(state2, keyFormat) {
  if (expectTag(state2, 48, `Invalid ${keyFormat === "spki" ? "SPKI" : "PKCS#8"} structure`), parseLength(state2), keyFormat === "pkcs8") {
    expectTag(state2, 2, "Expected version field");
    const length = parseLength(state2);
    state2.pos += length;
  }
  expectTag(state2, 48, "Expected algorithm identifier"), parseLength(state2);
}
var parseECAlgorithmIdentifier = (state2) => {
  const algOid = parseAlgorithmOID(state2);
  if (bytesEqual(algOid, [43, 101, 110]))
    return "X25519";
  if (!bytesEqual(algOid, [42, 134, 72, 206, 61, 2, 1]))
    throw new Error("Unsupported key algorithm");
  expectTag(state2, 6, "Expected curve OID");
  const curveOidLen = parseLength(state2), curveOid = getSubarray(state2, curveOidLen);
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
      const state2 = createASN1State(keyData);
      parseKeyHeader(state2, keyFormat), algorithm = entry.resolve({ crv: parseECAlgorithmIdentifier(state2) });
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

// vendor/jose/key/export.js
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

// vendor/jose/jwk/thumbprint.js
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

// vendor/jose/jwks/remote.js
var USER_AGENT;
(typeof navigator > "u" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) && (USER_AGENT = "jose/v6.2.12");

// vendor/jose/key/import.js
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

// vendor/jose/key/generate_key_pair.js
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

// core.mjs
var DEMO_PASSWORD = "SYNTHETIC ONLY - never a personal password";
var TYPE = "strategy-demo+jwe";
var MAX_PLAINTEXT_BYTES = 12e4;
var MAX_JWE_CHARS = 2e5;
var enc = new TextEncoder();
var dec = new TextDecoder("utf-8", { fatal: true });
var fail = (message2) => {
  throw new Error(message2);
};
var exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
function demoPassword(password) {
  if (password !== DEMO_PASSWORD) fail("This prototype accepts the displayed synthetic password only.");
}
async function validatePublic(config, expectedKid) {
  if (!exact(config, ["version", "synthetic", "kid", "jwk"]) || config.version !== 1 || config.synthetic !== true) fail("Synthetic public-key config required");
  const k = config.jwk;
  if (!exact(k, ["kty", "n", "e"]) || k.kty !== "RSA" || k.e !== "AQAB" || typeof k.n !== "string" || !/^[A-Za-z0-9_-]{512}$/.test(k.n)) fail("Only a 3072-bit public RSA JWK is accepted; private/extra fields rejected");
  const bytes = b64decode(k.n);
  if (bytes.length !== 384 || bytes[0] < 128) fail("RSA modulus must be 3072 bits");
  const kid = await calculateJwkThumbprint(k, "sha256");
  if (config.kid !== kid || expectedKid !== kid) fail("Pinned public-key fingerprint mismatch");
  return importJWK(k, "RSA-OAEP-256");
}
function b64encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function b64decode(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9_-]+$/.test(str)) fail("Invalid base64url");
  return Uint8Array.from(atob(str.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
}
async function derive2(password, salt) {
  demoPassword(password);
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 6e5 }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function setupDemo(password) {
  demoPassword(password);
  const { publicKey, privateKey: privateKey2 } = await generateKeyPair("RSA-OAEP-256", { modulusLength: 3072, extractable: true });
  const jwk = await exportJWK(publicKey);
  const config = { version: 1, synthetic: true, kid: await calculateJwkThumbprint(jwk, "sha256"), jwk };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derive2(password, salt);
  const pkcs8 = enc.encode(await exportPKCS8(privateKey2));
  const ciphertext2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(config.kid) }, key, pkcs8);
  pkcs8.fill(0);
  return { config, backup: { version: 1, synthetic: true, kid: config.kid, kdf: "PBKDF2-SHA256", iterations: 6e5, salt: b64encode(salt), iv: b64encode(iv), ciphertext: b64encode(new Uint8Array(ciphertext2)) } };
}
async function unlockDemo(backup, password, expectedKid) {
  demoPassword(password);
  if (!exact(backup, ["version", "synthetic", "kid", "kdf", "iterations", "salt", "iv", "ciphertext"]) || backup.version !== 1 || backup.synthetic !== true || backup.kdf !== "PBKDF2-SHA256" || backup.iterations !== 6e5 || backup.kid !== expectedKid) fail("Invalid synthetic backup");
  if (typeof backup.ciphertext !== "string" || backup.ciphertext.length > 11e3 || typeof backup.salt !== "string" || backup.salt.length !== 22 || typeof backup.iv !== "string" || backup.iv.length !== 16) fail("Invalid backup encoding bounds");
  const salt = b64decode(backup.salt), iv = b64decode(backup.iv), ciphertext2 = b64decode(backup.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext2.length > 8192) fail("Invalid backup bounds");
  const key = await derive2(password, salt);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(expectedKid) }, key, ciphertext2);
  const privateKey2 = await importPKCS8(dec.decode(plain), "RSA-OAEP-256", { extractable: false });
  new Uint8Array(plain).fill(0);
  return privateKey2;
}
function validateDocument(doc) {
  if (!exact(doc, ["version", "synthetic", "id", "tabs"]) || doc.version !== 1 || doc.synthetic !== true || !/^demo-[a-z0-9-]{1,60}$/.test(doc.id) || !Array.isArray(doc.tabs) || doc.tabs.length !== 3) fail("Only synthetic three-tab documents accepted");
  for (const tab of doc.tabs) if (!exact(tab, ["title", "text"]) || typeof tab.title !== "string" || typeof tab.text !== "string" || tab.title.length > 80 || tab.text.length > 2e4) fail("Invalid tab");
  if (enc.encode(JSON.stringify(doc)).length > MAX_PLAINTEXT_BYTES) fail("Serialized document too large");
  return doc;
}
async function decryptDocument(jwe, key, pinnedKid) {
  if (typeof jwe !== "string" || jwe.length > MAX_JWE_CHARS) fail("Ciphertext too large");
  const { plaintext, protectedHeader: h } = await compactDecrypt(jwe, key, { keyManagementAlgorithms: ["RSA-OAEP-256"], contentEncryptionAlgorithms: ["A256GCM"] });
  if (plaintext.length > MAX_PLAINTEXT_BYTES) fail("Plaintext too large");
  if (!exact(h, ["alg", "enc", "typ", "kid"]) || h.typ !== TYPE || h.kid !== pinnedKid) fail("Unsupported document envelope");
  return validateDocument(JSON.parse(dec.decode(plaintext)));
}

// app.mjs
var $ = (id) => document.getElementById(id);
var state;
var privateKey;
var ciphertext;
var epoch = 0;
var status = (t) => $("status").textContent = t;
function download(name, value) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1e3);
}
function show(doc) {
  $("viewer").hidden = false;
  $("tabs").replaceChildren();
  doc.tabs.forEach((tab, index) => {
    const button = document.createElement("button");
    button.textContent = tab.title;
    button.setAttribute("role", "tab");
    button.onclick = () => {
      for (const b of $("tabs").children) b.setAttribute("aria-selected", String(b === button));
      $("content").textContent = tab.text;
    };
    $("tabs").append(button);
    if (index === 0) button.click();
  });
  $("lock").disabled = false;
}
async function open() {
  const generation = ++epoch;
  const current = state, encrypted = ciphertext, password = $("password").value;
  let key = privateKey;
  if (!state) throw new Error("SETUP_REQUIRED");
  if (!key) {
    try {
      key = await unlockDemo(current.backup, password, current.config.kid);
    } catch {
      throw new Error("BACKUP_UNLOCK_FAILED");
    }
  }
  if (generation !== epoch) return;
  let doc;
  try {
    doc = await decryptDocument(encrypted, key, current.config.kid);
  } catch {
    throw new Error("DOCUMENT_INVALID_OR_KEY_MISMATCH");
  }
  if (generation !== epoch) return;
  try {
    show(doc);
  } catch {
    throw new Error("RENDER_FAILED");
  }
  privateKey = key;
  status("\uAC00\uC0C1 \uC804\uB7B5\uC744 \uC5F4\uC5C8\uC2B5\uB2C8\uB2E4. \uAC19\uC740 \uD398\uC774\uC9C0\uC5D0\uC11C \uC0C8 \uBB38\uC11C\uB294 \uC7AC\uC124\uC815 \uC5C6\uC774 \uC5F4 \uC218 \uC788\uC2B5\uB2C8\uB2E4.");
}
function commitState(next) {
  epoch++;
  privateKey = void 0;
  state = next;
  $("viewer").hidden = true;
  $("content").textContent = "";
  $("tabs").replaceChildren();
  $("setup").disabled = true;
  $("public").disabled = $("backup").disabled = false;
  $("unlock").disabled = !ciphertext;
  $("lock").disabled = false;
  $("fingerprint").textContent = "\uACF5\uAC1C\uD0A4 \uC9C0\uBB38: " + state.config.kid;
  $("publicJson").value = JSON.stringify(state.config);
  $("backupJson").value = JSON.stringify(state.backup);
}
$("setup").onclick = async () => {
  const generation = ++epoch;
  try {
    $("setup").disabled = true;
    status("\uAC00\uC0C1 \uD0A4 \uC0DD\uC131 \uC911\u2026");
    const next = await setupDemo($("password").value);
    if (generation !== epoch) return;
    commitState(next);
    status("\uAC00\uC0C1 \uD0A4 \uC900\uBE44 \uC644\uB8CC. \uACF5\uAC1C\uD0A4\uB9CC \uC554\uD638\uD654 \uC791\uC5C5\uC5D0 \uC804\uB2EC\uD569\uB2C8\uB2E4.");
  } catch (e) {
    if (generation !== epoch) return;
    status(e.message);
    $("setup").disabled = !!state;
  }
};
$("public").onclick = () => download("SYNTHETIC-public-key.json", state.config);
$("backup").onclick = () => download("SYNTHETIC-encrypted-backup.json", state.backup);
function beginSelection() {
  const generation = ++epoch;
  if (!state) $("setup").disabled = false;
  ciphertext = void 0;
  $("viewer").hidden = true;
  $("tabs").replaceChildren();
  $("content").textContent = "";
  $("unlock").disabled = true;
  return generation;
}
function selectCiphertext(text, generation) {
  if (generation !== epoch) return;
  if (text.length > MAX_JWE_CHARS || text.split(".").length !== 5) {
    status("\uAC00\uC0C1 JWE \uD615\uC2DD \uB610\uB294 \uD06C\uAE30\uB97C \uD655\uC778\uD558\uC138\uC694.");
    return;
  }
  ciphertext = text;
  $("unlock").disabled = !state;
  status("\uAC00\uC0C1 \uC804\uB7B5\uC744 \uC120\uD0DD\uD588\uC2B5\uB2C8\uB2E4. \uC7A0\uAE08 \uD574\uC81C\uB97C \uB204\uB974\uC138\uC694.");
}
$("cipher").onchange = async () => {
  const generation = beginSelection();
  const file = $("cipher").files[0];
  if (!file || file.size > MAX_JWE_CHARS) {
    status("\uC791\uC740 \uAC00\uC0C1 JWE \uD30C\uC77C\uB9CC \uC120\uD0DD\uD558\uC138\uC694.");
    return;
  }
  try {
    selectCiphertext((await file.text()).trim(), generation);
  } catch {
    if (generation === epoch) status("\uAC00\uC0C1 \uD30C\uC77C\uC744 \uC77D\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.");
  }
};
$("unlock").onclick = () => open().catch((e) => status({ SETUP_REQUIRED: "\uBA3C\uC800 \uAC00\uC0C1 \uD0A4\uB97C \uC124\uC815\uD558\uC138\uC694.", BACKUP_UNLOCK_FAILED: "\uBCF5\uAD6C \uD0A4 \uC7A0\uAE08 \uD574\uC81C\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4. \uD14C\uC2A4\uD2B8 \uC554\uD638 \uB610\uB294 \uBCF5\uAD6C \uD30C\uC77C\uC744 \uD655\uC778\uD558\uC138\uC694.", DOCUMENT_INVALID_OR_KEY_MISMATCH: "\uD0A4\uB294 \uC5F4\uB838\uC9C0\uB9CC \uC804\uB7B5 \uD30C\uC77C \uAC80\uC99D\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4. \uD30C\uC77C \uB610\uB294 \uC5F0\uACB0\uB41C \uACF5\uAC1C\uD0A4\uB97C \uD655\uC778\uD558\uC138\uC694.", RENDER_FAILED: "\uBCF5\uD638\uD654\uB294 \uB05D\uB0AC\uC9C0\uB9CC \uD654\uBA74 \uD45C\uC2DC\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4." }[e.message] || "\uD14C\uC2A4\uD2B8 \uC624\uB958\uAC00 \uBC1C\uC0DD\uD588\uC2B5\uB2C8\uB2E4."));
$("lock").onclick = () => {
  epoch++;
  privateKey = void 0;
  $("viewer").hidden = true;
  $("content").textContent = "";
  $("tabs").replaceChildren();
  status("\uC7A0\uACBC\uC2B5\uB2C8\uB2E4.");
};
window.demo = { getPublic: () => state?.config, getBackup: () => state?.backup, load: async (jwe) => {
  ciphertext = jwe;
  await open();
}, restore: async (config, backup) => {
  commitState({ config, backup });
}, lock: () => $("lock").click() };
$("loadText").onclick = () => {
  const generation = beginSelection();
  selectCiphertext($("cipherText").value.trim(), generation);
};
$("restore").onclick = async () => {
  const generation = ++epoch;
  try {
    const config = JSON.parse($("restorePublic").value);
    const backup = JSON.parse($("restoreBackup").value);
    await validatePublic(config, config.kid);
    if (generation !== epoch) return;
    if (backup.synthetic !== true || backup.kid !== config.kid) throw new Error();
    commitState({ config, backup });
    status("\uAC00\uC0C1 \uBC31\uC5C5\uC744 \uAC00\uC838\uC654\uC2B5\uB2C8\uB2E4. \uC7A0\uAE08 \uD574\uC81C \uD6C4 \uBCF5\uAD6C\uB97C \uD655\uC778\uD558\uC138\uC694.");
  } catch {
    if (generation === epoch) {
      $("setup").disabled = !!state;
      status("\uAC00\uC0C1 \uACF5\uAC1C\uD0A4 \uB610\uB294 \uBCF5\uAD6C \uD30C\uC77C\uC774 \uC798\uBABB\uB418\uC5C8\uC2B5\uB2C8\uB2E4.");
    }
  }
};

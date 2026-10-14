// production/render-report.mjs
var el = (tag2, text, cls) => {
  const n = document.createElement(tag2);
  if (text !== void 0) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
function definitions(text) {
  const dl = el("dl"), lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 2) {
    dl.append(el("dt", lines[i]));
    dl.append(el("dd", lines[i + 1] || ""));
  }
  return dl;
}
function table(block, nested = false) {
  const wrap2 = el("div", void 0, "table-wrap"), t = el("table"), head = el("thead"), hr = el("tr"), body = el("tbody");
  for (const text of block.headers) {
    const th = el("th", text);
    th.scope = "col";
    hr.append(th);
  }
  head.append(hr);
  for (const row of block.rows) {
    const tr = el("tr");
    for (const text of row) {
      const td = el("td");
      if (nested) td.append(definitions(text));
      else td.textContent = text;
      tr.append(td);
    }
    body.append(tr);
  }
  t.append(head, body);
  wrap2.append(t);
  return wrap2;
}
function generic(block) {
  if (block.type === "table") return table(block);
  if (block.type === "list") {
    const ul = el("ul");
    for (const text of block.items) ul.append(el("li", text));
    return ul;
  }
  return el(block.type === "heading" ? "h3" : "p", block.text, "report-text");
}
function types(tab) {
  return tab.blocks.map((b) => b.type).join(",");
}
function renderReport(doc, cover, panels) {
  const [p, q, e] = doc.tabs;
  const restored = types(p) === "paragraph,heading,paragraph,paragraph,paragraph,heading,heading,list,paragraph,table" && types(q) === "heading,heading,paragraph,paragraph,heading,paragraph,paragraph,heading,paragraph,paragraph" && types(e) === "heading,heading,table,heading,table,heading,table,heading,paragraph,table";
  if (!restored) {
    for (let i = 0; i < doc.tabs.length; i++) for (const block of doc.tabs[i].blocks) panels[i].append(generic(block));
    return;
  }
  const b = p.blocks, header = el("header", void 0, "cover");
  header.append(el("p", b[0].text, "eyebrow"), el("h1", b[1].text));
  const meta = el("dl", void 0, "report-meta");
  for (const item of b.slice(2, 4)) {
    const div = el("div"), lines = item.text.split("\n");
    div.append(el("dt", lines.shift()), el("dd", lines.join("\n")));
    meta.append(div);
  }
  header.append(meta);
  cover.append(header, el("p", b[4].text, "private-notice"));
  panels[0].append(el("h2", b[5].text));
  const jd = el("div", void 0, "jd-original");
  jd.append(el("h3", b[6].text), generic(b[7]));
  panels[0].append(jd, el("p", b[8].text, "persona"), table(b[9]));
  panels[1].append(el("h2", q.blocks[0].text));
  for (let i = 1; i < q.blocks.length; i += 3) {
    const card = el("article", void 0, "card");
    card.append(el("h3", q.blocks[i].text));
    for (const block of q.blocks.slice(i + 1, i + 3)) card.append(definitions(block.text));
    panels[1].append(card);
  }
  panels[2].append(el("h2", e.blocks[0].text));
  for (let i = 1; i < 7; i += 2) {
    const card = el("article", void 0, "card");
    card.append(el("h3", e.blocks[i].text), table(e.blocks[i + 1], true));
    panels[2].append(card);
  }
  const terms = el("div", void 0, "terminology-block");
  terms.append(el("h3", e.blocks[7].text), el("p", e.blocks[8].text, "terminology-note"), table(e.blocks[9], true));
  panels[2].append(terms);
}

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
var tag = (key2) => key2[Symbol.toStringTag];
var jwkMatchesOp = (entry, key2, usage) => {
  const { alg } = entry;
  if (key2.use !== void 0) {
    const expected = usage === "sign" || usage === "verify" ? "sig" : "enc";
    if (key2.use !== expected)
      throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
  }
  if (key2.alg !== void 0 && key2.alg !== alg)
    throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
  if (Array.isArray(key2.key_ops)) {
    const expectedKeyOp = usage === "encrypt" || usage === "decrypt" ? entry.ops?.[usage === "encrypt" ? 0 : 1] : usage;
    if (expectedKeyOp && !key2.key_ops.includes(expectedKeyOp))
      throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
  }
};
async function prepareKey(entry, key2, usage) {
  const { alg, secret } = entry, privateKey = usage === "decrypt" || usage === "sign";
  if (secret && key2 instanceof Uint8Array)
    return key2;
  let normalized, keyObject;
  if (isObject(key2)) {
    if (normalized = normalizeJwk(key2), typeof normalized.kty != "string")
      throw invalidKeyType(alg, key2, secret);
    if (!(secret ? normalized.kty === "oct" && typeof normalized.k == "string" : normalized.kty !== "oct" && (privateKey ? normalized.kty === "AKP" && typeof normalized.priv == "string" || typeof normalized.d == "string" : normalized.d === void 0 && normalized.priv === void 0)))
      throw new TypeError(secret ? 'JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present' : `JSON Web Key for this operation must be a ${privateKey ? "private" : "public"} JWK`);
    if (jwkMatchesOp(entry, normalized, usage), normalized.kty === "oct")
      return decode(normalized.k);
    if (!Object.isFrozen(key2)) {
      const { key_ops } = key2;
      Array.isArray(key_ops) && Object.freeze(key_ops), Object.freeze(key2);
    }
  } else {
    if (!isKeyLike(key2))
      throw invalidKeyType(alg, key2, secret);
    const expectedType = secret ? "secret" : privateKey ? "private" : "public";
    if (key2.type !== expectedType && (secret || ["secret", "public", "private"].includes(key2.type)))
      throw new TypeError(`${tag(key2)} instances must be of type "${expectedType}" for the ${alg} algorithm`);
    if (isCryptoKey(key2))
      return key2;
    if (keyObject = key2, keyObject.type === "secret")
      return keyObject.export();
  }
  cache ||= /* @__PURE__ */ new WeakMap();
  const cacheKey = key2;
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
function assertCryptoKey(key2) {
  if (!isCryptoKey(key2))
    throw new Error("CryptoKey instance expected");
}
var isCryptoKey = (key2) => {
  if (key2?.[Symbol.toStringTag] === "CryptoKey")
    return true;
  try {
    return key2 instanceof CryptoKey;
  } catch {
    return false;
  }
};
var isKeyObject = (key2) => key2?.[Symbol.toStringTag] === "KeyObject";
var isKeyLike = (key2) => isCryptoKey(key2) || isKeyObject(key2);
function message(msg, actual, ...types2) {
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else types2.length === 2 ? msg += `one of type ${types2[0]} or ${types2[1]}.` : msg += `of type ${types2[0]}.`;
  return actual == null ? msg += ` Received ${actual}` : typeof actual == "function" && actual.name ? msg += ` Received function ${actual.name}` : typeof actual == "object" && actual != null && actual.constructor?.name && (msg += ` Received an instance of ${actual.constructor.name}`), msg;
}
var invalidKeyInput = (actual, ...types2) => message("Key must be ", actual, ...types2);
function invalidKeyType(alg, actual, secret) {
  const types2 = ["CryptoKey", "KeyObject", "JSON Web Key"];
  return secret && types2.push("Uint8Array"), new TypeError(message(`Key for the ${alg} algorithm must be `, actual, ...types2));
}
var unusable = (name, prop = "algorithm.name") => new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
function checkUsage(key2, usage) {
  if (usage && !key2.usages.includes(usage))
    throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
}
function checkModulusLength(alg, key2) {
  const { modulusLength } = key2.algorithm;
  if (typeof modulusLength != "number" || modulusLength < 2048)
    throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
}
function checkCryptoKey(key2, expected, usage) {
  const algorithm = key2.algorithm;
  if (algorithm.name !== expected.name)
    throw unusable(expected.name);
  if (expected.hash && algorithm.hash?.name !== expected.hash)
    throw unusable(expected.hash, "algorithm.hash");
  if (expected.namedCurve && algorithm.namedCurve !== expected.namedCurve)
    throw unusable(expected.namedCurve, "algorithm.namedCurve");
  if (expected.length !== void 0 && algorithm.length !== expected.length)
    throw unusable(expected.length, "algorithm.length");
  checkUsage(key2, usage);
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
async function rawKey(key2, expected, usage, extractable = false) {
  return key2 instanceof Uint8Array && (key2 = await crypto.subtle.importKey("raw", key2, expected, extractable, [usage])), checkCryptoKey(key2, expected, usage), key2;
}

// vendor/jose/lib/content_encryption.js
var generateCek = (enc) => crypto.getRandomValues(new Uint8Array(enc.cekBits >> 3));
function checkCekLength(cek, expected) {
  const actual = cek.byteLength << 3;
  if (actual !== expected)
    throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
}
function checkIvLength(enc, iv) {
  if (iv.length << 3 !== enc.ivBits)
    throw new JWEInvalid("Invalid Initialization Vector length");
}
async function cbcKeySetup(enc, cek, usage) {
  if (!(cek instanceof Uint8Array))
    throw new TypeError(invalidKeyInput(cek, "Uint8Array"));
  const keySize = enc.cekBits >> 1, encKey = await crypto.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, [usage]), macKey = await crypto.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  return [encKey, macKey, keySize];
}
async function cbcHmacTag(macKey, macData, keySize) {
  return new Uint8Array((await crypto.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
}
async function timingSafeEqual(a, b) {
  const algorithm = { name: "HMAC", hash: "SHA-256" }, key2 = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]), aHmac = await crypto.subtle.sign(algorithm, key2, a);
  return crypto.subtle.verify(algorithm, key2, aHmac, b);
}
async function cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  const [encKey, macKey, keySize] = await cbcKeySetup(enc, cek, "decrypt"), macData = concat(aad, iv, ciphertext, uint64be(aad.length * 8)), expectedTag = await cbcHmacTag(macKey, macData, keySize);
  try {
    if (await timingSafeEqual(tag2, expectedTag))
      return new Uint8Array(await crypto.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext));
  } catch {
  }
  throw new JWEDecryptionFailed();
}
async function decrypt(enc, cek, ciphertext, iv, tag2, aad) {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array))
    throw new TypeError(invalidKeyInput(cek, "CryptoKey", "KeyObject", "Uint8Array", "JSON Web Key"));
  if (!iv)
    throw new JWEInvalid("JWE Initialization Vector missing");
  if (!tag2)
    throw new JWEInvalid("JWE Authentication Tag missing");
  if (!enc.cbc && tag2.length !== 16)
    throw new JWEInvalid("Invalid Authentication Tag length");
  if (checkIvLength(enc, iv), cek instanceof Uint8Array && checkCekLength(cek, enc.cekBits), enc.cbc)
    return cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad);
  const encKey = await rawKey(cek, enc.subtle, "decrypt");
  try {
    return new Uint8Array(await crypto.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext, tag2)));
  } catch {
    throw new JWEDecryptionFailed();
  }
}

// vendor/jose/lib/key_descriptor.js
function table2(entries) {
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
var JWE = table2({
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
var ENC = table2({
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
function jweEncryption(enc) {
  return (typeof enc == "string" ? ENC[enc] : void 0) ?? unsupported("enc", "Encryption Algorithm");
}

// vendor/jose/lib/key_management.js
function checkEcdhCryptoKey(key2, usage) {
  if (key2.algorithm.name !== "ECDH" && key2.algorithm.name !== "X25519")
    throw new TypeError("CryptoKey does not support this operation, its algorithm.name must be ECDH or X25519");
  checkUsage(key2, usage);
}
async function aeskwUnwrap(alg, key2, encryptedKey) {
  const cryptoKey = await rawKey(key2, jweAlgorithm(alg).subtle, "unwrapKey", true), cryptoKeyCek = await crypto.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", { hash: "SHA-256", name: "HMAC" }, true, ["sign"]);
  return new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKeyCek));
}
function checkRsaKey(alg, key2, usage) {
  checkCryptoKey(key2, jweAlgorithm(alg).subtle, usage), checkModulusLength(alg, key2);
}
async function deriveKey(p2s, alg, p2c, key2) {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8)
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  if (!Number.isSafeInteger(p2c) || Math.sign(p2c) !== 1)
    throw new JWEInvalid("PBES2 Count Input must be a positive integer");
  const salt = concat(encode(alg), Uint8Array.of(0), p2s), keylen = parseInt(alg.slice(13, 16), 10), subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  }, cryptoKey = await rawKey(key2, jweAlgorithm(alg).subtle, "deriveBits");
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
async function ecdhesDeriveKey(publicKey2, privateKey, algorithm, keyLength, apu = new Uint8Array(), apv = new Uint8Array()) {
  checkEcdhCryptoKey(publicKey2), checkEcdhCryptoKey(privateKey, "deriveBits");
  const otherInfo = concat(lengthAndInput(encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength)), Z = new Uint8Array(await crypto.subtle.deriveBits({
    name: publicKey2.algorithm.name,
    public: publicKey2
  }, privateKey, publicKey2.algorithm.name === "X25519" ? 256 : Math.ceil(parseInt(publicKey2.algorithm.namedCurve.slice(-3), 10) / 8) << 3));
  return concatKdf(Z, keyLength, otherInfo);
}
function assertEcdhKey(key2) {
  assertCryptoKey(key2);
  const curve = key2.algorithm.namedCurve;
  if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521" && key2.algorithm.name !== "X25519")
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
async function decryptKeyManagement(entry, enc, key2, encryptedKey, joseHeader, maxPBES2Count) {
  const { alg } = entry, mode = entry.mode;
  if (mode === "direct-encryption")
    return assertNoEncryptedKey(encryptedKey), key2;
  const direct = mode === "direct-key-agreement";
  switch (direct ? assertNoEncryptedKey(encryptedKey) : assertEncryptedKey(encryptedKey), entry.subtle.name) {
    case "ECDH": {
      const { epk } = joseHeader;
      if (!isObject(epk) || ["d", "k", "p", "q", "dp", "dq", "qi", "oth", "priv"].some((parameter) => Object.hasOwn(epk, parameter)))
        throw new JWEInvalid('JOSE Header "epk" (Ephemeral Public Key) missing or invalid');
      assertEcdhKey(key2);
      const ephemeralPublicKey = await jwkToKey(entry, epk), partyUInfo = partyInfo(joseHeader, "apu"), partyVInfo = partyInfo(joseHeader, "apv");
      checkPartyInfo(partyUInfo, partyVInfo);
      const sharedSecret = await ecdhesDeriveKey(ephemeralPublicKey, key2, direct ? enc.alg : alg, direct ? enc.cekBits : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (direct)
        return sharedSecret;
      key2 = sharedSecret;
      break;
    }
    case "RSA-OAEP":
      return assertCryptoKey(key2), checkRsaKey(alg, key2, "decrypt"), new Uint8Array(await crypto.subtle.decrypt("RSA-OAEP", key2, encryptedKey));
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
      key2 = await deriveKey(p2s, alg, joseHeader.p2c, key2);
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
      return decrypt(jweEncryption(alg.slice(0, -2)), key2, encryptedKey, iv, tag2, new Uint8Array());
    }
  }
  return aeskwUnwrap(alg.slice(-6), key2, encryptedKey);
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
function shareJWE(jwe2) {
  const { protected: encodedProtected, ciphertext, iv, tag: tag2, aad } = jwe2;
  let parsedProt;
  return encodedProtected !== void 0 && (parsedProt = parseJoseHeader(encodedProtected, JWEInvalid, "JWE Protected Header is invalid")), [
    parsedProt,
    decodeBase64url(ciphertext, "ciphertext", JWEInvalid),
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
async function decryptJWE(jwe2, shared, key2, token = shareJWE(jwe2)) {
  const [parsedProt, ciphertext, iv, tag2, additionalData] = token, { header, unprotected, aad } = jwe2;
  let joseHeader;
  if (header !== void 0 || unprotected !== void 0) {
    if (!isDisjoint(parsedProt, header, unprotected))
      throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
    joseHeader = { ...parsedProt, ...header, ...unprotected };
  } else
    joseHeader = parsedProt ?? {};
  const [keyManagementAlgorithms, contentEncryptionAlgorithms, crit, maxPBES2Count, maxDecompressedLength] = shared, { encrypted_key: encodedKey } = jwe2;
  validateCrit(JWEInvalid, JWE_RECOGNIZED, crit, parsedProt, joseHeader), validateZip(joseHeader, parsedProt);
  const { alg, enc } = joseHeader;
  if (typeof alg != "string" || !alg)
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  const selected = JWE[alg];
  if (encodedKey === "" && (!selected || !isJWECEKTransport(selected)))
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  const integrated = selected?.mode === "integrated-encryption";
  if (!integrated && (typeof enc != "string" || !enc))
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg) || !keyManagementAlgorithms && alg.startsWith("PBES2"))
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  let encEntry;
  if (integrated) {
    if (enc !== void 0)
      throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must not be present for integrated encryption');
    if (iv?.byteLength)
      throw new JWEInvalid("JWE Initialization Vector must be empty for integrated encryption");
    if (tag2?.byteLength)
      throw new JWEInvalid("JWE Authentication Tag must be empty for integrated encryption");
  } else {
    if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc))
      throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
    encEntry = jweEncryption(enc);
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
  typeof key2 == "function" && (key2 = await key2(parsedProt, jwe2), resolvedKey = true);
  const algEntry = selected ?? jweAlgorithm(alg);
  isJWECEKTransport(algEntry) && encryptedKey === void 0 && (encryptedKey = new Uint8Array());
  const k = await prepareKey(algEntry.mode === "direct-encryption" ? encEntry : algEntry, key2, "decrypt");
  let plaintext;
  if (algEntry.mode === "integrated-encryption")
    plaintext = await algEntry.decrypt(k, encryptedKey, ciphertext, additionalData, parsedProt, joseHeader);
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
    plaintext = await decrypt(encryption, cek, ciphertext, iv, tag2, additionalData);
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
async function decryptCompact(jwe2, shared, key2) {
  if (jwe2 instanceof Uint8Array && (jwe2 = decoder.decode(jwe2)), typeof jwe2 != "string")
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag2, length } = jwe2.split(".");
  if (length !== 5)
    throw new JWEInvalid("Invalid Compact JWE");
  return decryptJWE({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag2 || void 0,
    encrypted_key: encryptedKey || void 0
  }, shared, key2);
}

// vendor/jose/jwe/compact/decrypt.js
async function compactDecrypt(jwe2, key2, options) {
  return decryptCompact(jwe2, prepareDecrypt(options), key2);
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
var JWS = table2({
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

// vendor/jose/key/export.js
async function exportJWK(key2) {
  if (isKeyObject(key2))
    if (key2.type === "secret")
      key2 = key2.export();
    else
      return key2.export({ format: "jwk" });
  if (key2 instanceof Uint8Array)
    return {
      kty: "oct",
      k: encode2(key2)
    };
  if (!isCryptoKey(key2))
    throw new TypeError(invalidKeyInput(key2, "CryptoKey", "KeyObject", "Uint8Array"));
  if (!key2.extractable)
    throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
  const jwk = await crypto.subtle.exportKey("jwk", key2);
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
async function calculateJwkThumbprint(key2, digestAlgorithm) {
  let jwk;
  if (isObject(key2)) {
    if (jwk = snapshotJwk(key2), typeof jwk.kty != "string")
      throw new TypeError(invalidKeyInput(key2, "CryptoKey", "KeyObject", "JSON Web Key"));
  } else if (isKeyLike(key2))
    jwk = snapshotJwk(await exportJWK(key2));
  else
    throw new TypeError(invalidKeyInput(key2, "CryptoKey", "KeyObject", "JSON Web Key"));
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

// production/crypto.mjs
var LIMITS = Object.freeze({ plaintext: 12e4, jwe: 2e5, backup: 12e3, public: 2e3 });
var E = new TextEncoder();
var D = new TextDecoder("utf-8", { fatal: true });
var EXACT = (x, keys) => x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).sort().join(",") === [...keys].sort().join(",");
var fail = (code) => {
  throw new Error(code);
};
var bytes = (x) => E.encode(JSON.stringify(x));
var unb64 = (x) => {
  if (typeof x !== "string" || !/^[A-Za-z0-9_-]+$/.test(x)) fail("ENCODING_INVALID");
  return Uint8Array.from(atob(x.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
};
var validKid = (x) => typeof x === "string" && /^[A-Za-z0-9_-]{43}$/.test(x);
async function publicKey(config2, pinnedKid) {
  if (bytes(config2).length > LIMITS.public || !EXACT(config2, ["format", "version", "kid", "jwk"]) || config2.format !== "strategy-public-key" || config2.version !== 1 || !validKid(config2.kid)) fail("PUBLIC_CONFIG_INVALID");
  const k = config2.jwk;
  if (!EXACT(k, ["kty", "n", "e"]) || k.kty !== "RSA" || k.e !== "AQAB" || typeof k.n !== "string" || !/^[A-Za-z0-9_-]{512}$/.test(k.n)) fail("PUBLIC_JWK_INVALID");
  const n = unb64(k.n);
  if (n.length !== 384 || n[0] < 128) fail("PUBLIC_JWK_INVALID");
  const kid2 = await calculateJwkThumbprint(k, "sha256");
  if (kid2 !== config2.kid || kid2 !== pinnedKid) fail("PUBLIC_KEY_PIN_MISMATCH");
  return importJWK(k, "RSA-OAEP-256");
}
function checkPassword(password, creating = false) {
  if (typeof password !== "string" || password.length > 1024 || !password.length || creating && [...password].length < 16) fail("PASSPHRASE_INVALID");
}
async function derive2(password, salt) {
  checkPassword(password);
  const key2 = await crypto.subtle.importKey("raw", E.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", iterations: 6e5, salt }, key2, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function validateBackup(backup2, expectedKid) {
  if (bytes(backup2).length > LIMITS.backup || !EXACT(backup2, ["format", "version", "kid", "kdf", "cipher"]) || backup2.format !== "strategy-key-backup" || backup2.version !== 1 || !validKid(backup2.kid) || backup2.kid !== expectedKid) fail("BACKUP_FORMAT_INVALID");
  const k = backup2.kdf, c = backup2.cipher;
  if (!EXACT(k, ["name", "hash", "iterations", "salt"]) || k.name !== "PBKDF2" || k.hash !== "SHA-256" || k.iterations !== 6e5 || typeof k.salt !== "string" || k.salt.length !== 22 || !EXACT(c, ["name", "iv", "data"]) || c.name !== "AES-GCM" || typeof c.iv !== "string" || c.iv.length !== 16 || typeof c.data !== "string" || c.data.length > 11e3) fail("BACKUP_FORMAT_INVALID");
  const salt = unb64(k.salt), iv = unb64(c.iv), data = unb64(c.data);
  if (salt.length !== 16 || iv.length !== 12 || data.length < 128 || data.length > 8192) fail("BACKUP_FORMAT_INVALID");
  return { salt, iv, data };
}
async function unlockOwnerBundle(backup2, password, config2, pinnedKid) {
  const pub = await publicKey(config2, pinnedKid), { salt, iv, data } = validateBackup(backup2, pinnedKid);
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
function validateDocument(doc, expected) {
  if (!EXACT(doc, ["version", "kind", "id", "revision", "tabs"]) || doc.version !== 1 || doc.kind !== "application-strategy" || typeof doc.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(doc.id) || typeof doc.revision !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(doc.revision) || !Array.isArray(doc.tabs) || doc.tabs.length !== 3) fail("DOCUMENT_SCHEMA_INVALID");
  const ids = ["positioning", "questions", "expressions"];
  const text = (x) => typeof x === "string" && x.length <= 2e4;
  for (let i = 0; i < 3; i++) {
    const t = doc.tabs[i];
    if (!EXACT(t, ["id", "title", "blocks"]) || t.id !== ids[i] || typeof t.title !== "string" || !t.title.length || t.title.length > 80 || !Array.isArray(t.blocks) || t.blocks.length > 100) fail("DOCUMENT_SCHEMA_INVALID");
    for (const b of t.blocks) {
      if ((b.type === "paragraph" || b.type === "heading") && EXACT(b, ["type", "text"]) && text(b.text)) continue;
      if (b.type === "list" && EXACT(b, ["type", "items"]) && Array.isArray(b.items) && b.items.length <= 100 && b.items.every(text)) continue;
      if (b.type === "table" && EXACT(b, ["type", "headers", "rows"]) && Array.isArray(b.headers) && b.headers.length >= 1 && b.headers.length <= 4 && b.headers.every((x) => text(x) && x.length <= 100) && Array.isArray(b.rows) && b.rows.length <= 100 && b.rows.every((r) => Array.isArray(r) && r.length === b.headers.length && r.every(text))) continue;
      fail("DOCUMENT_SCHEMA_INVALID");
    }
  }
  if (bytes(doc).length > LIMITS.plaintext) fail("DOCUMENT_TOO_LARGE");
  if (!expected || doc.id !== expected.id || doc.revision !== expected.revision) fail("DOCUMENT_IDENTITY_MISMATCH");
  return doc;
}
async function decryptStrategy(jwe2, key2, pinnedKid, expected) {
  if (typeof jwe2 !== "string" || jwe2.length > LIMITS.jwe) fail("CIPHERTEXT_INVALID");
  let result;
  try {
    result = await compactDecrypt(jwe2, key2, { keyManagementAlgorithms: ["RSA-OAEP-256"], contentEncryptionAlgorithms: ["A256GCM"] });
  } catch {
    fail("DOCUMENT_AUTHENTICATION_FAILED");
  }
  const h = result.protectedHeader;
  if (!EXACT(h, ["alg", "enc", "typ", "kid"]) || h.typ !== "application-strategy+jwe" || h.kid !== pinnedKid) fail("DOCUMENT_ENVELOPE_INVALID");
  if (result.plaintext.length > LIMITS.plaintext) fail("DOCUMENT_TOO_LARGE");
  let doc;
  try {
    doc = JSON.parse(D.decode(result.plaintext));
  } catch {
    fail("DOCUMENT_JSON_INVALID");
  }
  return validateDocument(doc, expected);
}

// production/storage.mjs
var DATABASE = "company-report-strategy-encrypted-backups-v1";
var STORE = "encryptedBackups";
async function database(create) {
  return new Promise((resolve, reject) => {
    let missing = false;
    const r = indexedDB.open(DATABASE, 1);
    r.onupgradeneeded = () => {
      if (!create) {
        missing = true;
        r.transaction.abort();
        return;
      }
      r.result.createObjectStore(STORE);
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => missing ? resolve(void 0) : reject(new Error("LOCAL_STORAGE_UNAVAILABLE"));
    r.onblocked = () => reject(new Error("LOCAL_STORAGE_UNAVAILABLE"));
  });
}
async function saveEncryptedBackup(backup2, kid2) {
  validateBackup(backup2, kid2);
  const db = await database(true);
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(backup2, kid2);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(new Error("LOCAL_STORAGE_FAILED"));
      tx.onabort = () => reject(new Error("LOCAL_STORAGE_FAILED"));
    });
  } finally {
    db.close();
  }
}
async function readEncryptedBackup(kid2) {
  const db = await database(false);
  if (!db) return void 0;
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly"), r = tx.objectStore(STORE).get(kid2);
      r.onsuccess = () => {
        try {
          if (r.result) validateBackup(r.result, kid2);
          resolve(r.result);
        } catch (e) {
          reject(e);
        }
      };
      r.onerror = () => reject(new Error("LOCAL_STORAGE_UNAVAILABLE"));
    });
  } finally {
    db.close();
  }
}

// production/viewer.mjs
var $ = (id2) => document.getElementById(id2);
var epoch = 0;
var key;
var backup;
var status = (code) => $("status").textContent = code;
var bundle = JSON.parse($("strategy-envelope").textContent);
var { config, kid, id, revision, jwe } = bundle;
var node = (tag2, text) => {
  const e = document.createElement(tag2);
  if (text !== void 0) e.textContent = text;
  return e;
};
function clear() {
  epoch++;
  key = void 0;
  $("unlock").disabled = false;
  $("viewer").hidden = true;
  $("tabs").replaceChildren();
  $("panels").replaceChildren();
  $("report-cover").replaceChildren();
  $("password").value = "";
  $("lock-panel").hidden = false;
  $("session-actions").hidden = true;
  $("session-options").hidden = true;
  $("options").setAttribute("aria-expanded", "false");
}
function render(doc) {
  $("tabs").replaceChildren();
  $("panels").replaceChildren();
  $("report-cover").replaceChildren();
  const panelList = [];
  doc.tabs.forEach((tab, index) => {
    const button = node("button", tab.title);
    button.type = "button";
    button.id = "tab-" + tab.id;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", "panel-" + tab.id);
    const panel = node("section");
    panel.id = "panel-" + tab.id;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", button.id);
    panel.className = "strategy-panel";
    panelList.push(panel);
    button.onclick = () => {
      for (const b of $("tabs").children) {
        b.setAttribute("aria-selected", String(b === button));
        b.tabIndex = b === button ? 0 : -1;
      }
      for (const p of $("panels").children) p.hidden = p !== panel;
    };
    button.onkeydown = (e) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      e.preventDefault();
      const list = [...$("tabs").children], at = list.indexOf(button);
      const to = e.key === "Home" ? 0 : e.key === "End" ? list.length - 1 : (at + (e.key === "ArrowRight" ? 1 : -1) + list.length) % list.length;
      list[to].click();
      list[to].focus();
    };
    $("tabs").append(button);
    $("panels").append(panel);
    if (index === 0) button.click();
    else panel.hidden = true;
  });
  renderReport(doc, $("report-cover"), panelList);
  $("viewer").hidden = false;
  $("lock-panel").hidden = true;
  $("session-actions").hidden = false;
}
$("backup-file").onchange = async () => {
  clear();
  const generation = epoch, file = $("backup-file").files[0];
  backup = void 0;
  if (!file || file.size > LIMITS.backup) {
    status("\uBCF5\uAD6C \uD30C\uC77C \uD06C\uAE30\uB97C \uD655\uC778\uD558\uC138\uC694.");
    return;
  }
  try {
    const candidate = JSON.parse(await file.text());
    validateBackup(candidate, kid);
    if (generation !== epoch) return;
    backup = candidate;
    status("\uBCF5\uAD6C \uD30C\uC77C\uC744 \uC120\uD0DD\uD588\uC2B5\uB2C8\uB2E4. \uBE44\uBC00\uBC88\uD638\uB97C \uC785\uB825\uD558\uC138\uC694.");
  } catch {
    if (generation === epoch) status("\uC774 \uACF5\uAC1C\uD0A4\uC5D0 \uB9DE\uB294 \uBCF5\uAD6C \uD30C\uC77C\uC774 \uC544\uB2D9\uB2C8\uB2E4.");
  }
};
$("unlock-form").onsubmit = async (event) => {
  event.preventDefault();
  const generation = ++epoch;
  const password = $("password").value;
  $("password").value = "";
  $("unlock").disabled = true;
  try {
    await publicKey(config, kid);
    let selected = backup;
    if (!selected) {
      try {
        selected = await readEncryptedBackup(kid);
      } catch {
      }
    }
    if (generation !== epoch) return;
    if (!selected) {
      status("\uC774 \uAE30\uAE30\uC5D0 \uBCF5\uAD6C \uD0A4\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4. \uCD5C\uCD08 \uC124\uC815\uC5D0\uC11C \uBC1B\uC740 \uBCF5\uAD6C \uD30C\uC77C\uC744 \uC120\uD0DD\uD558\uC138\uC694.");
      return;
    }
    let candidate;
    try {
      candidate = key || await unlockOwnerBundle(selected, password, config, kid);
    } catch {
      if (generation !== epoch) return;
      status("\uBCF5\uAD6C \uD0A4 \uC7A0\uAE08\uC744 \uD480\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4. \uBE44\uBC00\uBC88\uD638 \uB610\uB294 \uBCF5\uAD6C \uD30C\uC77C\uC744 \uD655\uC778\uD558\uC138\uC694.");
      return;
    }
    if (generation !== epoch) return;
    let doc;
    try {
      doc = await decryptStrategy(jwe, candidate, kid, { id, revision });
    } catch {
      if (generation !== epoch) return;
      status("\uD0A4\uB294 \uC5F4\uB838\uC9C0\uB9CC \uC804\uB7B5 \uD30C\uC77C \uAC80\uC99D\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4. \uBB38\uC11C \uBC84\uC804 \uB610\uB294 \uD30C\uC77C\uC744 \uD655\uC778\uD558\uC138\uC694.");
      return;
    }
    if (generation !== epoch) return;
    try {
      render(doc);
    } catch {
      clear();
      status("\uBCF5\uD638\uD654\uB294 \uC644\uB8CC\uD588\uC9C0\uB9CC \uD654\uBA74 \uD45C\uC2DC\uC5D0 \uC2E4\uD328\uD588\uC2B5\uB2C8\uB2E4.");
      return;
    }
    key = candidate;
    backup = selected;
    status("");
  } catch {
    if (generation === epoch) status("\uC124\uC815 \uB610\uB294 \uD30C\uC77C\uC744 \uD655\uC778\uD558\uC138\uC694.");
  } finally {
    if (generation === epoch) $("unlock").disabled = false;
  }
};
$("options").onclick = () => {
  const open = $("session-options").hidden;
  $("session-options").hidden = !open;
  $("options").setAttribute("aria-expanded", String(open));
};
$("remember").onclick = async () => {
  if (!$("storage-consent").checked || !backup || !key) {
    status("\uBA3C\uC800 \uC7A0\uAE08\uC744 \uD574\uC81C\uD558\uACE0 \uC554\uD638\uD654 \uBCF5\uAD6C \uD0A4 \uC800\uC7A5\uC5D0 \uB3D9\uC758\uD558\uC138\uC694.");
    return;
  }
  try {
    await saveEncryptedBackup(backup, kid);
    status("\uC554\uD638\uD654\uB41C \uBCF5\uAD6C \uD0A4\uB9CC \uC774 \uBE0C\uB77C\uC6B0\uC800\uC5D0 \uC800\uC7A5\uD588\uC2B5\uB2C8\uB2E4. \uBE44\uBC00\uBC88\uD638\uB294 \uC800\uC7A5\uD558\uC9C0 \uC54A\uC2B5\uB2C8\uB2E4.");
  } catch {
    status("\uC774 \uBE0C\uB77C\uC6B0\uC800\uC5D0 \uC800\uC7A5\uD560 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4. \uBCF5\uAD6C \uD30C\uC77C\uC740 \uBCC4\uB3C4\uB85C \uBCF4\uAD00\uD558\uC138\uC694.");
  }
};
$("lock").onclick = () => {
  clear();
  $("unlock").disabled = false;
  status("\uC7A0\uACBC\uC2B5\uB2C8\uB2E4.");
};
window.addEventListener("pagehide", clear);

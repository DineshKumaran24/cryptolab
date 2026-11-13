import { webcrypto } from 'node:crypto';

// Setup browser globals for Node testing (crypto is already native in Node 24!)
globalThis.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
globalThis.window = {
  btoa: globalThis.btoa,
  atob: globalThis.atob
};

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

console.log("==================================================");
console.log("CRYPTOLAB AUTOMATED TEST & QUALITY ASSURANCE SUITE");
console.log("==================================================\n");

// 1. Caesar Cipher Verification
console.log("--- 1. Testing Caesar Cipher ---");
function caesarProcess(text, shift, isEncrypt = true) {
  let s = parseInt(shift, 10);
  if (isNaN(s)) throw new Error('Invalid shift');
  s = ((s % 26) + 26) % 26;
  if (!isEncrypt) s = (26 - s) % 26;
  return text.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + s) % 26) + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 + s) % 26) + 97);
    }
    return char;
  }).join('');
}

const cEnc1 = caesarProcess("HELLO", 3, true);
assert(cEnc1 === "KHOOR", `HELLO with shift 3 -> ${cEnc1} (Expected: KHOOR)`);
const cDec1 = caesarProcess(cEnc1, 3, false);
assert(cDec1 === "HELLO", `Decrypted KHOOR with shift 3 -> ${cDec1} (Expected: HELLO)`);

const cCase = caesarProcess("Hello, World! 123", 3, true);
assert(cCase === "Khoor, Zruog! 123", `Case & Punctuation Preserved: ${cCase}`);

const cLarge = caesarProcess("HELLO", 55, true); // 55 mod 26 = 3
assert(cLarge === "KHOOR", `Large shift 55 (mod 26 = 3) -> ${cLarge}`);

const cNeg = caesarProcess("KHOOR", -3, true);
assert(cNeg === "HELLO", `Negative shift -3 on KHOOR -> ${cNeg}`);


// 2. Multiplicative Cipher Verification
console.log("\n--- 2. Testing Multiplicative Cipher ---");
function gcd(a, b) {
  a = Math.abs(a);
  b = Math.abs(b);
  while (b) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

function modInverse(a, m = 26) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return null;
}

function multProcess(text, key, isEncrypt = true) {
  const k = parseInt(key, 10);
  const normKey = ((k % 26) + 26) % 26;
  if (gcd(normKey, 26) !== 1) throw new Error("Key not coprime with 26");
  const factor = isEncrypt ? normKey : modInverse(normKey, 26);
  return text.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65) * factor) % 26 + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97) * factor) % 26 + 97);
    }
    return char;
  }).join('');
}

assert(gcd(5, 26) === 1, "Key 5 is coprime with 26");
assert(modInverse(5, 26) === 21, "Modular inverse of 5 mod 26 is 21 (5 * 21 = 105 = 4*26 + 1)");
assert(gcd(4, 26) === 2, "Key 4 correctly identified as non-coprime (gcd = 2)");
assert(gcd(13, 26) === 13, "Key 13 correctly identified as non-coprime (gcd = 13)");

const mEncHello = multProcess("HELLO", 5, true);
assert(mEncHello === "JUDDS", `Multiplicative HELLO * 5 -> ${mEncHello} (Expected: JUDDS)`);
const mDecHello = multProcess(mEncHello, 5, false);
assert(mDecHello === "HELLO", `Multiplicative Decrypt JUDDS -> ${mDecHello} (Expected: HELLO)`);

const mEncHella = multProcess("HELLA", 5, true);
assert(mEncHella === "JUDDA", `Multiplicative HELLA * 5 -> ${mEncHella} (A=0*5=0=A -> JUDDA)`);


// 3. Hill Cipher Verification
console.log("\n--- 3. Testing Hill Cipher (2x2 and 3x3) ---");
function mod(n, m = 26) {
  return ((n % m) + m) % m;
}

function hill2x2(text, m, isEncrypt = true) {
  const det = mod(m[0][0] * m[1][1] - m[0][1] * m[1][0], 26);
  const detInv = modInverse(det, 26);
  if (!detInv) throw new Error("Matrix not invertible");
  
  const keyMat = isEncrypt ? m : [
    [mod(m[1][1] * detInv, 26), mod(-m[0][1] * detInv, 26)],
    [mod(-m[1][0] * detInv, 26), mod(m[0][0] * detInv, 26)]
  ];

  let padded = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (padded.length % 2 !== 0) padded += 'X';

  let res = '';
  for (let i = 0; i < padded.length; i += 2) {
    const p0 = padded.charCodeAt(i) - 65;
    const p1 = padded.charCodeAt(i + 1) - 65;
    const c0 = mod(keyMat[0][0] * p0 + keyMat[0][1] * p1, 26);
    const c1 = mod(keyMat[1][0] * p0 + keyMat[1][1] * p1, 26);
    res += String.fromCharCode(c0 + 65, c1 + 65);
  }
  return res;
}

const key2x2 = [[3, 3], [2, 5]];
const hEnc2 = hill2x2("HELP", key2x2, true);
assert(hEnc2 === "HIAT", `Hill 2x2 HELP -> ${hEnc2} (Expected: HIAT)`);
const hDec2 = hill2x2(hEnc2, key2x2, false);
assert(hDec2 === "HELP", `Hill 2x2 Decrypt HIAT -> ${hDec2} (Expected: HELP)`);

// 3x3
function det3x3(m) {
  const a = m[0][0], b = m[0][1], c = m[0][2];
  const d = m[1][0], e = m[1][1], f = m[1][2];
  const g = m[2][0], h = m[2][1], i = m[2][2];
  return mod(a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g), 26);
}

function inv3x3(m) {
  const det = det3x3(m);
  const detInv = modInverse(det, 26);
  if (!detInv) return null;

  const a = m[0][0], b = m[0][1], c = m[0][2];
  const e = m[1][0], f = m[1][1], g = m[1][2];
  const h = m[2][0], i = m[2][1], j = m[2][2];

  const c00 = mod(f * j - g * i, 26);
  const c01 = mod(-(e * j - g * h), 26);
  const c02 = mod(e * i - f * h, 26);
  const c10 = mod(-(b * j - c * i), 26);
  const c11 = mod(a * j - c * h, 26);
  const c12 = mod(-(a * i - b * h), 26);
  const c20 = mod(b * g - c * f, 26);
  const c21 = mod(-(a * g - c * e), 26);
  const c22 = mod(a * f - b * e, 26);

  return [
    [mod(c00 * detInv, 26), mod(c10 * detInv, 26), mod(c20 * detInv, 26)],
    [mod(c01 * detInv, 26), mod(c11 * detInv, 26), mod(c21 * detInv, 26)],
    [mod(c02 * detInv, 26), mod(c12 * detInv, 26), mod(c22 * detInv, 26)]
  ];
}

function hill3x3(text, m, isEncrypt = true) {
  const keyMat = isEncrypt ? m : inv3x3(m);
  let padded = text.toUpperCase().replace(/[^A-Z]/g, '');
  while (padded.length % 3 !== 0) padded += 'X';

  let res = '';
  for (let i = 0; i < padded.length; i += 3) {
    const v = [padded.charCodeAt(i) - 65, padded.charCodeAt(i + 1) - 65, padded.charCodeAt(i + 2) - 65];
    for (let r = 0; r < 3; r++) {
      const c = mod(keyMat[r][0] * v[0] + keyMat[r][1] * v[1] + keyMat[r][2] * v[2], 26);
      res += String.fromCharCode(c + 65);
    }
  }
  return res;
}

const key3x3 = [[2, 4, 5], [9, 2, 11], [3, 17, 7]];
const hEnc3 = hill3x3("ATTACKATDAWN", key3x3, true);
assert(hEnc3 === "PNOGKANTGXFX", `Hill 3x3 ATTACKATDAWN -> ${hEnc3} (Expected: PNOGKANTGXFX)`);
const hDec3 = hill3x3(hEnc3, key3x3, false);
assert(hDec3 === "ATTACKATDAWN", `Hill 3x3 Decrypt -> ${hDec3} (Expected: ATTACKATDAWN)`);


// 4. SHA-256 Verification
console.log("\n--- 4. Testing SHA-256 Hashing ---");
async function testSha256() {
  const enc = new TextEncoder().encode("abc");
  const hashBuf = await webcrypto.subtle.digest("SHA-256", enc);
  const hex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  assert(hex === expected, `SHA-256 'abc' -> ${hex}`);
}


// 5. AES-GCM Verification
console.log("\n--- 5. Testing AES-GCM (Web Crypto API) ---");
async function testAesGcm() {
  const rawKey = webcrypto.getRandomValues(new Uint8Array(32)); // 256-bit
  const cryptoKey = await webcrypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const iv1 = webcrypto.getRandomValues(new Uint8Array(12));
  const iv2 = webcrypto.getRandomValues(new Uint8Array(12));

  // Verify non-reused IV
  assert(Buffer.from(iv1).toString('hex') !== Buffer.from(iv2).toString('hex'), "Fresh IV generated on subsequent operations");

  const plaintext = "CryptoLab AES-GCM authenticated payload 2026";
  const encoded = new TextEncoder().encode(plaintext);

  const ct = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, cryptoKey, encoded);
  const decrypted = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: iv1 }, cryptoKey, ct);
  const decText = new TextDecoder().decode(decrypted);

  assert(decText === plaintext, `AES-GCM Round Trip: "${decText}"`);

  // Tamper test
  let tampered = new Uint8Array(ct);
  tampered[0] ^= 0xFF; // Flip bit in ciphertext
  let tamperCaught = false;
  try {
    await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: iv1 }, cryptoKey, tampered);
  } catch (e) {
    tamperCaught = true;
  }
  assert(tamperCaught, "AES-GCM tampered ciphertext rejected with authentication failure");
}


// 6. RSA-OAEP Verification
console.log("\n--- 6. Testing RSA-OAEP (Web Crypto API) ---");
async function testRsaOaep() {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const msg = "CryptoLab RSA Key Exchange";
  const encMsg = new TextEncoder().encode(msg);

  const ciphertext = await webcrypto.subtle.encrypt({ name: "RSA-OAEP" }, keyPair.publicKey, encMsg);
  const decrypted = await webcrypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, ciphertext);
  const decText = new TextDecoder().decode(decrypted);

  assert(decText === msg, `RSA-OAEP Round Trip: "${decText}"`);
}


// 7. HMAC-SHA-256 Verification
console.log("\n--- 7. Testing HMAC-SHA-256 ---");
async function testHmac() {
  const secret = "shared-secret-key-123";
  const key = await webcrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const message = "Verify transaction #9021";
  const msgBytes = new TextEncoder().encode(message);

  const sig = await webcrypto.subtle.sign("HMAC", key, msgBytes);
  const isValid = await webcrypto.subtle.verify("HMAC", key, sig, msgBytes);
  assert(isValid === true, "HMAC signature verified successfully");

  const tamperedMsgBytes = new TextEncoder().encode("Verify transaction #9022");
  const isTamperedValid = await webcrypto.subtle.verify("HMAC", key, sig, tamperedMsgBytes);
  assert(isTamperedValid === false, "HMAC altered message signature rejected");
}

async function runAll() {
  await testSha256();
  await testAesGcm();
  await testRsaOaep();
  await testHmac();

  console.log("\n==================================================");
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log("==================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runAll().catch(err => {
  console.error("Test execution error:", err);
  process.exit(1);
});

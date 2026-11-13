// Node.js crypto test verification
import crypto from 'node:crypto';

console.log("=== CRYPTO VERIFICATION TEST SUITE ===");

// 1. Caesar Cipher
function caesarEncrypt(text, shift) {
  shift = ((shift % 26) + 26) % 26;
  return text.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + shift) % 26) + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 + shift) % 26) + 97);
    }
    return char;
  }).join('');
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, -shift);
}

const caesarTest = caesarEncrypt("HELLO", 3);
console.log(`Caesar HELLO + 3: ${caesarTest} (Expected: KHOOR) -> ${caesarTest === 'KHOOR' ? 'PASS' : 'FAIL'}`);
console.log(`Caesar Decrypt KHOOR - 3: ${caesarDecrypt(caesarTest, 3)} (Expected: HELLO) -> ${caesarDecrypt(caesarTest, 3) === 'HELLO' ? 'PASS' : 'FAIL'}`);

// 2. Multiplicative Cipher
function gcd(a, b) {
  a = Math.abs(a);
  b = Math.abs(b);
  while (b) {
    let t = b;
    b = a % b;
    a = t;
  }
  return a;
}

function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return null;
}

function multiplicativeEncrypt(text, key) {
  if (gcd(key, 26) !== 1) {
    throw new Error(`Key ${key} is not coprime with 26`);
  }
  const k = ((key % 26) + 26) % 26;
  return text.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      const p = code - 65;
      const c = (p * k) % 26;
      return String.fromCharCode(c + 65);
    } else if (code >= 97 && code <= 122) {
      const p = code - 97;
      const c = (p * k) % 26;
      return String.fromCharCode(c + 97);
    }
    return char;
  }).join('');
}

function multiplicativeDecrypt(text, key) {
  if (gcd(key, 26) !== 1) {
    throw new Error(`Key ${key} is not coprime with 26`);
  }
  const inv = modInverse(key, 26);
  return multiplicativeEncrypt(text, inv);
}

const multTestHello = multiplicativeEncrypt("HELLO", 5);
console.log(`Multiplicative HELLO * 5: ${multTestHello} (H=7*5=9:J, E=4*5=20:U, L=11*5=3:D, L=11*5=3:D, O=14*5=70%26=18:S -> JUDDS)`);
const multDecHello = multiplicativeDecrypt(multTestHello, 5);
console.log(`Multiplicative Decrypt: ${multDecHello} (Expected: HELLO) -> ${multDecHello === 'HELLO' ? 'PASS' : 'FAIL'}`);

const multTestHella = multiplicativeEncrypt("HELLA", 5);
console.log(`Multiplicative HELLA * 5: ${multTestHella} (A=0*5=0:A -> JUDDA)`);

// 3. Hill Cipher 2x2 and 3x3
function mod(n, m) {
  return ((n % m) + m) % m;
}

function det3x3(m) {
  const a = m[0][0], b = m[0][1], c = m[0][2];
  const d = m[1][0], e = m[1][1], f = m[1][2];
  const g = m[2][0], h = m[2][1], i = m[2][2];
  return mod(a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g), 26);
}

function inv3x3(m) {
  const d = det3x3(m);
  const detInv = modInverse(d, 26);
  if (!detInv) return null;

  const a = m[0][0], b = m[0][1], c = m[0][2];
  const e = m[1][0], f = m[1][1], g = m[1][2];
  const h = m[2][0], i = m[2][1], j = m[2][2];

  // Cofactor matrix elements
  const c00 = mod(f * j - g * i, 26);
  const c01 = mod(-(e * j - g * h), 26);
  const c02 = mod(e * i - f * h, 26);

  const c10 = mod(-(b * j - c * i), 26);
  const c11 = mod(a * j - c * h, 26);
  const c12 = mod(-(a * i - b * h), 26);

  const c20 = mod(b * g - c * f, 26);
  const c21 = mod(-(a * g - c * e), 26);
  const c22 = mod(a * f - b * e, 26);

  // Transpose (adjugate) multiplied by detInv
  return [
    [mod(c00 * detInv, 26), mod(c10 * detInv, 26), mod(c20 * detInv, 26)],
    [mod(c01 * detInv, 26), mod(c11 * detInv, 26), mod(c21 * detInv, 26)],
    [mod(c02 * detInv, 26), mod(c12 * detInv, 26), mod(c22 * detInv, 26)]
  ];
}

function hill3x3Encrypt(text, matrix) {
  const det = det3x3(matrix);
  if (gcd(det, 26) !== 1) throw new Error(`Matrix det ${det} not invertible mod 26`);

  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  let padded = letters;
  while (padded.length % 3 !== 0) padded += 'X';

  let res = '';
  for (let i = 0; i < padded.length; i += 3) {
    const v = [
      padded.charCodeAt(i) - 65,
      padded.charCodeAt(i + 1) - 65,
      padded.charCodeAt(i + 2) - 65
    ];
    for (let r = 0; r < 3; r++) {
      const c = mod(matrix[r][0] * v[0] + matrix[r][1] * v[1] + matrix[r][2] * v[2], 26);
      res += String.fromCharCode(c + 65);
    }
  }
  return { ciphertext: res, paddingAdded: padded.length - letters.length };
}

function hill3x3Decrypt(ciphertext, matrix) {
  const invMatrix = inv3x3(matrix);
  if (!invMatrix) throw new Error("Matrix not invertible mod 26");

  let res = '';
  for (let i = 0; i < ciphertext.length; i += 3) {
    const v = [
      ciphertext.charCodeAt(i) - 65,
      ciphertext.charCodeAt(i + 1) - 65,
      ciphertext.charCodeAt(i + 2) - 65
    ];
    for (let r = 0; r < 3; r++) {
      const p = mod(invMatrix[r][0] * v[0] + invMatrix[r][1] * v[1] + invMatrix[r][2] * v[2], 26);
      res += String.fromCharCode(p + 65);
    }
  }
  return { plaintext: res, invMatrix };
}

// Test 3x3 matrix:
// [ 6, 24, 1 ]
// [ 13, 16, 10 ]
// [ 20, 17, 15 ]
// Let's test with a known invertible matrix:
// [ 2, 4, 5 ]
// [ 9, 2, 11 ]
// [ 3, 17, 7 ]
const key3x3 = [
  [2, 4, 5],
  [9, 2, 11],
  [3, 17, 7]
];
const d3 = det3x3(key3x3);
console.log(`Key 3x3 Determinant: ${d3}, gcd with 26: ${gcd(d3, 26)}`);
const enc3 = hill3x3Encrypt("ATTACKATDAWN", key3x3);
console.log(`Hill 3x3 Encrypted: ${enc3.ciphertext}`);
const dec3 = hill3x3Decrypt(enc3.ciphertext, key3x3);
console.log(`Hill 3x3 Decrypted: ${dec3.plaintext} -> ${dec3.plaintext === 'ATTACKATDAWN' ? 'PASS' : 'FAIL'}`);

function hill2x2Encrypt(text, matrix) {
  const det = mod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], 26);
  if (gcd(det, 26) !== 1) throw new Error(`Matrix det ${det} not invertible mod 26`);
  
  // Clean letters
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  let padded = letters;
  if (padded.length % 2 !== 0) padded += 'X';
  
  let res = '';
  for (let i = 0; i < padded.length; i += 2) {
    const p0 = padded.charCodeAt(i) - 65;
    const p1 = padded.charCodeAt(i + 1) - 65;
    const c0 = mod(matrix[0][0] * p0 + matrix[0][1] * p1, 26);
    const c1 = mod(matrix[1][0] * p0 + matrix[1][1] * p1, 26);
    res += String.fromCharCode(c0 + 65) + String.fromCharCode(c1 + 65);
  }
  return { ciphertext: res, paddingAdded: padded.length - letters.length };
}

function hill2x2Decrypt(ciphertext, matrix) {
  const det = mod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], 26);
  const detInv = modInverse(det, 26);
  if (!detInv) throw new Error("Determinant not invertible mod 26");
  
  // Adjugate matrix mod 26:
  // [ d  -b ]
  // [ -c  a ]
  const invMatrix = [
    [mod(matrix[1][1] * detInv, 26), mod(-matrix[0][1] * detInv, 26)],
    [mod(-matrix[1][0] * detInv, 26), mod(matrix[0][0] * detInv, 26)]
  ];
  
  let res = '';
  for (let i = 0; i < ciphertext.length; i += 2) {
    const c0 = ciphertext.charCodeAt(i) - 65;
    const c1 = ciphertext.charCodeAt(i + 1) - 65;
    const p0 = mod(invMatrix[0][0] * c0 + invMatrix[0][1] * c1, 26);
    const p1 = mod(invMatrix[1][0] * c0 + invMatrix[1][1] * c1, 26);
    res += String.fromCharCode(p0 + 65) + String.fromCharCode(p1 + 65);
  }
  return { plaintext: res, invMatrix };
}

// Invertible key matrix: [[3, 3], [2, 5]] -> det = 15 - 6 = 9. gcd(9,26)=1. detInv of 9 mod 26: 9*3=27=1 mod 26 -> 3.
const hillKey = [[3, 3], [2, 5]];
const hillEnc = hill2x2Encrypt("HELP", hillKey);
console.log(`Hill 2x2 HELP Encrypted: ${hillEnc.ciphertext}`);
const hillDec = hill2x2Decrypt(hillEnc.ciphertext, hillKey);
console.log(`Hill 2x2 Decrypted: ${hillDec.plaintext} -> ${hillDec.plaintext === 'HELP' ? 'PASS' : 'FAIL'}`);

// 4. SHA-256
const sha256Hash = crypto.createHash('sha256').update('abc').digest('hex');
console.log(`SHA-256 'abc': ${sha256Hash}`);
console.log(`Matches expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad: ${sha256Hash === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' ? 'PASS' : 'FAIL'}`);

// 5. HMAC-SHA-256
const hmacKey = "secret-key";
const hmacMessage = "The quick brown fox jumps over the lazy dog";
const hmacCode = crypto.createHmac('sha256', hmacKey).update(hmacMessage).digest('hex');
console.log(`HMAC-SHA-256: ${hmacCode}`);

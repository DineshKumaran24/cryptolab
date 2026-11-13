// Test Web Crypto API (AES-GCM and RSA-OAEP)
import { webcrypto } from 'node:crypto';

async function testModernCrypto() {
  console.log("=== TESTING WEB CRYPTO API ===");

  // 1. AES-GCM Test
  const rawKey = webcrypto.getRandomValues(new Uint8Array(32)); // 256-bit key
  const aesKey = await webcrypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  const iv = webcrypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const plaintext = "Top secret message for Cryptolab testing!";
  const encText = new TextEncoder().encode(plaintext);

  const ciphertextBuffer = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encText);
  const decryptedBuffer = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertextBuffer);
  const decryptedText = new TextDecoder().decode(decryptedBuffer);

  console.log(`AES-GCM Plaintext: ${plaintext}`);
  console.log(`AES-GCM Decrypted: ${decryptedText} -> ${decryptedText === plaintext ? 'PASS' : 'FAIL'}`);

  // 2. RSA-OAEP Test
  const rsaKeyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const rsaPlaintext = "Secure RSA test vector";
  const rsaEncrypted = await webcrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKeyPair.publicKey,
    new TextEncoder().encode(rsaPlaintext)
  );

  const rsaDecrypted = await webcrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    rsaKeyPair.privateKey,
    rsaEncrypted
  );
  const rsaDecText = new TextDecoder().decode(rsaDecrypted);
  console.log(`RSA-OAEP Plaintext: ${rsaPlaintext}`);
  console.log(`RSA-OAEP Decrypted: ${rsaDecText} -> ${rsaDecText === rsaPlaintext ? 'PASS' : 'FAIL'}`);

  // Export to PEM check
  const spki = await webcrypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
  const spkiB64 = Buffer.from(spki).toString("base64");
  const pubPem = `-----BEGIN PUBLIC KEY-----\n${spkiB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  console.log("RSA Public Key PEM formatted successfully:\n" + pubPem.substring(0, 50) + "...");
}

testModernCrypto().catch(console.error);

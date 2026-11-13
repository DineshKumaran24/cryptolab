/**
 * CryptoLab - AES-GCM Modern Cryptography Engine
 * Implements AES-GCM 128-bit and 256-bit authenticated encryption using Web Crypto API,
 * dynamic cryptographically secure random IV generation,
 * Base64 packaging, and tampering detection.
 */

const AesToolkit = {
  currentKeySize: 256, // 128 or 256 bits

  // Convert ArrayBuffer to Base64
  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },

  // Convert Base64 to Uint8Array
  base64ToBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  // Convert Buffer to Hex string
  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Convert Hex string to Uint8Array
  hexToBuffer(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) throw new Error('Hex string must have an even number of characters.');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
  },

  // Generate cryptographically secure random key
  generateRandomKey(bits = 256) {
    const byteLength = bits / 8;
    const keyBytes = crypto.getRandomValues(new Uint8Array(byteLength));
    return {
      hex: this.bufferToHex(keyBytes),
      base64: this.bufferToBase64(keyBytes),
      bytes: keyBytes
    };
  },

  // Parse key from user input (Hex, Base64, or raw text derived with SHA-256)
  async parseCryptoKey(keyInput, bits = 256) {
    const raw = keyInput.trim();
    if (!raw) throw new Error('Please enter or generate a secret key.');

    const targetBytes = bits / 8;
    let keyBytes = null;

    // Check if valid Hex matching exact length
    const hexPattern = /^[0-9a-fA-F]+$/;
    if (raw.length === targetBytes * 2 && hexPattern.test(raw)) {
      keyBytes = this.hexToBuffer(raw);
    } else {
      // Check if valid Base64
      try {
        const decoded = this.base64ToBuffer(raw);
        if (decoded.length === targetBytes) {
          keyBytes = decoded;
        }
      } catch (e) {
        // Not direct base64
      }
    }

    // If not exact hex or base64, derive key bytes deterministically using SHA-256
    if (!keyBytes) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
      keyBytes = new Uint8Array(hashBuffer).slice(0, targetBytes);
    }

    return await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(plaintext, keyInput, bits = 256) {
    if (!plaintext) throw new Error('Please enter plaintext to encrypt.');
    const cryptoKey = await this.parseCryptoKey(keyInput, bits);

    // Generate fresh 96-bit (12-byte) random IV for GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      cryptoKey,
      encoded
    );

    const ivB64 = this.bufferToBase64(iv);
    const ctB64 = this.bufferToBase64(ciphertextBuffer);
    const bundle = `${ivB64}:${ctB64}`;

    const jsonPackage = JSON.stringify({
      algorithm: 'AES-GCM',
      keySizeBits: bits,
      tagLengthBits: 128,
      iv: ivB64,
      ivHex: this.bufferToHex(iv),
      ciphertext: ctB64,
      combinedPayload: bundle
    }, null, 2);

    return {
      bundle,
      jsonPackage,
      ivHex: this.bufferToHex(iv),
      ivB64,
      ctB64,
      byteLength: ciphertextBuffer.byteLength
    };
  },

  async decrypt(payloadInput, keyInput, bits = 256, customIv = null) {
    if (!payloadInput) throw new Error('Please enter ciphertext bundle to decrypt.');
    const cryptoKey = await this.parseCryptoKey(keyInput, bits);

    let ivBytes = null;
    let ctBytes = null;

    const trimmed = payloadInput.trim();

    // Check if input is JSON package
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.iv && parsed.ciphertext) {
          ivBytes = this.base64ToBuffer(parsed.iv);
          ctBytes = this.base64ToBuffer(parsed.ciphertext);
        }
      } catch (e) {
        // Fall back to separator parsing
      }
    }

    // Check if input is separated by colon "IV:Ciphertext"
    if (!ivBytes && trimmed.includes(':')) {
      const parts = trimmed.split(':');
      if (parts.length >= 2) {
        ivBytes = this.base64ToBuffer(parts[0].trim());
        ctBytes = this.base64ToBuffer(parts.slice(1).join(':').trim());
      }
    }

    // If separate IV was supplied
    if (!ivBytes && customIv) {
      const cleanIv = customIv.trim();
      ivBytes = /^[0-9a-fA-F]{24}$/.test(cleanIv)
        ? this.hexToBuffer(cleanIv)
        : this.base64ToBuffer(cleanIv);
      ctBytes = this.base64ToBuffer(trimmed);
    }

    if (!ivBytes || !ctBytes) {
      throw new Error('Invalid ciphertext format. Expected "IV(Base64):Ciphertext(Base64)" or JSON package.');
    }

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
        cryptoKey,
        ctBytes
      );
      return new TextDecoder().decode(decryptedBuffer);
    } catch (err) {
      throw new Error('Decryption failed! Ciphertext authentication tag did not match. Ensure key, IV, and ciphertext are intact.');
    }
  },

  // UI Controller Binding
  initUI() {
    const inputEl = document.getElementById('aes-input');
    const keyInput = document.getElementById('aes-key');
    const keySize128 = document.getElementById('aes-size-128');
    const keySize256 = document.getElementById('aes-size-256');
    const btnGenKey = document.getElementById('aes-gen-key-btn');
    const outputEl = document.getElementById('aes-output');
    const ivBadge = document.getElementById('aes-iv-display');
    const btnEncrypt = document.getElementById('aes-encrypt-btn');
    const btnDecrypt = document.getElementById('aes-decrypt-btn');
    const btnCopy = document.getElementById('aes-copy-btn');
    const btnClear = document.getElementById('aes-clear-btn');
    const btnSwap = document.getElementById('aes-swap-btn');
    const btnExample = document.getElementById('aes-example-btn');

    if (!inputEl || !outputEl) return;

    // Key size toggle
    if (keySize128 && keySize256) {
      keySize128.addEventListener('click', () => {
        keySize128.classList.add('active');
        keySize256.classList.remove('active');
        this.currentKeySize = 128;
        const newKey = this.generateRandomKey(128);
        if (keyInput) keyInput.value = newKey.hex;
        Toast.info('Key Size Updated', 'Switched to AES-GCM 128-bit key (16 bytes).');
      });

      keySize256.addEventListener('click', () => {
        keySize256.classList.add('active');
        keySize128.classList.remove('active');
        this.currentKeySize = 256;
        const newKey = this.generateRandomKey(256);
        if (keyInput) keyInput.value = newKey.hex;
        Toast.info('Key Size Updated', 'Switched to AES-GCM 256-bit key (32 bytes).');
      });
    }

    // Key Generation
    if (btnGenKey) {
      btnGenKey.addEventListener('click', () => {
        const newKey = this.generateRandomKey(this.currentKeySize);
        if (keyInput) keyInput.value = newKey.hex;
        Toast.success('Key Generated', `Generated cryptographically secure random ${this.currentKeySize}-bit key.`);
      });
    }

    // Encrypt
    if (btnEncrypt) {
      btnEncrypt.addEventListener('click', async () => {
        try {
          const text = inputEl.value;
          const key = keyInput ? keyInput.value : '';
          const res = await this.encrypt(text, key, this.currentKeySize);
          outputEl.textContent = res.bundle;
          if (ivBadge) ivBadge.textContent = `Latest IV (96-bit hex): ${res.ivHex}`;

          HistoryManager.addEntry({
            algorithm: 'AES-GCM',
            operation: 'Encryption',
            inputSnippet: text,
            outputSnippet: res.bundle,
            details: `Key Size: ${this.currentKeySize}-bit, IV: ${res.ivHex.substring(0, 8)}...`
          });
          Toast.success('Encrypted', `AES-GCM ${this.currentKeySize}-bit authenticated encryption completed.`);
        } catch (err) {
          Toast.error('Encryption Failed', err.message);
        }
      });
    }

    // Decrypt
    if (btnDecrypt) {
      btnDecrypt.addEventListener('click', async () => {
        try {
          const payload = inputEl.value;
          const key = keyInput ? keyInput.value : '';
          const plaintext = await this.decrypt(payload, key, this.currentKeySize);
          outputEl.textContent = plaintext;

          HistoryManager.addEntry({
            algorithm: 'AES-GCM',
            operation: 'Decryption',
            inputSnippet: payload,
            outputSnippet: plaintext,
            details: `Key Size: ${this.currentKeySize}-bit`
          });
          Toast.success('Decrypted', 'AES-GCM payload successfully authenticated and decrypted.');
        } catch (err) {
          Toast.error('Decryption Failed', err.message);
        }
      });
    }

    // Copy
    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        Clipboard.copy(outputEl.textContent, btnCopy);
      });
    }

    // Clear
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        inputEl.value = '';
        outputEl.textContent = '';
        Toast.info('Cleared', 'AES workspace reset.');
      });
    }

    // Swap
    if (btnSwap) {
      btnSwap.addEventListener('click', () => {
        const out = outputEl.textContent;
        if (!out) {
          Toast.warning('Cannot Swap', 'Output field is currently empty.');
          return;
        }
        inputEl.value = out;
        outputEl.textContent = '';
        Toast.info('Swapped', 'Transferred output to input.');
      });
    }

    // Example
    if (btnExample) {
      btnExample.addEventListener('click', () => {
        inputEl.value = 'Confidential financial transaction payload: $50,000 to CryptoLab Vault.';
        const key = this.generateRandomKey(this.currentKeySize);
        if (keyInput) keyInput.value = key.hex;
        Toast.info('Example Loaded', `Loaded sample text and fresh ${this.currentKeySize}-bit AES key.`);
      });
    }

    // Generate initial key if empty
    if (keyInput && !keyInput.value) {
      const initKey = this.generateRandomKey(256);
      keyInput.value = initKey.hex;
    }
  }
};

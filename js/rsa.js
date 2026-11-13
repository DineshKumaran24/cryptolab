/**
 * CryptoLab - RSA-OAEP Modern Asymmetric Cryptography Engine
 * Implements 2048-bit RSA-OAEP key pair generation,
 * PEM formatting/export, public-key encryption, private-key decryption,
 * and maximum payload capacity validation using Web Crypto API.
 */

const RsaToolkit = {
  currentKeyPair: null,
  MAX_MESSAGE_BYTES: 190, // 2048 / 8 - 2 * 32 - 2 = 190 bytes for RSA-OAEP with SHA-256

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

  // Format Base64 string to standard 64-column PEM
  wrapPem(base64, type) {
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
  },

  // Extract clean Base64 from PEM wrapper
  cleanPem(pem) {
    return pem
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s+/g, '');
  },

  // Generate 2048-bit RSA-OAEP key pair
  async generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    // Export SPKI (public) and PKCS#8 (private)
    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const pkcs8Buffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const publicPem = this.wrapPem(this.bufferToBase64(spkiBuffer), 'PUBLIC KEY');
    const privatePem = this.wrapPem(this.bufferToBase64(pkcs8Buffer), 'PRIVATE KEY');

    this.currentKeyPair = {
      keyPair,
      publicPem,
      privatePem
    };

    return this.currentKeyPair;
  },

  // Import Public Key from PEM
  async importPublicKey(pem) {
    const b64 = this.cleanPem(pem);
    const buffer = this.base64ToBuffer(b64);
    return await crypto.subtle.importKey(
      'spki',
      buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
  },

  // Import Private Key from PEM
  async importPrivateKey(pem) {
    const b64 = this.cleanPem(pem);
    const buffer = this.base64ToBuffer(b64);
    return await crypto.subtle.importKey(
      'pkcs8',
      buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );
  },

  async encrypt(plaintext, publicPem) {
    if (!plaintext) throw new Error('Please enter plaintext to encrypt.');
    if (!publicPem) throw new Error('Please provide or generate an RSA Public Key.');

    const encoded = new TextEncoder().encode(plaintext);
    if (encoded.byteLength > this.MAX_MESSAGE_BYTES) {
      throw new Error(`Message size (${encoded.byteLength} bytes) exceeds RSA-OAEP 2048-bit capacity limit of ${this.MAX_MESSAGE_BYTES} bytes. In standard cryptography, RSA is used to encrypt symmetric keys (hybrid encryption), not large files.`);
    }

    try {
      const pubKey = await this.importPublicKey(publicPem);
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pubKey,
        encoded
      );
      return this.bufferToBase64(encryptedBuffer);
    } catch (err) {
      throw new Error('RSA Encryption failed. Verify that the public key is a valid 2048-bit RSA-OAEP PEM.');
    }
  },

  async decrypt(ciphertextBase64, privatePem) {
    if (!ciphertextBase64) throw new Error('Please enter RSA ciphertext to decrypt.');
    if (!privatePem) throw new Error('Please provide or generate an RSA Private Key.');

    try {
      const privKey = await this.importPrivateKey(privatePem);
      const ctBuffer = this.base64ToBuffer(ciphertextBase64.trim());
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privKey,
        ctBuffer
      );
      return new TextDecoder().decode(decryptedBuffer);
    } catch (err) {
      throw new Error('RSA Decryption failed! The private key does not correspond to the public key used for encryption, or the ciphertext was corrupted.');
    }
  },

  // UI Controller Binding
  initUI() {
    const btnGenKeys = document.getElementById('rsa-gen-keys-btn');
    const pubKeyTextarea = document.getElementById('rsa-public-key');
    const privKeyTextarea = document.getElementById('rsa-private-key');
    const btnCopyPub = document.getElementById('rsa-copy-pub-btn');
    const btnCopyPriv = document.getElementById('rsa-copy-priv-btn');
    const inputEl = document.getElementById('rsa-input');
    const byteCounter = document.getElementById('rsa-byte-counter');
    const outputEl = document.getElementById('rsa-output');
    const btnEncrypt = document.getElementById('rsa-encrypt-btn');
    const btnDecrypt = document.getElementById('rsa-decrypt-btn');
    const btnCopyOutput = document.getElementById('rsa-copy-output-btn');
    const btnClear = document.getElementById('rsa-clear-btn');
    const btnSwap = document.getElementById('rsa-swap-btn');
    const btnExample = document.getElementById('rsa-example-btn');

    if (!pubKeyTextarea || !outputEl) return;

    // Byte counter updater
    if (inputEl && byteCounter) {
      inputEl.addEventListener('input', () => {
        const bytes = new TextEncoder().encode(inputEl.value).byteLength;
        byteCounter.textContent = `${bytes} / ${this.MAX_MESSAGE_BYTES} bytes`;
        if (bytes > this.MAX_MESSAGE_BYTES) {
          byteCounter.style.color = 'var(--danger)';
          byteCounter.style.fontWeight = '700';
        } else {
          byteCounter.style.color = 'var(--text-muted)';
          byteCounter.style.fontWeight = '500';
        }
      });
    }

    // Key Generation
    if (btnGenKeys) {
      btnGenKeys.addEventListener('click', async () => {
        try {
          btnGenKeys.disabled = true;
          const origText = btnGenKeys.innerHTML;
          btnGenKeys.innerHTML = '<span class="loading-spinner"></span> Generating 2048-bit Key Pair...';
          
          const keys = await this.generateKeyPair();
          pubKeyTextarea.value = keys.publicPem;
          privKeyTextarea.value = keys.privatePem;
          
          btnGenKeys.disabled = false;
          btnGenKeys.innerHTML = origText;
          Toast.success('Key Pair Ready', 'Generated 2048-bit RSA-OAEP Public and Private key pair.');
        } catch (err) {
          btnGenKeys.disabled = false;
          Toast.error('Keygen Failed', err.message);
        }
      });
    }

    // Copy Keys
    if (btnCopyPub) {
      btnCopyPub.addEventListener('click', () => {
        Clipboard.copy(pubKeyTextarea.value, btnCopyPub);
      });
    }

    if (btnCopyPriv) {
      btnCopyPriv.addEventListener('click', () => {
        Clipboard.copy(privKeyTextarea.value, btnCopyPriv);
      });
    }

    // Encrypt
    if (btnEncrypt) {
      btnEncrypt.addEventListener('click', async () => {
        try {
          const text = inputEl.value;
          const pubPem = pubKeyTextarea.value;
          const ctB64 = await this.encrypt(text, pubPem);
          outputEl.textContent = ctB64;

          HistoryManager.addEntry({
            algorithm: 'RSA-OAEP',
            operation: 'Encryption',
            inputSnippet: text,
            outputSnippet: ctB64,
            details: '2048-bit Key with SHA-256 padding'
          });
          Toast.success('Encrypted', 'RSA-OAEP public key encryption completed.');
        } catch (err) {
          Toast.error('Encryption Failed', err.message);
        }
      });
    }

    // Decrypt
    if (btnDecrypt) {
      btnDecrypt.addEventListener('click', async () => {
        try {
          const ct = inputEl.value;
          const privPem = privKeyTextarea.value;
          const pt = await this.decrypt(ct, privPem);
          outputEl.textContent = pt;

          HistoryManager.addEntry({
            algorithm: 'RSA-OAEP',
            operation: 'Decryption',
            inputSnippet: ct,
            outputSnippet: pt,
            details: '2048-bit Private Key Decryption'
          });
          Toast.success('Decrypted', 'RSA-OAEP private key decryption successful.');
        } catch (err) {
          Toast.error('Decryption Failed', err.message);
        }
      });
    }

    // Copy Output
    if (btnCopyOutput) {
      btnCopyOutput.addEventListener('click', () => {
        Clipboard.copy(outputEl.textContent, btnCopyOutput);
      });
    }

    // Clear
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        inputEl.value = '';
        outputEl.textContent = '';
        if (byteCounter) byteCounter.textContent = `0 / ${this.MAX_MESSAGE_BYTES} bytes`;
        Toast.info('Cleared', 'RSA input and output cleared.');
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
        if (byteCounter) {
          const bytes = new TextEncoder().encode(inputEl.value).byteLength;
          byteCounter.textContent = `${bytes} / ${this.MAX_MESSAGE_BYTES} bytes`;
        }
        Toast.info('Swapped', 'Transferred ciphertext to input.');
      });
    }

    // Example
    if (btnExample) {
      btnExample.addEventListener('click', async () => {
        inputEl.value = 'CryptoLab Secret Key Exchange Token: 0x9A4F2E1B';
        if (byteCounter) {
          const bytes = new TextEncoder().encode(inputEl.value).byteLength;
          byteCounter.textContent = `${bytes} / ${this.MAX_MESSAGE_BYTES} bytes`;
        }
        if (!pubKeyTextarea.value || !privKeyTextarea.value) {
          await this.generateKeyPair();
          pubKeyTextarea.value = this.currentKeyPair.publicPem;
          privKeyTextarea.value = this.currentKeyPair.privatePem;
        }
        Toast.info('Example Loaded', 'Loaded RSA test vector and verified keypair.');
      });
    }

    // Auto-generate keys on load if empty
    if (!pubKeyTextarea.value) {
      this.generateKeyPair().then(keys => {
        pubKeyTextarea.value = keys.publicPem;
        privKeyTextarea.value = keys.privatePem;
      }).catch(console.error);
    }
  }
};

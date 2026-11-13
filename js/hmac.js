/**
 * CryptoLab - HMAC-SHA-256 Message Authentication Engine
 * Implements RFC 2104 / RFC 4231 keyed-hash message authentication
 * code generation and verification using Web Crypto API.
 */

const HmacToolkit = {
  // Convert ArrayBuffer to Hex string
  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  // Convert ArrayBuffer to Base64
  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },

  // Convert Hex string to Uint8Array
  hexToBuffer(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) throw new Error('Hex string must have an even length.');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
  },

  // Import key for HMAC
  async importHmacKey(keyText) {
    if (!keyText || keyText.trim() === '') {
      throw new Error('Please enter a secret key for HMAC.');
    }
    const rawKey = new TextEncoder().encode(keyText);
    return await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  },

  // Compute HMAC
  async generateMac(message, secretKey) {
    if (!message) throw new Error('Please enter a message to sign.');
    const key = await this.importHmacKey(secretKey);
    const msgData = new TextEncoder().encode(message);
    const signatureBuffer = await crypto.subtle.sign('HMAC', key, msgData);

    return {
      hex: this.bufferToHex(signatureBuffer),
      base64: this.bufferToBase64(signatureBuffer),
      byteLength: signatureBuffer.byteLength
    };
  },

  // Verify HMAC
  async verifyMac(message, secretKey, suppliedMac) {
    if (!message) throw new Error('Please enter the original message.');
    if (!suppliedMac) throw new Error('Please provide the HMAC tag to verify.');
    const key = await this.importHmacKey(secretKey);
    const msgData = new TextEncoder().encode(message);

    const cleanMac = suppliedMac.trim();
    let macBytes = null;

    // Check if hex or base64
    const hexPattern = /^[0-9a-fA-F]{64}$/;
    if (hexPattern.test(cleanMac)) {
      macBytes = this.hexToBuffer(cleanMac);
    } else {
      try {
        const decoded = window.atob(cleanMac);
        const bytes = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
          bytes[i] = decoded.charCodeAt(i);
        }
        if (bytes.length === 32) {
          macBytes = bytes;
        }
      } catch (e) {
        // Not base64
      }
    }

    if (!macBytes) {
      throw new Error('Invalid HMAC format. Expected 64-character Hex string or 32-byte Base64 token.');
    }

    const isValid = await crypto.subtle.verify('HMAC', key, macBytes, msgData);
    const expected = await this.generateMac(message, secretKey);

    return {
      isValid,
      expectedHex: expected.hex,
      providedHex: this.bufferToHex(macBytes)
    };
  },

  // UI Controller Binding
  initUI() {
    // Generate Tab elements
    const genMsgInput = document.getElementById('hmac-gen-msg');
    const genKeyInput = document.getElementById('hmac-gen-key');
    const genOutputEl = document.getElementById('hmac-gen-output');
    const btnGen = document.getElementById('hmac-generate-btn');
    const btnCopyGen = document.getElementById('hmac-gen-copy-btn');
    const btnClearGen = document.getElementById('hmac-gen-clear-btn');
    const btnExampleGen = document.getElementById('hmac-gen-example-btn');

    // Verify Tab elements
    const verMsgInput = document.getElementById('hmac-ver-msg');
    const verKeyInput = document.getElementById('hmac-ver-key');
    const verTagInput = document.getElementById('hmac-ver-tag');
    const btnVerify = document.getElementById('hmac-verify-btn');
    const verStatusBanner = document.getElementById('hmac-ver-status');
    const btnExampleVer = document.getElementById('hmac-ver-example-btn');

    // Generate MAC Action
    if (btnGen) {
      btnGen.addEventListener('click', async () => {
        try {
          const msg = genMsgInput.value;
          const key = genKeyInput.value;
          const res = await this.generateMac(msg, key);
          genOutputEl.textContent = res.hex;

          HistoryManager.addEntry({
            algorithm: 'HMAC-SHA256',
            operation: 'HMAC Sign',
            inputSnippet: msg,
            outputSnippet: res.hex,
            details: 'RFC 2104 / SHA-256 Digest'
          });
          Toast.success('MAC Generated', 'HMAC-SHA-256 authentication code computed.');
        } catch (err) {
          Toast.error('Generation Failed', err.message);
        }
      });
    }

    // Copy MAC
    if (btnCopyGen) {
      btnCopyGen.addEventListener('click', () => {
        Clipboard.copy(genOutputEl.textContent, btnCopyGen);
      });
    }

    // Clear Generation
    if (btnClearGen) {
      btnClearGen.addEventListener('click', () => {
        genMsgInput.value = '';
        genKeyInput.value = '';
        genOutputEl.textContent = '';
        Toast.info('Cleared', 'HMAC generation fields cleared.');
      });
    }

    // Example Generation
    if (btnExampleGen) {
      btnExampleGen.addEventListener('click', () => {
        genMsgInput.value = 'Transfer $1,000,000 to Account #849204';
        genKeyInput.value = 'bank-secret-signing-key-2026';
        Toast.info('Example Loaded', 'Loaded message and secret key for HMAC.');
      });
    }

    // Verify MAC Action
    if (btnVerify) {
      btnVerify.addEventListener('click', async () => {
        try {
          const msg = verMsgInput.value;
          const key = verKeyInput.value;
          const tag = verTagInput.value;
          const res = await this.verifyMac(msg, key, tag);

          if (res.isValid) {
            verStatusBanner.className = 'verify-status-banner match';
            verStatusBanner.innerHTML = `
              <div class="verify-status-icon">✓</div>
              <div>
                <strong>AUTHENTICATION VERIFIED: VALID</strong><br>
                The HMAC signature matches the message and secret key. The message is authentic and unaltered.
              </div>
            `;
            Toast.success('Verified', 'HMAC tag matches message and key.');
          } else {
            verStatusBanner.className = 'verify-status-banner mismatch';
            verStatusBanner.innerHTML = `
              <div class="verify-status-icon">✕</div>
              <div>
                <strong>AUTHENTICATION FAILED: INVALID TAG</strong><br>
                The provided HMAC code did not match. The message was altered or the secret key is incorrect.
              </div>
            `;
            Toast.error('Verification Failed', 'HMAC tag does not match expected value.');
          }

          HistoryManager.addEntry({
            algorithm: 'HMAC-SHA256',
            operation: 'HMAC Verify',
            inputSnippet: msg,
            outputSnippet: res.isValid ? 'MATCH (Valid)' : 'MISMATCH (Tampered)',
            details: `Result: ${res.isValid ? 'Valid' : 'Invalid'}`
          });
        } catch (err) {
          Toast.error('Verification Error', err.message);
        }
      });
    }

    // Example Verification
    if (btnExampleVer) {
      btnExampleVer.addEventListener('click', async () => {
        const msg = 'Secure payload from CryptoLab client';
        const key = 'shared-crypto-secret-key';
        const mac = await this.generateMac(msg, key);
        verMsgInput.value = msg;
        verKeyInput.value = key;
        verTagInput.value = mac.hex;
        Toast.info('Example Loaded', 'Loaded matching message, key, and computed HMAC tag.');
      });
    }
  }
};

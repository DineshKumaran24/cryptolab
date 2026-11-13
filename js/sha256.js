/**
 * CryptoLab - SHA-256 Cryptographic Hash Engine
 * Implements FIPS 180-2 compliant 256-bit hashing using Web Crypto API,
 * provides live hex digestion, and interactive Avalanche Effect analysis.
 */

const Sha256Toolkit = {
  // Convert ArrayBuffer to 64-character lowercase Hex string
  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  // Compute SHA-256 Hash
  async hash(text) {
    const encoded = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    return this.bufferToHex(hashBuffer);
  },

  // Calculate bit difference between two hex hashes (Hamming distance)
  calculateHammingDistance(hex1, hex2) {
    if (hex1.length !== hex2.length) return 0;
    let diffBits = 0;
    for (let i = 0; i < hex1.length; i++) {
      const v1 = parseInt(hex1[i], 16);
      const v2 = parseInt(hex2[i], 16);
      let xor = v1 ^ v2;
      while (xor > 0) {
        if (xor & 1) diffBits++;
        xor >>= 1;
      }
    }
    return diffBits;
  },

  // UI Controller Binding
  initUI() {
    const inputEl = document.getElementById('sha-input');
    const outputEl = document.getElementById('sha-output');
    const bitLenBadge = document.getElementById('sha-bit-len');
    const byteLenBadge = document.getElementById('sha-byte-len');
    const btnHash = document.getElementById('sha-hash-btn');
    const btnCopy = document.getElementById('sha-copy-btn');
    const btnClear = document.getElementById('sha-clear-btn');
    const btnExample = document.getElementById('sha-example-btn');

    // Avalanche effect elements
    const avInputA = document.getElementById('av-input-a');
    const avInputB = document.getElementById('av-input-b');
    const avHashA = document.getElementById('av-hash-a');
    const avHashB = document.getElementById('av-hash-b');
    const avMetric = document.getElementById('av-metric');

    if (!inputEl || !outputEl) return;

    const performHash = async (saveHistory = false) => {
      try {
        const text = inputEl.value;
        const hex = await this.hash(text);
        outputEl.textContent = hex;
        if (bitLenBadge) bitLenBadge.textContent = '256 bits';
        if (byteLenBadge) byteLenBadge.textContent = '32 bytes (64 hex characters)';

        if (saveHistory) {
          HistoryManager.addEntry({
            algorithm: 'SHA-256',
            operation: 'Hash',
            inputSnippet: text,
            outputSnippet: hex,
            details: '256-bit Digest (One-Way)'
          });
          Toast.success('Hash Generated', 'SHA-256 cryptographic digest computed.');
        }
      } catch (err) {
        Toast.error('Hashing Failed', err.message);
      }
    };

    // Live update on input typing
    inputEl.addEventListener('input', () => performHash(false));

    // Explicit hash button
    if (btnHash) {
      btnHash.addEventListener('click', () => performHash(true));
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
        if (bitLenBadge) bitLenBadge.textContent = '0 bits';
        if (byteLenBadge) byteLenBadge.textContent = '0 bytes';
        Toast.info('Cleared', 'SHA-256 field cleared.');
      });
    }

    // Example: Standard FIPS 180-2 Test Vector 'abc'
    if (btnExample) {
      btnExample.addEventListener('click', async () => {
        inputEl.value = 'abc';
        await performHash(true);
        Toast.info('Test Vector Loaded', 'Loaded standard FIPS test vector "abc". Hash begins with ba7816bf...');
      });
    }

    // Avalanche Comparator logic
    const updateAvalanche = async () => {
      if (!avInputA || !avInputB || !avHashA || !avHashB || !avMetric) return;
      const tA = avInputA.value;
      const tB = avInputB.value;
      const hA = await this.hash(tA);
      const hB = await this.hash(tB);
      avHashA.textContent = hA;
      avHashB.textContent = hB;

      const flippedBits = this.calculateHammingDistance(hA, hB);
      const percentage = ((flippedBits / 256) * 100).toFixed(1);
      avMetric.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline><polyline points="17 6 23 6 23 12"></polyline></svg>
        <span>${flippedBits} of 256 bits changed (${percentage}% avalanche divergence)</span>
      `;
    };

    if (avInputA && avInputB) {
      avInputA.addEventListener('input', updateAvalanche);
      avInputB.addEventListener('input', updateAvalanche);
      updateAvalanche();
    }

    // Initial hash if input has default
    if (inputEl.value) {
      performHash(false);
    }
  }
};

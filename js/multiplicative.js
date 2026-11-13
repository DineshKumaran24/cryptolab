/**
 * CryptoLab - Multiplicative Cipher Engine
 * Modular arithmetic modulo 26, coprime key validation,
 * modular multiplicative inverse calculation, and interactive UI.
 */

const MultiplicativeCipher = {
  COPRIME_KEYS: [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25],

  gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b) {
      const t = b;
      b = a % b;
      a = t;
    }
    return a;
  },

  modInverse(a, m = 26) {
    a = ((a % m) + m) % m;
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return null;
  },

  validateKey(key) {
    const k = parseInt(key, 10);
    if (isNaN(k)) {
      return { valid: false, message: 'Please enter a valid integer for the key.' };
    }
    const normalizedKey = ((k % 26) + 26) % 26;
    if (normalizedKey === 0) {
      return { valid: false, message: 'Key cannot be 0 (mod 26).' };
    }
    const d = this.gcd(normalizedKey, 26);
    if (d !== 1) {
      const reasons = [];
      if (normalizedKey % 2 === 0) reasons.push('shares a common factor of 2 with 26');
      if (normalizedKey % 13 === 0) reasons.push('shares a common factor of 13 with 26');
      return {
        valid: false,
        k: normalizedKey,
        gcd: d,
        message: `Invalid key: ${key} (mod 26 = ${normalizedKey}) is NOT coprime with 26 (gcd = ${d}). It ${reasons.join(' and ')}. Only coprime keys have a modular inverse!`
      };
    }
    const inv = this.modInverse(normalizedKey, 26);
    return {
      valid: true,
      k: normalizedKey,
      inverse: inv,
      message: `Valid coprime key (gcd = 1). Modular multiplicative inverse is ${inv} (because ${normalizedKey} × ${inv} = ${normalizedKey * inv} ≡ 1 mod 26).`
    };
  },

  process(text, key, isEncrypt = true) {
    if (!text) {
      throw new Error('Please enter plaintext or ciphertext to process.');
    }

    const val = this.validateKey(key);
    if (!val.valid) {
      throw new Error(val.message);
    }

    const multFactor = isEncrypt ? val.k : val.inverse;
    const steps = [];
    let output = '';

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const code = char.charCodeAt(0);
      let transformed = char;
      let stepInfo = null;

      if (code >= 65 && code <= 90) {
        // Uppercase
        const p = code - 65;
        const c = (p * multFactor) % 26;
        transformed = String.fromCharCode(c + 65);
        stepInfo = {
          char,
          type: 'Upper',
          origVal: p,
          formula: isEncrypt 
            ? `(${p} × ${val.k}) = ${p * val.k} ≡ ${c} mod 26`
            : `(${p} × ${val.inverse}) = ${p * val.inverse} ≡ ${c} mod 26`,
          newVal: c,
          result: transformed
        };
      } else if (code >= 97 && code <= 122) {
        // Lowercase
        const p = code - 97;
        const c = (p * multFactor) % 26;
        transformed = String.fromCharCode(c + 97);
        stepInfo = {
          char,
          type: 'Lower',
          origVal: p,
          formula: isEncrypt 
            ? `(${p} × ${val.k}) = ${p * val.k} ≡ ${c} mod 26`
            : `(${p} × ${val.inverse}) = ${p * val.inverse} ≡ ${c} mod 26`,
          newVal: c,
          result: transformed
        };
      } else {
        stepInfo = {
          char,
          type: 'Symbol/Space',
          origVal: '—',
          formula: 'Preserved unchanged',
          newVal: '—',
          result: char
        };
      }

      output += transformed;
      if (steps.length < 25) {
        steps.push(stepInfo);
      }
    }

    return {
      output,
      key: val.k,
      inverse: val.inverse,
      steps
    };
  },

  encrypt(text, key) {
    return this.process(text, key, true);
  },

  decrypt(text, key) {
    return this.process(text, key, false);
  },

  // UI Controller Binding
  initUI() {
    const inputEl = document.getElementById('mult-input');
    const keyInput = document.getElementById('mult-key');
    const statusBanner = document.getElementById('mult-status-banner');
    const quickPickContainer = document.getElementById('mult-quick-picks');
    const outputEl = document.getElementById('mult-output');
    const btnEncrypt = document.getElementById('mult-encrypt-btn');
    const btnDecrypt = document.getElementById('mult-decrypt-btn');
    const btnCopy = document.getElementById('mult-copy-btn');
    const btnClear = document.getElementById('mult-clear-btn');
    const btnSwap = document.getElementById('mult-swap-btn');
    const btnExample = document.getElementById('mult-example-btn');
    const stepsTableBody = document.getElementById('mult-steps-body');

    if (!inputEl || !outputEl) return;

    // Render quick-pick buttons for coprime keys
    if (quickPickContainer) {
      quickPickContainer.innerHTML = this.COPRIME_KEYS.map(k => `
        <button type="button" class="quick-pick-btn" data-key="${k}">${k}</button>
      `).join('');

      quickPickContainer.querySelectorAll('.quick-pick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const k = btn.getAttribute('data-key');
          if (keyInput) {
            keyInput.value = k;
            updateStatusUI();
          }
        });
      });
    }

    const updateStatusUI = () => {
      if (!keyInput || !statusBanner) return;
      const val = this.validateKey(keyInput.value);
      if (val.valid) {
        statusBanner.className = 'coprime-status-banner coprime-valid';
        statusBanner.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
          <div>
            <strong>Coprime Key Confirmed:</strong> ${val.message}
          </div>
        `;
      } else {
        statusBanner.className = 'coprime-status-banner coprime-invalid';
        statusBanner.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
          <div>
            <strong>Coprime Key Error:</strong> ${val.message}
          </div>
        `;
      }
    };

    if (keyInput) {
      keyInput.addEventListener('input', updateStatusUI);
      updateStatusUI();
    }

    // Encrypt
    if (btnEncrypt) {
      btnEncrypt.addEventListener('click', () => {
        try {
          const text = inputEl.value;
          const key = keyInput ? keyInput.value : 5;
          const res = this.encrypt(text, key);
          outputEl.textContent = res.output;
          this.renderSteps(res.steps, stepsTableBody);

          HistoryManager.addEntry({
            algorithm: 'Multiplicative Cipher',
            operation: 'Encryption',
            inputSnippet: text,
            outputSnippet: res.output,
            details: `Key: ${res.key}, Modular Inverse: ${res.inverse}`
          });
          Toast.success('Encrypted', `Multiplicative Cipher completed with key ${res.key}.`);
        } catch (err) {
          Toast.error('Operation Failed', err.message);
        }
      });
    }

    // Decrypt
    if (btnDecrypt) {
      btnDecrypt.addEventListener('click', () => {
        try {
          const text = inputEl.value;
          const key = keyInput ? keyInput.value : 5;
          const res = this.decrypt(text, key);
          outputEl.textContent = res.output;
          this.renderSteps(res.steps, stepsTableBody);

          HistoryManager.addEntry({
            algorithm: 'Multiplicative Cipher',
            operation: 'Decryption',
            inputSnippet: text,
            outputSnippet: res.output,
            details: `Key: ${res.key}, Modular Inverse: ${res.inverse}`
          });
          Toast.success('Decrypted', `Multiplicative Cipher decrypted using inverse key ${res.inverse}.`);
        } catch (err) {
          Toast.error('Operation Failed', err.message);
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
        if (stepsTableBody) stepsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Run encryption or decryption to view calculation steps.</td></tr>';
        Toast.info('Cleared', 'Multiplicative cipher fields reset.');
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
        Toast.info('Swapped', 'Output transferred to input.');
      });
    }

    // Example
    if (btnExample) {
      btnExample.addEventListener('click', () => {
        inputEl.value = 'HELLO';
        if (keyInput) keyInput.value = '5';
        updateStatusUI();
        Toast.info('Example Loaded', 'Loaded test vector: HELLO with key 5 (inverse = 21).');
      });
    }
  },

  renderSteps(steps, container) {
    if (!container) return;
    if (!steps || steps.length === 0) {
      container.innerHTML = '<tr><td colspan="5" class="empty-state">No steps to display.</td></tr>';
      return;
    }

    container.innerHTML = steps.map((s, idx) => `
      <tr>
        <td><strong>#${idx + 1}</strong></td>
        <td><code>${s.char === ' ' ? '[space]' : s.char}</code> (${s.type})</td>
        <td>${s.origVal}</td>
        <td><span class="font-mono text-secondary">${s.formula}</span></td>
        <td><strong><code>${s.result === ' ' ? '[space]' : s.result}</code></strong></td>
      </tr>
    `).join('');
  }
};

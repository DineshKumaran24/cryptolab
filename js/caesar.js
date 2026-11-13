/**
 * CryptoLab - Caesar Cipher Engine
 * Handles shift validation, uppercase/lowercase transformation,
 * character preservation, step-by-step trace generation, and UI bindings.
 */

const CaesarCipher = {
  // Math core
  normalizeShift(shift) {
    const s = parseInt(shift, 10);
    if (isNaN(s)) return 0;
    return ((s % 26) + 26) % 26;
  },

  process(text, shift, isEncrypt = true) {
    if (!text) {
      throw new Error('Please enter text to process.');
    }

    const rawShift = parseInt(shift, 10);
    if (isNaN(rawShift)) {
      throw new Error('Invalid shift key. Please enter a valid integer.');
    }

    const effectiveShift = isEncrypt 
      ? this.normalizeShift(rawShift)
      : this.normalizeShift(-rawShift);

    const steps = [];
    let output = '';

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const code = char.charCodeAt(0);
      let transformed = char;
      let stepInfo = null;

      if (code >= 65 && code <= 90) {
        // Uppercase A-Z
        const p = code - 65;
        const c = (p + effectiveShift) % 26;
        transformed = String.fromCharCode(c + 65);
        stepInfo = {
          char,
          type: 'Upper',
          origVal: p,
          formula: isEncrypt ? `(${p} + ${effectiveShift}) mod 26` : `(${p} - ${this.normalizeShift(rawShift)}) mod 26`,
          newVal: c,
          result: transformed
        };
      } else if (code >= 97 && code <= 122) {
        // Lowercase a-z
        const p = code - 97;
        const c = (p + effectiveShift) % 26;
        transformed = String.fromCharCode(c + 97);
        stepInfo = {
          char,
          type: 'Lower',
          origVal: p,
          formula: isEncrypt ? `(${p} + ${effectiveShift}) mod 26` : `(${p} - ${this.normalizeShift(rawShift)}) mod 26`,
          newVal: c,
          result: transformed
        };
      } else {
        // Non-alphabetic character preserved
        stepInfo = {
          char,
          type: 'Symbol/Space',
          origVal: '—',
          formula: 'Preserved as-is',
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
      rawShift,
      effectiveShift,
      totalChars: text.length,
      steps
    };
  },

  encrypt(text, shift) {
    return this.process(text, shift, true);
  },

  decrypt(text, shift) {
    return this.process(text, shift, false);
  },

  // UI Controller Binding
  initUI() {
    const inputEl = document.getElementById('caesar-input');
    const shiftInput = document.getElementById('caesar-shift');
    const shiftSlider = document.getElementById('caesar-slider');
    const shiftBadge = document.getElementById('caesar-shift-badge');
    const outputEl = document.getElementById('caesar-output');
    const btnEncrypt = document.getElementById('caesar-encrypt-btn');
    const btnDecrypt = document.getElementById('caesar-decrypt-btn');
    const btnCopy = document.getElementById('caesar-copy-btn');
    const btnClear = document.getElementById('caesar-clear-btn');
    const btnSwap = document.getElementById('caesar-swap-btn');
    const btnExample = document.getElementById('caesar-example-btn');
    const stepsTableBody = document.getElementById('caesar-steps-body');
    const charCountEl = document.getElementById('caesar-char-count');
    const mappingPreview = document.getElementById('caesar-mapping-preview');

    if (!inputEl || !outputEl) return;

    // Synchronize shift input and slider
    const updateShiftUI = (val) => {
      const num = parseInt(val, 10) || 0;
      const normalized = this.normalizeShift(num);
      if (shiftBadge) shiftBadge.textContent = `k = ${num} (mod 26: ${normalized})`;
      this.renderMappingPreview(normalized, mappingPreview);
    };

    if (shiftInput && shiftSlider) {
      shiftInput.addEventListener('input', () => {
        shiftSlider.value = this.normalizeShift(shiftInput.value);
        updateShiftUI(shiftInput.value);
      });

      shiftSlider.addEventListener('input', () => {
        shiftInput.value = shiftSlider.value;
        updateShiftUI(shiftSlider.value);
      });
    }

    if (inputEl && charCountEl) {
      inputEl.addEventListener('input', () => {
        charCountEl.textContent = `${inputEl.value.length} characters`;
      });
    }

    // Encrypt Action
    if (btnEncrypt) {
      btnEncrypt.addEventListener('click', () => {
        try {
          const text = inputEl.value;
          const shift = shiftInput ? shiftInput.value : 3;
          const res = this.encrypt(text, shift);
          outputEl.textContent = res.output;
          this.renderSteps(res.steps, stepsTableBody);

          HistoryManager.addEntry({
            algorithm: 'Caesar Cipher',
            operation: 'Encryption',
            inputSnippet: text,
            outputSnippet: res.output,
            details: `Shift: ${res.rawShift} (Effective: ${res.effectiveShift})`
          });
          Toast.success('Encrypted', `Caesar Cipher completed with shift ${res.rawShift}.`);
        } catch (err) {
          Toast.error('Operation Failed', err.message);
        }
      });
    }

    // Decrypt Action
    if (btnDecrypt) {
      btnDecrypt.addEventListener('click', () => {
        try {
          const text = inputEl.value;
          const shift = shiftInput ? shiftInput.value : 3;
          const res = this.decrypt(text, shift);
          outputEl.textContent = res.output;
          this.renderSteps(res.steps, stepsTableBody);

          HistoryManager.addEntry({
            algorithm: 'Caesar Cipher',
            operation: 'Decryption',
            inputSnippet: text,
            outputSnippet: res.output,
            details: `Shift: ${res.rawShift} (Effective: -${res.effectiveShift})`
          });
          Toast.success('Decrypted', `Caesar Cipher decrypted with shift ${res.rawShift}.`);
        } catch (err) {
          Toast.error('Operation Failed', err.message);
        }
      });
    }

    // Copy Action
    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        Clipboard.copy(outputEl.textContent, btnCopy);
      });
    }

    // Clear Action
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        inputEl.value = '';
        outputEl.textContent = '';
        if (stepsTableBody) stepsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Run encryption or decryption to view calculation steps.</td></tr>';
        if (charCountEl) charCountEl.textContent = '0 characters';
        Toast.info('Cleared', 'Caesar cipher fields reset.');
      });
    }

    // Swap Input/Output Action
    if (btnSwap) {
      btnSwap.addEventListener('click', () => {
        const out = outputEl.textContent;
        if (!out) {
          Toast.warning('Cannot Swap', 'Output field is currently empty.');
          return;
        }
        inputEl.value = out;
        outputEl.textContent = '';
        if (charCountEl) charCountEl.textContent = `${out.length} characters`;
        Toast.info('Swapped', 'Output transferred to input.');
      });
    }

    // Example Action
    if (btnExample) {
      btnExample.addEventListener('click', () => {
        inputEl.value = 'HELLO, CRYPTOLAB!';
        if (shiftInput) shiftInput.value = '3';
        if (shiftSlider) shiftSlider.value = '3';
        updateShiftUI(3);
        if (charCountEl) charCountEl.textContent = `${inputEl.value.length} characters`;
        Toast.info('Example Loaded', 'Loaded test vector: HELLO with shift 3.');
      });
    }

    // Initial mapping preview
    updateShiftUI(shiftInput ? shiftInput.value : 3);
  },

  renderMappingPreview(shift, container) {
    if (!container) return;
    const samples = ['A', 'B', 'C', 'D', 'E', '...', 'X', 'Y', 'Z'];
    let html = '';
    for (const ch of samples) {
      if (ch === '...') {
        html += '<span style="padding: 0 4px; color: var(--text-light);">&bull;&bull;&bull;</span>';
      } else {
        const p = ch.charCodeAt(0) - 65;
        const c = (p + shift) % 26;
        const shifted = String.fromCharCode(c + 65);
        html += `
          <div class="char-pair">
            <span class="char-plain">${ch}</span>
            <span class="char-arrow">&darr;</span>
            <span class="char-cipher">${shifted}</span>
          </div>
        `;
      }
    }
    container.innerHTML = html;
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

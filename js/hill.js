/**
 * CryptoLab - Hill Cipher Engine
 * Implements 2x2 and 3x3 polygraphic substitution ciphers,
 * modular matrix multiplication, determinant computation,
 * modular matrix inversion mod 26, vector padding, and interactive UI.
 */

const HillCipher = {
  currentSize: 2, // 2 or 3

  mod(n, m = 26) {
    return ((n % m) + m) % m;
  },

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
    a = this.mod(a, m);
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return null;
  },

  // 2x2 Matrix Math
  det2x2(m) {
    return this.mod(m[0][0] * m[1][1] - m[0][1] * m[1][0], 26);
  },

  inv2x2(m) {
    const det = this.det2x2(m);
    const detInv = this.modInverse(det, 26);
    if (!detInv) return null;

    // Adjugate for [[a, b], [c, d]] is [[d, -b], [-c, a]]
    return [
      [this.mod(m[1][1] * detInv, 26), this.mod(-m[0][1] * detInv, 26)],
      [this.mod(-m[1][0] * detInv, 26), this.mod(m[0][0] * detInv, 26)]
    ];
  },

  // 3x3 Matrix Math
  det3x3(m) {
    const a = m[0][0], b = m[0][1], c = m[0][2];
    const d = m[1][0], e = m[1][1], f = m[1][2];
    const g = m[2][0], h = m[2][1], i = m[2][2];
    return this.mod(a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g), 26);
  },

  inv3x3(m) {
    const det = this.det3x3(m);
    const detInv = this.modInverse(det, 26);
    if (!detInv) return null;

    const a = m[0][0], b = m[0][1], c = m[0][2];
    const e = m[1][0], f = m[1][1], g = m[1][2];
    const h = m[2][0], i = m[2][1], j = m[2][2];

    const c00 = this.mod(f * j - g * i, 26);
    const c01 = this.mod(-(e * j - g * h), 26);
    const c02 = this.mod(e * i - f * h, 26);

    const c10 = this.mod(-(b * j - c * i), 26);
    const c11 = this.mod(a * j - c * h, 26);
    const c12 = this.mod(-(a * i - b * h), 26);

    const c20 = this.mod(b * g - c * f, 26);
    const c21 = this.mod(-(a * g - c * e), 26);
    const c22 = this.mod(a * f - b * e, 26);

    // Transpose of cofactor matrix (adjugate) multiplied by detInv
    return [
      [this.mod(c00 * detInv, 26), this.mod(c10 * detInv, 26), this.mod(c20 * detInv, 26)],
      [this.mod(c01 * detInv, 26), this.mod(c11 * detInv, 26), this.mod(c21 * detInv, 26)],
      [this.mod(c02 * detInv, 26), this.mod(c12 * detInv, 26), this.mod(c22 * detInv, 26)]
    ];
  },

  validateMatrix(matrix, size) {
    const det = size === 2 ? this.det2x2(matrix) : this.det3x3(matrix);
    const g = this.gcd(det, 26);
    const invertible = g === 1;
    const detInv = invertible ? this.modInverse(det, 26) : null;
    const invMatrix = invertible ? (size === 2 ? this.inv2x2(matrix) : this.inv3x3(matrix)) : null;

    return {
      size,
      det,
      gcd: g,
      invertible,
      detInv,
      invMatrix,
      message: invertible
        ? `Valid Invertible Key: det = ${det}, det⁻¹ = ${detInv} (gcd(${det}, 26) = 1). Decryption is mathematically supported.`
        : `Invalid Matrix: det = ${det} is NOT coprime with 26 (gcd = ${g}). Matrix cannot be inverted modulo 26!`
    };
  },

  cleanText(text) {
    return text.toUpperCase().replace(/[^A-Z]/g, '');
  },

  encrypt(text, matrix, size) {
    const clean = this.cleanText(text);
    if (!clean) throw new Error('Please enter text containing alphabetic characters.');

    const val = this.validateMatrix(matrix, size);
    if (!val.invertible) throw new Error(val.message);

    // Padding check
    let padded = clean;
    const padCount = (size - (padded.length % size)) % size;
    for (let p = 0; p < padCount; p++) {
      padded += 'X';
    }

    const steps = [];
    let ciphertext = '';

    for (let i = 0; i < padded.length; i += size) {
      const vec = [];
      const charBlock = [];
      for (let k = 0; k < size; k++) {
        const ch = padded[i + k];
        charBlock.push(ch);
        vec.push(ch.charCodeAt(0) - 65);
      }

      const outVec = [];
      const stepFormulas = [];

      for (let r = 0; r < size; r++) {
        let sum = 0;
        const terms = [];
        for (let c = 0; c < size; c++) {
          sum += matrix[r][c] * vec[c];
          terms.push(`(${matrix[r][c]} × ${vec[c]})`);
        }
        const modVal = this.mod(sum, 26);
        outVec.push(modVal);
        const outChar = String.fromCharCode(modVal + 65);
        ciphertext += outChar;
        stepFormulas.push(`${terms.join(' + ')} = ${sum} ≡ ${modVal} ('${outChar}')`);
      }

      if (steps.length < 15) {
        steps.push({
          block: charBlock.join(''),
          vec: `[${vec.join(', ')}]ᵀ`,
          formulas: stepFormulas,
          outBlock: outVec.map(v => String.fromCharCode(v + 65)).join('')
        });
      }
    }

    return {
      ciphertext,
      cleanText: clean,
      paddedText: padded,
      padCount,
      matrix,
      val,
      steps
    };
  },

  decrypt(ciphertext, matrix, size) {
    const clean = this.cleanText(ciphertext);
    if (!clean) throw new Error('Please enter ciphertext containing alphabetic characters.');
    if (clean.length % size !== 0) {
      throw new Error(`Ciphertext length (${clean.length}) must be a multiple of matrix size ${size}.`);
    }

    const val = this.validateMatrix(matrix, size);
    if (!val.invertible || !val.invMatrix) throw new Error(val.message);

    const inv = val.invMatrix;
    const steps = [];
    let plaintext = '';

    for (let i = 0; i < clean.length; i += size) {
      const vec = [];
      const charBlock = [];
      for (let k = 0; k < size; k++) {
        const ch = clean[i + k];
        charBlock.push(ch);
        vec.push(ch.charCodeAt(0) - 65);
      }

      const outVec = [];
      const stepFormulas = [];

      for (let r = 0; r < size; r++) {
        let sum = 0;
        const terms = [];
        for (let c = 0; c < size; c++) {
          sum += inv[r][c] * vec[c];
          terms.push(`(${inv[r][c]} × ${vec[c]})`);
        }
        const modVal = this.mod(sum, 26);
        outVec.push(modVal);
        const outChar = String.fromCharCode(modVal + 65);
        plaintext += outChar;
        stepFormulas.push(`${terms.join(' + ')} = ${sum} ≡ ${modVal} ('${outChar}')`);
      }

      if (steps.length < 15) {
        steps.push({
          block: charBlock.join(''),
          vec: `[${vec.join(', ')}]ᵀ`,
          formulas: stepFormulas,
          outBlock: outVec.map(v => String.fromCharCode(v + 65)).join('')
        });
      }
    }

    return {
      plaintext,
      ciphertext: clean,
      matrix,
      invMatrix: inv,
      val,
      steps
    };
  },

  // UI Controller Binding
  initUI() {
    const inputEl = document.getElementById('hill-input');
    const outputEl = document.getElementById('hill-output');
    const size2Btn = document.getElementById('hill-size-2');
    const size3Btn = document.getElementById('hill-size-3');
    const gridContainer = document.getElementById('hill-matrix-grid');
    const statusBanner = document.getElementById('hill-status-banner');
    const invMatrixContainer = document.getElementById('hill-inv-matrix-preview');
    const btnEncrypt = document.getElementById('hill-encrypt-btn');
    const btnDecrypt = document.getElementById('hill-decrypt-btn');
    const btnCopy = document.getElementById('hill-copy-btn');
    const btnClear = document.getElementById('hill-clear-btn');
    const btnSwap = document.getElementById('hill-swap-btn');
    const btnExample = document.getElementById('hill-example-btn');
    const stepsTableBody = document.getElementById('hill-steps-body');

    if (!inputEl || !outputEl) return;

    // Preset matrices
    const preset2x2 = [[3, 3], [2, 5]];
    const preset3x3 = [[2, 4, 5], [9, 2, 11], [3, 17, 7]];

    const renderGrid = (size, values = null) => {
      this.currentSize = size;
      if (!gridContainer) return;
      gridContainer.className = `matrix-grid grid-${size}x${size}`;
      
      const defaultVals = values || (size === 2 ? preset2x2 : preset3x3);
      let cellsHtml = '';
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const val = defaultVals[r] && defaultVals[r][c] !== undefined ? defaultVals[r][c] : 1;
          cellsHtml += `<input type="number" class="matrix-cell-input" data-row="${r}" data-col="${c}" value="${val}" min="0" max="100">`;
        }
      }
      gridContainer.innerHTML = cellsHtml;

      gridContainer.querySelectorAll('.matrix-cell-input').forEach(input => {
        input.addEventListener('input', updateDiagnostics);
      });

      updateDiagnostics();
    };

    const getMatrixFromGrid = () => {
      const size = this.currentSize;
      const matrix = Array.from({ length: size }, () => Array(size).fill(0));
      gridContainer.querySelectorAll('.matrix-cell-input').forEach(input => {
        const r = parseInt(input.getAttribute('data-row'), 10);
        const c = parseInt(input.getAttribute('data-col'), 10);
        matrix[r][c] = parseInt(input.value, 10) || 0;
      });
      return matrix;
    };

    const updateDiagnostics = () => {
      const matrix = getMatrixFromGrid();
      const val = this.validateMatrix(matrix, this.currentSize);

      if (statusBanner) {
        if (val.invertible) {
          statusBanner.className = 'coprime-status-banner coprime-valid';
          statusBanner.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <div><strong>Invertible Matrix (Valid):</strong> det(K) = ${val.det} mod 26, det⁻¹ = ${val.detInv}. Decryption is possible!</div>
          `;
        } else {
          statusBanner.className = 'coprime-status-banner coprime-invalid';
          statusBanner.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <div><strong>Non-Invertible Matrix (Invalid):</strong> det(K) = ${val.det} mod 26 (gcd(${val.det}, 26) = ${val.gcd} ≠ 1). This matrix cannot be inverted!</div>
          `;
        }
      }

      if (invMatrixContainer) {
        if (val.invertible && val.invMatrix) {
          const formatted = val.invMatrix.map(row => `[ ${row.join(', ')} ]`).join('\n');
          invMatrixContainer.textContent = formatted;
        } else {
          invMatrixContainer.textContent = 'Inverse matrix does not exist (det not coprime with 26)';
        }
      }
    };

    // Size Switchers
    if (size2Btn && size3Btn) {
      size2Btn.addEventListener('click', () => {
        size2Btn.classList.add('active');
        size3Btn.classList.remove('active');
        renderGrid(2, preset2x2);
      });

      size3Btn.addEventListener('click', () => {
        size3Btn.classList.add('active');
        size2Btn.classList.remove('active');
        renderGrid(3, preset3x3);
      });
    }

    // Encrypt
    if (btnEncrypt) {
      btnEncrypt.addEventListener('click', () => {
        try {
          const text = inputEl.value;
          const matrix = getMatrixFromGrid();
          const res = this.encrypt(text, matrix, this.currentSize);
          outputEl.textContent = res.ciphertext;
          this.renderSteps(res.steps, stepsTableBody, res.padCount);

          let detailMsg = `Size: ${this.currentSize}x${this.currentSize}, Det: ${res.val.det}`;
          if (res.padCount > 0) {
            detailMsg += ` (Padded with ${res.padCount} 'X' character${res.padCount > 1 ? 's' : ''})`;
          }

          HistoryManager.addEntry({
            algorithm: 'Hill Cipher',
            operation: 'Encryption',
            inputSnippet: text,
            outputSnippet: res.ciphertext,
            details: detailMsg
          });
          Toast.success('Encrypted', `Hill Cipher encryption complete.${res.padCount > 0 ? ` Padded with ${res.padCount} 'X'.` : ''}`);
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
          const matrix = getMatrixFromGrid();
          const res = this.decrypt(text, matrix, this.currentSize);
          outputEl.textContent = res.plaintext;
          this.renderSteps(res.steps, stepsTableBody, 0);

          HistoryManager.addEntry({
            algorithm: 'Hill Cipher',
            operation: 'Decryption',
            inputSnippet: text,
            outputSnippet: res.plaintext,
            details: `Size: ${this.currentSize}x${this.currentSize}, InvDet: ${res.val.detInv}`
          });
          Toast.success('Decrypted', 'Hill Cipher decryption complete.');
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
        if (stepsTableBody) stepsTableBody.innerHTML = '<tr><td colspan="4" class="empty-state">Run encryption or decryption to view matrix calculation steps.</td></tr>';
        Toast.info('Cleared', 'Hill cipher fields reset.');
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
        if (this.currentSize === 2) {
          inputEl.value = 'HELP';
          renderGrid(2, preset2x2);
          Toast.info('Example Loaded', 'Loaded 2x2 test vector: HELP with key [[3, 3], [2, 5]].');
        } else {
          inputEl.value = 'ATTACKATDAWN';
          renderGrid(3, preset3x3);
          Toast.info('Example Loaded', 'Loaded 3x3 test vector: ATTACKATDAWN with key [[2, 4, 5], [9, 2, 11], [3, 17, 7]].');
        }
      });
    }

    // Initial render
    renderGrid(2, preset2x2);
  },

  renderSteps(steps, container, padCount = 0) {
    if (!container) return;
    if (!steps || steps.length === 0) {
      container.innerHTML = '<tr><td colspan="4" class="empty-state">No steps to display.</td></tr>';
      return;
    }

    let padNotice = '';
    if (padCount > 0) {
      padNotice = `<tr><td colspan="4" style="background:#FFFBEB; color:#B45309; padding: 8px 12px; font-weight:600;">
        ⚠️ Padding Notice: Added ${padCount} 'X' character${padCount > 1 ? 's' : ''} to complete vector block size.
      </td></tr>`;
    }

    container.innerHTML = padNotice + steps.map((s, idx) => `
      <tr>
        <td><strong>Block #${idx + 1}</strong></td>
        <td><code>${s.block}</code> &rarr; <code>${s.vec}</code></td>
        <td>
          <div style="font-family: var(--font-mono); font-size: 0.775rem; line-height: 1.4;">
            ${s.formulas.join('<br>')}
          </div>
        </td>
        <td><strong><code>${s.outBlock}</code></strong></td>
      </tr>
    `).join('');
  }
};

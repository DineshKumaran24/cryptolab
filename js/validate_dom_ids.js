import fs from 'node:fs';

console.log("=== CHECKING HTML & SCRIPT ID CONSISTENCY ===");

const classicalHtml = fs.readFileSync('classical.html', 'utf8');
const modernHtml = fs.readFileSync('modern.html', 'utf8');
const historyHtml = fs.readFileSync('history.html', 'utf8');
const dashboardHtml = fs.readFileSync('dashboard.html', 'utf8');

function checkIds(filename, htmlContent, requiredIds) {
  console.log(`\nChecking ${filename}...`);
  let missing = 0;
  for (const id of requiredIds) {
    if (htmlContent.includes(`id="${id}"`)) {
      console.log(`  ✓ Found id="${id}"`);
    } else {
      console.error(`  ✗ MISSING id="${id}" in ${filename}`);
      missing++;
    }
  }
  return missing;
}

const classicalIds = [
  // Caesar
  'caesar-input', 'caesar-shift', 'caesar-slider', 'caesar-shift-badge',
  'caesar-output', 'caesar-encrypt-btn', 'caesar-decrypt-btn', 'caesar-copy-btn',
  'caesar-clear-btn', 'caesar-swap-btn', 'caesar-example-btn', 'caesar-steps-body',
  'caesar-char-count', 'caesar-mapping-preview',
  // Multiplicative
  'mult-input', 'mult-key', 'mult-status-banner', 'mult-quick-picks',
  'mult-output', 'mult-encrypt-btn', 'mult-decrypt-btn', 'mult-copy-btn',
  'mult-clear-btn', 'mult-swap-btn', 'mult-example-btn', 'mult-steps-body',
  // Hill
  'hill-input', 'hill-output', 'hill-size-2', 'hill-size-3',
  'hill-matrix-grid', 'hill-status-banner', 'hill-inv-matrix-preview',
  'hill-encrypt-btn', 'hill-decrypt-btn', 'hill-copy-btn', 'hill-clear-btn',
  'hill-swap-btn', 'hill-example-btn', 'hill-steps-body'
];

const modernIds = [
  // AES
  'aes-input', 'aes-key', 'aes-size-128', 'aes-size-256',
  'aes-gen-key-btn', 'aes-output', 'aes-iv-display', 'aes-encrypt-btn',
  'aes-decrypt-btn', 'aes-copy-btn', 'aes-clear-btn', 'aes-swap-btn', 'aes-example-btn',
  // RSA
  'rsa-gen-keys-btn', 'rsa-public-key', 'rsa-private-key', 'rsa-copy-pub-btn',
  'rsa-copy-priv-btn', 'rsa-input', 'rsa-byte-counter', 'rsa-output',
  'rsa-encrypt-btn', 'rsa-decrypt-btn', 'rsa-copy-output-btn', 'rsa-clear-btn',
  'rsa-swap-btn', 'rsa-example-btn',
  // SHA-256
  'sha-input', 'sha-output', 'sha-bit-len', 'sha-byte-len',
  'sha-hash-btn', 'sha-copy-btn', 'sha-clear-btn', 'sha-example-btn',
  'av-input-a', 'av-input-b', 'av-hash-a', 'av-hash-b', 'av-metric',
  // HMAC
  'hmac-gen-msg', 'hmac-gen-key', 'hmac-gen-output', 'hmac-generate-btn',
  'hmac-gen-copy-btn', 'hmac-gen-clear-btn', 'hmac-gen-example-btn',
  'hmac-ver-msg', 'hmac-ver-key', 'hmac-ver-tag', 'hmac-verify-btn',
  'hmac-ver-status', 'hmac-ver-example-btn'
];

const historyIds = [
  'history-table-body', 'history-count-badge', 'history-filter-algo',
  'history-filter-op', 'history-search', 'history-clear-all-btn',
  'history-export-csv-btn'
];

const dashIds = [
  'dash-total-ops', 'dash-top-algo', 'sidebar-history-count',
  'dash-activity-table-body', 'dash-clear-history-btn'
];

let totalMissing = 0;
totalMissing += checkIds('classical.html', classicalHtml, classicalIds);
totalMissing += checkIds('modern.html', modernHtml, modernIds);
totalMissing += checkIds('history.html', historyHtml, historyIds);
totalMissing += checkIds('dashboard.html', dashboardHtml, dashIds);

console.log(`\nTotal Missing IDs: ${totalMissing}`);
if (totalMissing > 0) process.exit(1);

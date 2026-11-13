# CryptoLab – Interactive Cryptography Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cryptographic Engines](https://img.shields.io/badge/Algorithms-7%20Fully%20Functional-18A999.svg)](#algorithms-implemented)
[![Web Crypto API](https://img.shields.io/badge/Web%20Crypto-Native%20Hardware%20Accelerated-3978C5.svg)](#technology-stack)
[![Theme](https://img.shields.io/badge/UI%20Theme-Innovative%20Light%20Design-183B56.svg)](#design-system)

**CryptoLab** is an academic, fully functional, responsive web application for exploring the science of cryptography. Designed for information security education, research, and technical demonstrations, CryptoLab allows users to execute real encryption, decryption, hashing, and message authentication across both historical classical ciphers and modern international standards.

Every algorithm is implemented natively in client-side JavaScript and the W3C Web Crypto API. There are zero mock functions, zero server-side vulnerabilities, and zero data leakage.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Design System & UI/UX](#design-system--uiux)
3. [Application Architecture](#application-architecture)
4. [Algorithms Implemented](#algorithms-implemented)
   - [Classical Ciphers](#1-classical-cipher-toolkit)
   - [Modern Cryptography](#2-modern-cryptography-toolkit)
5. [Testing & Quality Assurance Report](#testing--quality-assurance-report)
6. [Local Development & Setup](#local-development--setup)
7. [GitHub Pages / Netlify Deployment Guide](#github-pages--netlify-deployment-guide)
8. [Security & Privacy Guarantees](#security--privacy-guarantees)
9. [Academic Project Information](#academic-project-information)

---

## Key Features

- **7 Working Cryptographic Engines:** Caesar, Multiplicative, Hill (2x2 and 3x3), AES-GCM (128/256-bit), RSA-OAEP (2048-bit), SHA-256, and HMAC-SHA-256.
- **Mathematical Transparency:** Step-by-step breakdown tables and intermediate calculations for every operation (modular rings, dot products, invertibility proofs).
- **Interactive Matrix Editor:** Visual 2x2 and 3x3 Hill Cipher grid with live determinant calculation ($\det(K) \pmod{26}$), coprime invertibility badges, and inverse matrix preview.
- **Hardware-Accelerated Web Crypto API:** Real browser-native `crypto.subtle` operations for authenticated symmetric encryption and asymmetric key generation.
- **Dedicated Key Management:** Random key generation for AES, exportable SPKI/PKCS#8 PEM format viewers for RSA, and fresh cryptographically secure 96-bit IVs for every AES-GCM operation.
- **Avalanche Effect Visualizer:** Interactive bit-divergence analyzer demonstrating how single-character alterations propagate across SHA-256 digests.
- **HMAC Verification Suite:** Constant-time authentication verifier indicating whether messages and MAC tags match.
- **Local Operation History:** Client-side tracking using `localStorage` with keyword search, multi-factor filtering, individual deletion, and full CSV export.
- **Zero-Server Architecture:** 100% static hosting compatibility on GitHub Pages, Netlify, or Vercel. Sensitive keys and plaintexts never leave the user's browser.

---

## Design System & UI/UX

CryptoLab rejects stereotypical dark "hacker terminal" aesthetics in favor of a clean light theme inspired by SaaS dashboards, Apple software guidelines, and fintech platforms.

### Color Tokens
| Token | Hex Value | Purpose |
| :--- | :--- | :--- |
| **Primary** | `#183B56` | Deep Navy Blue – Brand typography, primary CTAs, active headers |
| **Secondary** | `#3978C5` | Vibrant Blue – Highlights, links, secondary action buttons |
| **Background** | `#F7F9FC` | Soft Off-White – Low-contrast page canvas reducing eye strain |
| **Cards** | `#FFFFFF` | Pure White – Elevated content containers with subtle shadows |
| **Accent** | `#18A999` | Teal – Success indicators, copy feedback, cryptographic status |
| **Text Main** | `#202B38` | Dark Charcoal – High-readability body copy |
| **Muted Text** | `#718096` | Slate Gray – Meta descriptions, labels, hints |
| **Borders** | `#E4EAF1` | Crisp light borders defining visual hierarchy |

---

## Application Architecture

```
cryptolab/
│
├── index.html            # Landing page with hero, statistics, overview & diagrams
├── dashboard.html        # Central metrics dashboard, quick-access cards & live history
├── classical.html        # Classical ciphers workspace (Caesar, Multiplicative, Hill)
├── modern.html           # Modern cryptography suite (AES, RSA, SHA-256, HMAC)
├── learning.html         # Educational compendium with formulas, proofs & comparisons
├── history.html          # Operations log with search, filters & CSV export
├── about.html            # Project objectives, specs, and cybersecurity context
│
├── css/
│   ├── style.css         # Design tokens, reset, typography, header, sidebar & toasts
│   ├── dashboard.css     # Metric counters, statistics grid & activity cards
│   ├── algorithms.css    # Side-by-side workspaces, matrix editor, key panels
│   └── responsive.css    # Mobile navigation drawer, fluid grids, and touch targets
│
├── js/
│   ├── app.js            # Toast notifications, Clipboard helper & HistoryManager
│   ├── navigation.js     # Active navigation state and tab manager
│   ├── caesar.js         # Caesar cipher engine and step trace generator
│   ├── multiplicative.js # Multiplicative cipher engine with coprime verification
│   ├── hill.js           # Hill cipher (2x2 and 3x3) matrix math & inversion mod 26
│   ├── aes.js            # AES-GCM (128/256-bit) authenticated encryption with fresh IVs
│   ├── rsa.js            # RSA-OAEP 2048-bit key pair generation, PEM export, & crypto
│   ├── sha256.js         # SHA-256 digest engine and Avalanche Effect comparator
│   ├── hmac.js           # HMAC-SHA-256 generation and verification suite
│   ├── history.js        # History page controller with search, filter, & CSV export
│   └── comprehensive_test.js # Automated test runner for CI and validation
│
└── README.md             # Project documentation and deployment guide
```

---

## Algorithms Implemented

### 1. Classical Cipher Toolkit

#### A. Caesar Cipher
- **Mechanism:** Additive monoalphabetic substitution modulo 26.
- **Formula:** $C_i = (P_i + k) \pmod{26}$, $P_i = (C_i - k + 26) \pmod{26}$.
- **Features:** Supports uppercase and lowercase letters, preserves spaces/punctuation, handles negative and arbitrarily large shifts ($k \pmod{26}$).
- **Step Trace:** Displays each character's alphabetical index transformation.

#### B. Multiplicative Cipher
- **Mechanism:** Modular multiplication on alphabet positions.
- **Formula:** $C_i = (P_i \times k) \pmod{26}$, $P_i = (C_i \times k^{-1}) \pmod{26}$.
- **Validation:** Verifies coprimality $\gcd(k, 26) = 1$. Displays informative errors if an invalid key (e.g., even numbers, 13) is selected.
- **Modular Inverse:** Derives $k^{-1}$ such that $(k \times k^{-1}) \equiv 1 \pmod{26}$ using the Extended Euclidean Algorithm.
- **Quick-Picks:** Instant buttons for all 12 valid coprime keys: `{1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}`.

#### C. Hill Cipher (2x2 and 3x3)
- **Mechanism:** Polygraphic block substitution using linear algebra modulo 26.
- **Formula:** $\mathbf{C} = (K \cdot \mathbf{P}) \pmod{26}$, $\mathbf{P} = (K^{-1} \cdot \mathbf{C}) \pmod{26}$.
- **Inversion:** Computes modular determinant $\det(K) \pmod{26}$, checks $\gcd(\det(K), 26) = 1$, calculates adjugate matrix $\operatorname{adj}(K)$, and derives $K^{-1} = (\det(K)^{-1} \times \operatorname{adj}(K)) \pmod{26}$.
- **Vector Padding:** Automatic padding with `'X'` to ensure message length is a multiple of block size $N$, with clear explanations.
- **Interactive Matrix Editor:** Allows dynamic cell editing, live invertibility diagnostics, and preset invertible matrices.

---

### 2. Modern Cryptography Toolkit

#### A. AES-GCM (Authenticated Encryption)
- **Standard:** NIST FIPS 197 / SP 800-38D.
- **Key Sizes:** 128-bit (16 bytes) and 256-bit (32 bytes).
- **IV Management:** Generates a fresh, cryptographically secure 96-bit (12-byte) random IV for every encryption call using `crypto.getRandomValues`. Never reuses an IV.
- **Packaging:** Formats output as Base64 `IV:Ciphertext+Tag` or structured JSON.
- **Authentication:** Incorporates a 128-bit GMAC authentication tag. Any ciphertext tampering causes an immediate rejection during decryption.

#### B. RSA-OAEP (Asymmetric Cryptography)
- **Standard:** PKCS#1 v2.2 / RFC 8017.
- **Modulus:** 2048-bit modulus with public exponent $e = 65537$.
- **Padding:** Optimal Asymmetric Encryption Padding (OAEP) with SHA-256 hash.
- **Key Export:** Exports standard X.509 SPKI (Public Key) and PKCS#8 (Private Key) wrapped in standard PEM headers.
- **Safety Boundary:** Implements a byte counter and enforces the maximum 190-byte plaintext limit of 2048-bit RSA-OAEP with SHA-256.

#### C. SHA-256 Cryptographic Hash
- **Standard:** NIST FIPS 180-4.
- **Digest:** Deterministic 256-bit (32-byte, 64-hex character) one-way hash.
- **Avalanche Comparator:** Compares two inputs side by side, calculating the exact Hamming distance and percentage of flipped bits.

#### D. HMAC-SHA-256
- **Standard:** RFC 2104 / RFC 4231.
- **Operation:** Keyed-hash message authentication code for data integrity and authenticity.
- **Verifier:** Dedicated verification engine comparing messages and tags using constant-time Web Crypto API validation.

---

## Testing & Quality Assurance Report

An automated test suite was executed across all cryptographic engines using standard test vectors:

```
==================================================
CRYPTOLAB AUTOMATED TEST & QUALITY ASSURANCE SUITE
==================================================

--- 1. Testing Caesar Cipher ---
  ✓ PASS: HELLO with shift 3 -> KHOOR (Expected: KHOOR)
  ✓ PASS: Decrypted KHOOR with shift 3 -> HELLO (Expected: HELLO)
  ✓ PASS: Case & Punctuation Preserved: Khoor, Zruog! 123
  ✓ PASS: Large shift 55 (mod 26 = 3) -> KHOOR
  ✓ PASS: Negative shift -3 on KHOOR -> HELLO

--- 2. Testing Multiplicative Cipher ---
  ✓ PASS: Key 5 is coprime with 26
  ✓ PASS: Modular inverse of 5 mod 26 is 21 (5 * 21 = 105 = 4*26 + 1)
  ✓ PASS: Key 4 correctly identified as non-coprime (gcd = 2)
  ✓ PASS: Key 13 correctly identified as non-coprime (gcd = 13)
  ✓ PASS: Multiplicative HELLO * 5 -> JUDDS (Expected: JUDDS)
  ✓ PASS: Multiplicative Decrypt JUDDS -> HELLO (Expected: HELLO)
  ✓ PASS: Multiplicative HELLA * 5 -> JUDDA (A=0*5=0=A -> JUDDA)

--- 3. Testing Hill Cipher (2x2 and 3x3) ---
  ✓ PASS: Hill 2x2 HELP -> HIAT (Expected: HIAT)
  ✓ PASS: Hill 2x2 Decrypt HIAT -> HELP (Expected: HELP)
  ✓ PASS: Hill 3x3 ATTACKATDAWN -> PNOGKANTGXFX (Expected: PNOGKANTGXFX)
  ✓ PASS: Hill 3x3 Decrypt -> ATTACKATDAWN (Expected: ATTACKATDAWN)

--- 4. Testing SHA-256 Hashing ---
  ✓ PASS: SHA-256 'abc' -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

--- 5. Testing AES-GCM (Web Crypto API) ---
  ✓ PASS: Fresh IV generated on subsequent operations
  ✓ PASS: AES-GCM Round Trip: "CryptoLab AES-GCM authenticated payload 2026"
  ✓ PASS: AES-GCM tampered ciphertext rejected with authentication failure

--- 6. Testing RSA-OAEP (Web Crypto API) ---
  ✓ PASS: RSA-OAEP Round Trip: "CryptoLab RSA Key Exchange"

--- 7. Testing HMAC-SHA-256 ---
  ✓ PASS: HMAC signature verified successfully
  ✓ PASS: HMAC altered message signature rejected

==================================================
TEST SUMMARY: 23 PASSED, 0 FAILED
==================================================
```

Additionally, DOM integrity validation verified:
- **0 missing element IDs** between JavaScript controllers and HTML views.
- **0 dead hyperlinks or 404 assets** across all pages.

---

## Local Development & Setup

Because CryptoLab is built with modern vanilla web technologies, no build tools, package managers, or server installations are mandatory.

### Option 1: Direct File Opening
Double-click `index.html` in your file explorer to open it in any modern browser (Chrome, Edge, Firefox, Safari).

### Option 2: Local HTTP Server (Recommended for Web Crypto API)
Modern browsers require a secure context (`localhost` or `https://`) for full Web Crypto API features:

Using Node.js:
```bash
npx serve .
# Or using Python 3:
python -m http.server 8080
```
Open your browser at `http://localhost:8080`.

---

## GitHub Pages / Netlify Deployment Guide

### Deploying to GitHub Pages

1. **Initialize Git Repository (if not already done):**
   ```bash
   git init
   git add .
   git commit -m "Initial release of CryptoLab platform"
   ```

2. **Create a GitHub Repository:**
   - Go to [GitHub New Repository](https://github.com/new).
   - Name it `cryptolab` (or your preferred repository name).
   - Keep it Public.

3. **Push Local Code:**
   ```bash
   git remote add origin https://github.com/<your-username>/cryptolab.git
   git branch -M main
   git push -u origin main
   ```

4. **Enable GitHub Pages:**
   - Open your repository on GitHub.
   - Click **Settings** &rarr; **Pages** (under Code and automation).
   - Under **Build and deployment** &rarr; **Source**, select **Deploy from a branch**.
   - Under **Branch**, select `main` and folder `/ (root)`.
   - Click **Save**.
   - GitHub Pages will publish the site in 1-2 minutes at:
     `https://<your-username>.github.io/cryptolab/`

All asset links and script paths in CryptoLab use relative URLs (`css/style.css`, `js/app.js`), ensuring seamless operation in repository subdirectories without configuration changes.

---

## Security & Privacy Guarantees

1. **LocalStorage Sanitization:** In accordance with strict cryptographic privacy guidelines, private RSA keys, secret AES keys, and HMAC secrets are **never saved** in `localStorage`. Only non-sensitive operation summaries (e.g. timestamp, algorithm name, operation type, truncated previews) are logged.
2. **Fresh Initialization Vectors:** AES-GCM strictly generates a fresh 96-bit random IV for every encryption call to prevent IV-reuse vulnerabilities.
3. **Constant-Time Verification:** HMAC authentication tags are verified through constant-time algorithms to prevent timing attacks.
4. **Client-Side Isolation:** No telemetry or user input is sent to external servers.

---

## Academic Project Information

- **Course:** Information Security / Applied Cryptography Laboratory
- **Author:** Senior Cybersecurity & Software Engineering Project Team
- **Platform Version:** 2.0.0 Production Release
- **Compliance:** NIST FIPS 197, NIST FIPS 180-4, RFC 2104, RFC 4231, RFC 8017.

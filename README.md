# VAULT//ZERO — The Server That Can't Read Your Data
> **Hackathon Problem Statement 2 (PS2): Full-Stack Web Development & Zero-Knowledge Cryptography**

[![Zero-Knowledge](https://img.shields.io/badge/Security-Zero--Knowledge-00ff9d?style=for-the-badge&logo=shield)](https://github.com)
[![WebCrypto API](https://img.shields.io/badge/Crypto-AES--256--GCM-00f0ff?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Atomic Storage](https://img.shields.io/badge/Storage-Atomic_SQLite_WAL-bd93f9?style=for-the-badge)](https://sqlite.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-ffb800?style=for-the-badge)](LICENSE)

---

## 🔒 1. Problem Statement Overview & Executive Summary

People paste database credentials, API tokens, private keys, and passwords into team chat apps every day. Those secrets remain unencrypted on third-party servers indefinitely.

**VAULT//ZERO** solves this through **mathematically enforceable zero-knowledge client-side encryption and burn-on-read destruction**:
- The secret is encrypted **inside the sender's browser** using the hardware-accelerated **WebCrypto API (`AES-256-GCM`)**.
- The decryption key exists **strictly in the URL hash fragment (`#key`)**. According to **RFC 3986**, the fragment identifier is processed purely by the user agent and is **never transmitted over the wire** to the server in HTTP/HTTPS request lines or headers.
- The server stores **only scrambled ciphertext, a random 12-byte IV, and operational TTL metadata**.
- When the recipient opens the link, the server executes an **atomic read-and-delete** transaction in SQLite (`BEGIN IMMEDIATE`). Even if 100 simultaneous requests hit the server at the exact same millisecond, exactly one request receives the ciphertext, and all others are rejected.
- The recipient's browser immediately executes `window.history.replaceState` to wipe the `#key` from the URL bar and navigation history, starts a 30-second memory-shredding countdown, and provides a one-click **"Copy & Burn Tab"** button.

---

## 👥 2. Engineering Team & Work Distribution

| Team Member | Role | Key Architectural Responsibilities |
| :--- | :--- | :--- |
| **Aryan Sharma** | **Lead Cryptography & Systems Architect** | • Engineered `crypto.subtle` AES-256-GCM in-browser encryption pipeline.<br>• Designed RFC 3986 URL hash isolation standard.<br>• Implemented dual-factor PBKDF2 passphrase derivation (600,000 rounds SHA-256).<br>• Authored threat model and zero-knowledge cryptographic specifications. |
| **Lavyansh Gupta** | **Full-Stack & Core Backend Engineer** | • Architected atomic SQLite transactions (`BEGIN IMMEDIATE`) for race-condition prevention.<br>• Built sliding-window rate limiter per IP address (30 reqs/min).<br>• Implemented background daemon thread for auto-purging expired secrets.<br>• Developed REST API endpoints (`/api/secrets`, `/api/transparency`, `/api/system/integrity`). |
| **Hitesh Gupta** | **Lead Frontend & UI/UX Designer** | • Created Modern Cyberpunk & Minimalist Glassmorphic UI design system.<br>• Built persistent Multi-Theme Engine with 4 distinct palettes.<br>• Designed frictionless auto-destruction UI: 30s visual countdown & DOM memory shredder.<br>• Developed built-in native SVG QR code generator for instant mobile link sharing. |
| **Bhoma Ram** | **Security Auditor & QA Engineer** | • Conducted concurrency race-condition penetration testing with parallel threads.<br>• Audited browser memory for DOM retention and history leakage.<br>• Implemented Live Transparency Vault allowing judges to inspect raw database storage.<br>• Verified zero-log policy across terminal logs and error handlers. |

---

## 🎨 3. Multi-Theme Engine & UI/UX Features

VAULT//ZERO features a persistent dynamic theme engine saved to `localStorage`:
1. ⚡ **"Cyber Dark"** (Default): OLED black (`#05070c`), neon emerald (`#00ff9d`) and cyan (`#00f0ff`) accents, glowing cyber borders.
2. 💎 **"Clean Slate"**: Modern Minimalist Light, crisp slate blue (`#2563eb`), high-contrast readability, clean porcelain cards.
3. 🔮 **"Dracula / Hacker Purple"**: Deep midnight violet (`#0d0914`), electric purple (`#bd93f9`) and hot pink (`#ff79c6`) neon glows.
4. 📟 **"Amber Terminal"**: Retro CRT carbon black (`#0c0905`), phosphor amber (`#ffb000`), optional retro scanline textures.

---

## 📑 4. Tabbed Application Navigation

### Tab 1: Create Secret
- **Rich Editor**: Secret text area with character counter, live entropy calculator (Low / Moderate / Cryptographically Strong), clear and random password generator tools.
- **Zero-Knowledge File Attachment**: Encrypts sensitive documents, certificates (PEM), or JSON keys up to 5MB client-side.
- **Configurable Expiry (TTL)**: 5 Minutes (Quick Burn), 1 Hour, 1 Day, 7 Days.
- **Destruction Trigger**: Burn after 1 view (default), or N-views (2, 5, 10 views).
- **Optional Passphrase**: Derives key via PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte random salt.
- **Local Reference Tag**: Saved strictly on sender's browser for local tracking.
- **Generated Link Card**: One-click copy, open in new tab, and built-in native SVG QR code.

### Tab 2: Transparency Vault / Audit Log
- **Live Database Inspector**: Live table displaying records currently held in SQLite.
- Proves beyond doubt to judges that:
  - `plaintext` stored: **0**
  - `decryption_keys` stored: **0**
  - Stored records contain strictly base64 ciphertext, IV, and timestamps.
- **Real-Time Live Search Bar**: Filters records dynamically by secret ID, status, or date.
- **Audit Event Log**: Records lifecycle events (`CREATED`, `VIEWED`, `BURNED`, `EXPIRED`).

### Tab 3: Security Architecture & Threat Model
- **Interactive Visual Flow Diagram**: 6-step end-to-end cryptographic pipeline.
- **RFC 3986 Deep Dive**: Section 3.5 fragment identifier isolation breakdown.
- **Threat Model Matrix**: Clear distinction between what the server learns vs what it cannot learn.
- **Build Hash & Code Integrity**: Client bundle SHA-256 fingerprint.

### Tab 4: Local History & Activity
- Stored exclusively in the sender's `localStorage` (never sent to server).
- Tracks created link ID, label, and timestamp.
- **Live Server Status Check**: Query the server to check whether a secret is still `ACTIVE`, already `BURNED`, or `EXPIRED` without consuming the view!

### Tab 5: Team & Hackathon Overview
- Comprehensive team cards with roles, avatar badges, and work distribution.
- Problem Statement 2 Rubric Alignment Checklist.

---

## 🛡️ 5. Threat Model: What Server Learns vs Cannot Learn

| Data Property | Server State | Cryptographic Explanation |
| :--- | :---: | :--- |
| **Plaintext Content** | ❌ **CANNOT LEARN** | Encrypted in sender browser via `AES-256-GCM` before transmission. Plaintext never touches the network. |
| **Decryption Key** | ❌ **CANNOT LEARN** | Resides strictly in URL fragment (`#key`). RFC 3986 guarantees user agents never send fragments in HTTP headers. |
| **Passphrase / Salt** | ❌ **CANNOT LEARN** | Passphrases are converted into keys via PBKDF2 in the browser; raw passphrases never leave the client. |
| **Secret Content After View** | ❌ **CANNOT LEARN** | Atomic transaction deletes row immediately upon viewing (`DELETE FROM secrets WHERE id = ?`). |
| **Secret ID** | ✅ Learns | 16-character unguessable URL-safe identifier for database lookup. |
| **Creation & Expiry Times** | ✅ Learns | Necessary for TTL cleanup daemon to purge expired records. |
| **Ciphertext Byte Length** | ✅ Learns | Size of the encrypted blob payload. |
| **Client IP Address** | ✅ Learns | Used solely by sliding-window rate limiter (30 reqs/min) to prevent abuse. |

---

## 🏆 6. Hackathon Problem Statement 2 Rubric Alignment

| Criterion | Weight | How VAULT//ZERO Achieves Full Marks |
| :--- | :---: | :--- |
| **Security Design** | **30%** | WebCrypto standard AES-256-GCM, RFC 3986 `#key` isolation, PBKDF2 600k rounds, zero plaintext or keys in DB, sanitized zero-sensitive logging. |
| **One-Time & Expiry Behavior** | **20%** | SQLite WAL mode with `BEGIN IMMEDIATE` atomic read-and-delete. Concurrency testing proves 10 simultaneous requests yield exactly 1 success and 9 rejections. Background TTL cleanup thread. |
| **Core Features** | **15%** | Client-side file attachment encryption, configurable TTLs (5m, 1h, 1d, 7d), N-view limits, optional passphrase protection, sliding-window rate limiting. |
| **Threat Model & Explanation** | **15%** | Complete interactive documentation, RFC 3986 explainer, clear threat table, Transparency Vault proving zero-knowledge. |
| **Usability** | **10%** | One-click copy link, built-in SVG QR code generator, 4-theme engine, 30s auto-burn countdown, "Copy & Burn Tab" button. |
| **Code Quality** | **10%** | Clean modular architecture, standard WebCrypto APIs (no homebrew crypto), comprehensive automated test suite. |

---

## 🚀 7. Quickstart & Local Execution

### Prerequisites:
- Python 3.8+ (Zero external dependencies required; uses standard libraries `sqlite3`, `http.server`, `secrets`, `hashlib`).

### Run the Server:
```bash
python3 server.py
```
Open **`http://localhost:8000`** in your browser.

### Run Automated Validation Test Suite:
```bash
python3 test_in_sandbox.py
```
All 6 core security and concurrency tests will execute and verify database schema, atomic read-and-delete, race-condition defense, and rate limiting.

---

## 🌐 8. Cloud Deployment Guide

VAULT//ZERO is 100% production-ready and can be deployed in under 60 seconds:

### Deploy to Render:
1. Push this repository to GitHub.
2. Link repository to Render as a **Web Service**.
3. Render automatically detects `render.yaml` or set:
   - Build Command: *(leave empty)*
   - Start Command: `python3 server.py`
   - Port: `8000`

### Deploy with Docker:
```bash
docker build -t vault-zero .
docker run -p 8000:8000 vault-zero
```

---

<p align="center">
  <strong>Built for Problem Statement 2 (PS2) • Zero-Knowledge Secret Sharing</strong><br>
  Engineering Team: Aryan Sharma • Lavyansh Gupta • Hitesh Gupta • Bhoma Ram
</p>

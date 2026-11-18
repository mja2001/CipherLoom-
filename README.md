# 🔐 CipherLoom

**Encrypted-by-default document vault and grounded Q&A for the Anna Marketplace.**

> **The Problem:** AI assistants are brilliant at working with documents — but every sensitive file you hand them (NDAs, financials, health records, unreleased product docs) gets copied into plaintext storage you don't control. Existing AI wrappers all share the same flaw: **the value grows with your data, but the risk grows too.**

---

## How It Works

CipherLoom is a complete **Anna Marketplace App** — a static-SPA frontend paired with a sandboxed Python **Executa** backend — that keeps your files encrypted at rest:

1. **Encrypt** — Files are encrypted with **AES-256-GCM** (PBKDF2-SHA256, 310,000 iterations). Only ciphertext rests in Anna's APS storage; each document receives a SHA-256 hash and a deterministic content-addressed CID for provenance.
2. **Ask** — The Executa backend decrypts in-memory only for the answering step, retrieves the top-*k* most relevant excerpts per document, and Anna synthesizes a grounded answer **cited inline** (`[E0]`, `[E1]`, …). Plaintext never persists, and every run is logged for auditability.
3. **Anchor (Bonus)** — `CipherAnchor.sol` commits `sha256(cid)` on an EVM L2, providing tamper-evident, privacy-preserving provenance without revealing document content.

> **Trust Model:** `v0.1` decrypts inside the sandboxed Executa runtime; `v0.2` (already stubbed in `crypto.js` using WebCrypto) moves decryption fully client-side so plaintext never leaves the device.

---

## Key Features

- 🔐 **Zero-knowledge-friendly vault** — ciphertext at rest with content-addressed CIDs
- 💬 **Chat-native workflow** — `#cipherloom` deep-links straight into the vault with `entry_payload`
- 📎 **Cited, grounded answers** — inline excerpt citations to prevent hallucinated claims
- 🏛️ **Optional on-chain provenance** — EVM L2 anchor (`CipherAnchor.sol`) for regulated/compliance use cases
- 🎨 **Theme-aware UI** — light/dark mode follows Anna, with search and per-file detail view
- 📈 **MAU-qualified run logging** — encrypt and Q&A runs log usage directly to the app dashboard

---

## Tech Stack

| Layer | Implementation |
| :--- | :--- |
| **Anna Platform** | Schema-4 manifest (`manifest.json`), static-SPA bundle, `AnnaAppRuntime` SDK, `storage` / `files` / `llm.complete` / `tools.invoke` host APIs |
| **Backend (Executa)** | Python JSON-RPC/stdio plugin (`cipherloom_plugin.py`), `cryptography` (AES-256-GCM) |
| **Frontend** | Vanilla ESM SPA (`index.html`, `app.js`) + WebCrypto client-side path (`crypto.js`) |
| **Smart Contract** | Solidity `0.8.24` (`CipherAnchor.sol`) — deployable to Base, Arbitrum, or Optimism |
| **Testing** | `pytest` (9 passing: roundtrip, tamper-detection, ranking, protocol) + `vitest` (`bundle.smoke.test.ts`) |

---

## Repository Structure

```text
.
├── manifest.json          # Anna Marketplace schema-4 app manifest
├── app.json               # App metadata and configuration
├── executa.json           # Executa plugin registration & capabilities
├── index.html             # Static-SPA entry point
├── app.js                 # Vault UI, search, deep-link & AnnaAppRuntime integration
├── crypto.js              # WebCrypto AES-256-GCM helpers (v0.2 client-side path)
├── cipherloom_plugin.py   # Sandboxed Python Executa backend (encrypt, retrieve, Q&A)
├── CipherAnchor.sol       # Optional EVM L2 provenance anchor contract
├── bundle.smoke.test.ts   # Vitest mountBundle smoke test
└── pyproject.toml         # Python project and test configuration

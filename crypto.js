/**
 * cipher.js — optional client-side AES-GCM helpers (WebCrypto).
 *
 * Roadmap: v0.1 decrypts inside the sandboxed Executa (simpler, still
 * ciphertext-at-rest). v0.2 moves decryption into the browser so plaintext
 * never leaves the device — reuse these functions for that migration.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromB64(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function deriveKey(passphrase, salt = enc.encode("cipherloom.v0")) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310_000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Encrypt UTF-8 text -> { ct_b64, nonce_b64 } (GCM tag appended to ct). */
export async function encryptText(plaintext, passphrase) {
  const key = await deriveKey(passphrase);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, enc.encode(plaintext));
  return { ct_b64: toB64(ct), nonce_b64: toB64(nonce), alg: "AES-256-GCM" };
}

/** Decrypt -> UTF-8 string. Throws on tamper (GCM auth failure). */
export async function decryptText(ctB64, nonceB64, passphrase) {
  const key = await deriveKey(passphrase);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(nonceB64) },
    key,
    fromB64(ctB64)
  );
  return dec.decode(pt);
}

/** SHA-256 hex, for provenance display. */
export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}
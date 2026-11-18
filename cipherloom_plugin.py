#!/usr/bin/env python3
"""CipherLoom — Anna Executa plugin (Python flavour).

One dispatcher tool (`cipherloom`) with an `action` discriminator — the
same pattern as the official focus-flow reference app:

    action=encrypt    AES-256-GCM encrypt plaintext -> {ct_b64, nonce_b64, tag_b64, sha256}
    action=decrypt    reverse of the above (tamper-detects via GCM tag)
    action=ask        decrypt -> keyword-rank chunks -> return excerpts for the
                      bundle to synthesise with anna.llm.complete
    action=search     decrypt -> substring/keyword search over one blob
    action=anchor     SHA-256 commitment of a CID/ciphertext for on-chain anchoring

Protocol: JSON-RPC 2.0 over stdio (describe / invoke / health).
Logs go to stderr ONLY — anything else on stdout breaks the protocol.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MANIFEST = {
    "name": "cipherloom",
    "display_name": "CipherLoom Crypto Core",
    "version": "0.1.0",
    "description": "Encrypt/decrypt/ask over AES-256-GCM encrypted blobs with IPFS-style content addressing.",
    "author": "aymmj",
    "tools": [
        {
            "name": "cipherloom",
            "description": (
                "CipherLoom vault operations. Use action='ask' with a question and "
                "ciphertext to get decrypted, ranked excerpts; action='encrypt' to "
                "seal a blob; action='anchor' to compute a provenance commitment."
            ),
            "parameters": [
                {"name": "action", "type": "string",
                 "description": "encrypt | decrypt | ask | search | anchor", "required": True},
                {"name": "passphrase", "type": "string",
                 "description": "Key material (scrypt/HKDF derived). Never persisted.", "required": False},
                {"name": "plaintext", "type": "string", "description": "For encrypt.", "required": False},
                {"name": "ciphertext", "type": "string", "description": "base64 GCM ciphertext. For decrypt/ask/search.", "required": False},
                {"name": "nonce_b64", "type": "string", "description": "base64 12-byte nonce.", "required": False},
                {"name": "question", "type": "string", "description": "For ask.", "required": False},
                {"name": "query", "type": "string", "description": "For search.", "required": False},
                {"name": "cid", "type": "string", "description": "For anchor.", "required": False},
            ],
        }
    ],
}

CHUNK_SIZE = 1200       # chars per retrieval chunk
CHUNK_OVERLAP = 150
TOP_K = 6
SALT = b"cipherloom.v0"  # domain-separation salt for HKDF


# ---------------------------------------------------------------- crypto core

def derive_key(passphrase: str) -> bytes:
    """HKDF-SHA256 over the passphrase -> 32-byte AES key.

    Production note: prefer scrypt/passphrase KDF for low-entropy secrets;
    HKDF here is correct when the passphrase already has high entropy
    (e.g. a generated vault key). Swap KDF without touching call sites.
    """
    if not passphrase:
        raise ValueError("passphrase required")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=b"cipherloom-aesgcm-v0")
    return hkdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str) -> dict:
    key = derive_key(passphrase)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)  # tag appended
    blob = {
        "ct_b64": base64.b64encode(ct).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "alg": "AES-256-GCM",
        "sha256": hashlib.sha256(ct).hexdigest(),
        "size": len(plaintext.encode("utf-8")),
    }
    # Content addressing: CIDv1-style digest over the ciphertext (real IPFS CID
    # requires multihash codec; drop-in replacement — see README 'IPFS' section).
    blob["cid_like"] = "bafycipher" + hashlib.sha256(ct).hexdigest()[:39]
    return blob


def decrypt(ct_b64: str, nonce_b64: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)
    pt = AESGCM(key).decrypt(nonce, ct, None)  # raises on tamper -> IntegrityError
    return pt.decode("utf-8")


# ------------------------------------------------------------- retrieval core

def chunk(text: str) -> list[str]:
    step = CHUNK_SIZE - CHUNK_OVERLAP
    return [text[i:i + CHUNK_SIZE] for i in range(0, len(text), step)]


def rank_chunks(question: str, chunks: list[str], k: int = TOP_K) -> list[dict]:
    """Tiny lexical ranker (no model dependency, deterministic, fast).

    Tokens are weighted: question terms x2, title-case terms x1.5.
    Good enough to ground an LLM answer; swap for embeddings later.
    """
    q_tokens = set(re.findall(r"[a-z0-9]+", question.lower()))
    scored = []
    for idx, c in enumerate(chunks):
        toks = re.findall(r"[a-z0-9]+", c.lower())
        if not toks:
            continue
        freq = {}
        for t in toks:
            freq[t] = freq.get(t, 0) + 1
        score = sum((2.0 if t in q_tokens else 0.0) * min(freq.get(t, 0), 5) for t in q_tokens)
        # coverage bonus: fraction of question terms present
        if q_tokens:
            score += 3.0 * (len(q_tokens & set(toks)) / len(q_tokens))
        scored.append({"idx": idx, "score": round(score, 3), "text": c})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:k]


# ------------------------------------------------------------------ dispatch

def do_action(args: dict) -> dict:
    action = (args.get("action") or "").lower()

    if action == "encrypt":
        blob = encrypt(args.get("plaintext", ""), args.get("passphrase", ""))
        return {"success": True, "data": blob}

    if action in ("decrypt", "ask", "search"):
        pt = decrypt(args["ciphertext"], args["nonce_b64"], args["passphrase"])

        if action == "decrypt":
            return {"success": True, "data": {"plaintext": pt, "chars": len(pt)}}

        if action == "search":
            q = (args.get("query") or "").lower()
            hits = [c for c in chunk(pt) if q and q in c.lower()]
            return {"success": True, "data": {"hits": hits[:TOP_K], "count": len(hits)}}

        # action == "ask"
        question = args.get("question") or ""
        excerpts = rank_chunks(question, chunk(pt))
        return {
            "success": True,
            "data": {
                "excerpts": excerpts,
                "doc_chars": len(pt),
                "hint": "Synthesise the answer with anna.llm.complete, citing excerpt idx values.",
            },
        }

    if action == "anchor":
        material = (args.get("cid") or args.get("ciphertext") or "").encode()
        return {
            "success": True,
            "data": {
                "commitment": "0x" + hashlib.sha256(material).hexdigest(),
                "note": "Store on-chain via CipherAnchor.sol commit().",
            },
        }

    raise ValueError(f"unknown action: {action!r} (expected encrypt|decrypt|ask|search|anchor)")


def handle(req: dict) -> dict:
    method = req.get("method")
    if method == "describe":
        return {"result": MANIFEST}
    if method == "health":
        return {"result": {"status": "ready", "version": MANIFEST["version"]}}
    if method == "invoke":
        params = req.get("params") or {}
        try:
            return {"result": do_action(params.get("arguments") or {})}
        except ValueError as exc:
            return {"error": {"code": -32602, "message": str(exc)}}
        except Exception as exc:  # noqa: BLE001
            return {"error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"}}
    return {"error": {"code": -32601, "message": f"unknown method: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}) + "\n")
            sys.stdout.flush()
            continue
        payload = handle(req)
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), **payload}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
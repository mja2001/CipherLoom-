"""pytest suite for the CipherLoom Executa plugin.

Run standalone:   uv run --with pytest --with cryptography pytest tests/test_plugin.py -q
Under Anna:       via anna-executa-test fixtures (executa_session / executa_invoke).
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

import cryptography.exceptions
import pytest

PLUGIN = Path(__file__).resolve().parent.parent / "executas" / "cipherloom-python" / "cipherloom_plugin.py"
sys.path.insert(0, str(PLUGIN.parent))
import cipherloom_plugin as cl  # noqa: E402

PASS = "unit-test-passphrase-entropy-9f2c"
DOC = ("Section 7: either party may terminate this agreement with 30 days written notice. "
       "Q3 emissions were 41.2 tCO2e across Scope 1 and Scope 2.")


def test_encrypt_decrypt_roundtrip():
    blob = cl.encrypt(DOC, PASS)
    pt = cl.decrypt(blob["ct_b64"], blob["nonce_b64"], PASS)
    assert pt == DOC
    assert blob["alg"] == "AES-256-GCM"
    assert len(blob["sha256"]) == 64
    assert blob["cid_like"].startswith("bafycipher")


def test_tamper_detection():
    blob = cl.encrypt(DOC, PASS)
    raw = bytearray(base64.b64decode(blob["ct_b64"]))
    raw[0] ^= 0xFF
    with pytest.raises(cryptography.exceptions.InvalidTag):
        cl.decrypt(base64.b64encode(bytes(raw)).decode(), blob["nonce_b64"], PASS)


def test_wrong_passphrase_fails():
    blob = cl.encrypt(DOC, PASS)
    with pytest.raises(cryptography.exceptions.InvalidTag):
        cl.decrypt(blob["ct_b64"], blob["nonce_b64"], "wrong-passphrase")


def test_ask_ranks_relevant_chunks():
    chunks = cl.chunk(DOC)
    out = cl.rank_chunks("termination notice", chunks)
    assert out and out[0]["score"] > 0
    assert "terminate" in out[0]["text"]


def test_search_hits():
    blob = cl.encrypt(DOC, PASS)
    res = cl.do_action({"action": "search", "ciphertext": blob["ct_b64"],
                        "nonce_b64": blob["nonce_b64"],
                        "passphrase": PASS, "query": "emissions"})
    assert res["success"] is True
    assert res["data"]["count"] >= 1


def test_ask_envelope():
    blob = cl.encrypt(DOC, PASS)
    res = cl.do_action({"action": "ask", "ciphertext": blob["ct_b64"],
                        "nonce_b64": blob["nonce_b64"],
                        "passphrase": PASS, "question": "what were Q3 emissions?"})
    assert res["success"] is True
    assert res["data"]["excerpts"]
    assert res["data"]["doc_chars"] == len(DOC)


def test_anchor_commitment():
    res = cl.do_action({"action": "anchor", "cid": "bafycipherdeadbeef"})
    assert res["success"] is True
    assert res["data"]["commitment"].startswith("0x")
    assert len(res["data"]["commitment"]) == 66


def test_unknown_action_is_clean_error():
    with pytest.raises(ValueError):
        cl.do_action({"action": "nope"})


def test_protocol_describe_and_invoke():
    def rpc(payload):
        p = subprocess.run([sys.executable, str(PLUGIN)],
                           input=json.dumps(payload) + "\n",
                           capture_output=True, text=True, timeout=20)
        return json.loads(p.stdout.strip().splitlines()[-1])

    desc = rpc({"jsonrpc": "2.0", "method": "describe", "id": 1})
    assert desc["result"]["tools"][0]["name"] == "cipherloom"

    blob = cl.encrypt("hello anna", PASS)
    inv = rpc({"jsonrpc": "2.0", "method": "invoke", "id": 2, "params": {
        "tool": "cipherloom",
        "arguments": {"action": "decrypt", "ciphertext": blob["ct_b64"],
                      "nonce_b64": blob["nonce_b64"], "passphrase": PASS}}})
    assert inv["result"]["data"]["plaintext"] == "hello anna"

    health = rpc({"jsonrpc": "2.0", "method": "health", "id": 3})
    assert health["result"]["status"] == "ready"
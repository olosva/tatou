# test/test_fuzz_rmap_payloads.py
import os, requests, base64
BASE = os.getenv("TARGET_URL", "http://localhost:5000")

CASES = [
    {"payload": ""},                         # tom
    {"payload": " "},
    {"payload": "not-base64"},
    {"payload": base64.b64encode(b"{}").decode()},
    {"payload": base64.b64encode(b'{"a":1}').decode()},
    {"payload": base64.b64encode(b"\x00"*64).decode()},
    {"payload": "A"*10000},
]

def test_rmap_initiate_no_5xx():
    for c in CASES:
        r = requests.post(f"{BASE}/rmap-initiate", json=c)
        assert r.status_code < 500, (c, r.status_code, r.text[:200])

def test_rmap_get_link_no_5xx():
    for c in CASES:
        r = requests.post(f"{BASE}/rmap-get-link", json=c)
        assert r.status_code < 500, (c, r.status_code, r.text[:200])

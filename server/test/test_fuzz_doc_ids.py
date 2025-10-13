# test/test_fuzz_doc_ids.py
import os, requests
BASE = os.getenv("TARGET_URL", "http://localhost:5000")

CASES = ["-1", "0", "999999999999", "abc", "1.5", "", "%00", " "]

def test_get_document_id_robustness():
    for cid in CASES:
        r = requests.get(f"{BASE}/get-document/{cid}")
        assert r.status_code < 500, (cid, r.status_code, r.text[:200])

def test_list_versions_id_robustness():
    for cid in CASES:
        r = requests.get(f"{BASE}/list-versions/{cid}")
        assert r.status_code < 500, (cid, r.status_code, r.text[:200])

def test_delete_document_id_robustness():
    for cid in CASES:
        r = requests.delete(f"{BASE}/delete-document/{cid}")
        assert r.status_code < 500, (cid, r.status_code, r.text[:200])

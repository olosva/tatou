# test/test_fuzz_concurrency_smoke.py
import os, requests, concurrent.futures
BASE = os.getenv("TARGET_URL", "http://localhost:5000")

def test_read_watermark_concurrent_no_5xx():
    url = f"{BASE}/read-watermark/1"
    body = {"method":"visible-stamp-gs", "key":"k"}
    def one():
        r = requests.post(url, json=body, timeout=10)
        return r.status_code
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        codes = list(ex.map(lambda _: one(), range(50)))
    assert all(c < 500 for c in codes), codes

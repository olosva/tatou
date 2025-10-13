# test/test_fuzz_watermark_hypothesis.py
import os, requests
from hypothesis import given, strategies as st

BASE = os.getenv("TARGET_URL", "http://localhost:5000")

weird_str = st.text(min_size=0, max_size=200).filter(lambda s: len(s.encode("utf-8", "ignore")) <= 800)

@given(method=weird_str, position=weird_str, key=weird_str, secret=weird_str, intended=weird_str)
def test_create_watermark_weird_strings_no_5xx(method, position, key, secret, intended):
    body = {"method": method, "position": position, "key": key, "secret": secret, "intended_for": intended}
    r = requests.post(f"{BASE}/create-watermark/1", json=body)
    assert r.status_code < 500, r.text[:300]

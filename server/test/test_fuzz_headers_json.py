# test/test_fuzz_headers_json.py
import os, requests, itertools
BASE = os.getenv("TARGET_URL", "http://localhost:5000")

ENDPOINTS = [
    ("POST", "/create-watermark/1"),
    ("POST", "/read-watermark/1"),
    ("POST", "/create-user"),
    ("POST", "/login"),
]

BODIES = [ {}, {"method":"visible-stamp-gs"}, {"method":""}, "not-json", 123, None ]
CTS = [None, "application/json", "text/plain", "application/x-www-form-urlencoded", "application/octet-stream"]

def test_headers_and_bodies_no_5xx():
    for method, path in ENDPOINTS:
        for ct, body in itertools.product(CTS, BODIES):
            url = f"{BASE}{path}"
            headers = {}
            data = None
            json = None
            if ct:
                headers["Content-Type"] = ct
            # sätt payload baserat på CT
            if ct == "application/json":
                json = body if isinstance(body, (dict, list)) else body
            elif ct in (None, "text/plain", "application/octet-stream"):
                data = str(body).encode() if body is not None else b""
            elif ct == "application/x-www-form-urlencoded":
                data = body if isinstance(body, dict) else {"x": str(body)}
            resp = requests.request(method, url, headers=headers, data=data, json=json)
            assert resp.status_code < 500, (path, ct, type(body).__name__, resp.status_code, resp.text[:300])

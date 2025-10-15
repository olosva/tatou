# test/test_fuzz_static_traversal.py
import os, requests, itertools

BASE = os.getenv("TARGET_URL", "http://localhost:5000")

def test_static_disallows_traversal():
    payloads = [
        "../app.py", "../../etc/passwd", "..%2f..%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/secret", "....//....//etc/passwd", "..\\..\\windows\\win.ini",
    ]
    for p in payloads:
        r = requests.get(f"{BASE}/static/{p}")
        # Tillåt 403/404/400, men **inte** 200 (läckage) och absolut inte 5xx
        assert r.status_code not in (200, 500, 502, 503), (p, r.status_code, r.text[:200])

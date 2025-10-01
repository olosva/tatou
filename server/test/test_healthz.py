import os
import requests

BASE = os.getenv("TEST_HTTP_BASE")

def test_healthz(client=None):
    if BASE:
        r = requests.get(f"{BASE}/healthz", timeout=5)
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            assert r.json().get("db_connected") is True
    else:
        r = client.get("/healthz")
        assert r.status_code in (200, 503)
        if r.status_code == 200:
            assert r.get_json().get("db_connected") is True

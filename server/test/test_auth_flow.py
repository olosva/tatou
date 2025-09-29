import os, requests, uuid

BASE = os.getenv("TEST_HTTP_BASE")

def _post_json(client, path, payload):
    if BASE:
        return requests.post(f"{BASE}{path}", json=payload, timeout=5)
    else:
        return client.post(path, json=payload)

def test_auth_flow(client=None):
    email = f"u{uuid.uuid4().hex[:8]}@ex.com"
    login = f"user_{uuid.uuid4().hex[:8]}"
    pw = "abc12345"  # min 8 i din validering i prod, lokalt satte du 3 – funkar här

    r = _post_json(client, "/api/create-user", {"email": email, "login": login, "password": pw})
    assert r.status_code == 201, getattr(r, "text", r.data)
    rid = (r.json() if BASE else r.get_json())["id"]
    assert rid

    r = _post_json(client, "/api/login", {"email": email, "password": pw})
    assert r.status_code == 200, getattr(r, "text", r.data)
    data = r.json() if BASE else r.get_json()
    assert "token" in data and data["token"]

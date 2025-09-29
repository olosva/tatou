import os, requests, uuid

BASE = os.getenv("TEST_HTTP_BASE")

def _post_json(client, path, payload):
    if BASE:
        return requests.post(f"{BASE}{path}", json=payload, timeout=5)
    else:
        return client.post(path, json=payload)

def _get(client, path, headers=None):
    if BASE:
        return requests.get(f"{BASE}{path}", headers=headers or {}, timeout=5)
    else:
        return client.get(path, headers=headers or {})

def test_protected_endpoints_require_auth(client=None):
    # 1) Utan token ska 401
    r = _get(client, "/api/list-documents")
    assert r.status_code == 401

    # 2) Skapa user + logga in
    email = f"p{uuid.uuid4().hex[:8]}@ex.com"
    login = f"p_{uuid.uuid4().hex[:8]}"
    pw = "abc12345"

    r = _post_json(client, "/api/create-user", {"email": email, "login": login, "password": pw})
    assert r.status_code == 201
    r = _post_json(client, "/api/login", {"email": email, "password": pw})
    assert r.status_code == 200
    data = r.json() if BASE else r.get_json()
    token = data["token"]

    # 3) Med token ska funka
    headers = {"Authorization": f"Bearer {token}"}
    r = _get(client, "/api/list-documents", headers=headers)
    assert r.status_code == 200
    body = r.json() if BASE else r.get_json()
    assert "documents" in body

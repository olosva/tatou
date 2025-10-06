# test/test_auth_flow.py
import uuid

def _post_json(client, path, payload):
    return client.post(path, json=payload)

def _get(client, path, headers=None):
    return client.get(path, headers=headers or {})

def test_auth_flow(client):
    email = f"u{uuid.uuid4().hex[:8]}@ex.com"
    login = f"user_{uuid.uuid4().hex[:8]}"
    pw = "abc12345"

    # skapa användare
    r = _post_json(client, "/api/create-user", {"email": email, "login": login, "password": pw})
    assert r.status_code == 201

    # logga in
    r = _post_json(client, "/api/login", {"email": email, "password": pw})
    assert r.status_code == 200
    data = r.get_json()
    assert "token" in data and data["token"]
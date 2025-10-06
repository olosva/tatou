# test/test_api.py
import pytest

def _ensure_user(client, email: str, login: str, password: str):
    # Försök skapa; ignorera om den redan finns
    client.post("/api/create-user", json={"email": email, "login": login, "password": password})

def test_tokens_unique_for_different_users(client):
    users = [
        ("olof@olof.olof",   "olof",   "olof"),
        ("jacob@jacob.jacob","jacob",  "jacob"),
        ("elliot@elliot.elliot","elliot","elliot"),
    ]
    for email, login, pw in users:
        _ensure_user(client, email, login, pw)

    res_a = client.post("/api/login", json={"email": users[0][0], "password": users[0][2]})
    res_b = client.post("/api/login", json={"email": users[1][0], "password": users[1][2]})
    res_c = client.post("/api/login", json={"email": users[2][0], "password": users[2][2]})

    assert res_a.status_code == 200
    assert res_b.status_code == 200
    assert res_c.status_code == 200

    ta = res_a.get_json()["token"]
    tb = res_b.get_json()["token"]
    tc = res_c.get_json()["token"]

    # Alla tre tokens ska skilja sig (sessionsbaserade)
    assert ta != tb
    assert tb != tc
    assert ta != tc

    
    

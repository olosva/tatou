from server import app
from werkzeug.security import generate_password_hash, check_password_hash


def test_login_sql_injection():
    client = app.test_client()
    payload = {"email": "' OR '1'='1", "password": "irrelevant"}
    res = client.post("/api/login", json=payload)
    # Should reject injection attempts
    assert res.status_code == 400
    assert "error" in res.get_json()
    
def test_create_user_sql_injection():
    client = app.test_client()
    payload = {"email": "' OR '1'='1", "login":""' OR ''='"", "password": "irrelevant"}
    res = client.post("/api/create-user", json=payload)
    # Should reject injection attempts
    assert res.status_code == 400
    assert "error" in res.get_json()
    
def test_tokens_unique_for_different_users(client):
    # create or ensure two users exist: user_a and user_b
    res_a = client.post("/api/login", json={"email":"olof@olof.olof","password":"olof"})
    res_b = client.post("/api/login", json={"email":"jacob@jacob.jacob","password":"jacob"})
    assert res_a.status_code == 200
    assert res_b.status_code == 200
    token_a = res_a.get_json()["token"]
    token_b = res_b.get_json()["token"]
    assert token_a != token_b, "Tokens must be unique per user"
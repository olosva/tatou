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

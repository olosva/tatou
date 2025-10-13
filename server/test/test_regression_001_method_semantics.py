import os, requests, pytest

BASE = os.getenv("TARGET_URL", "http://localhost:5000")

@pytest.mark.xfail(reason="Nuvarande beteende: 403. Standard/tolkning: 405.")
def test_get_create_user_should_be_405():
    r = requests.get(f"{BASE}/create-user")
    assert r.status_code == 405

# test/test_healthz.py
def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code in (200, 503)
    if r.status_code == 200:
        assert r.get_json().get("db_connected") is True


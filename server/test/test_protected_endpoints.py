# test/test_protected_endpoints.py
import io

def _get(client, path, headers=None):
    return client.get(path, headers=headers or {})

def _post(client, path, headers=None, data=None, content_type=None):
    return client.post(path, headers=headers or {}, data=data, content_type=content_type)

def test_protected_endpoints_require_auth(client):
    # 1) Utan token => 401
    r = _get(client, "/api/list-documents")
    assert r.status_code == 401

    # 2) Skapa en användare och logga in, prova sen upload/list
    email = "protected@example.com"
    login = "protected_user"
    pw = "abc12345"
    client.post("/api/create-user", json={"email": email, "login": login, "password": pw})
    r = client.post("/api/login", json={"email": email, "password": pw})
    assert r.status_code == 200
    token = r.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # lista dokument (tom lista men 200)
    r = _get(client, "/api/list-documents", headers=headers)
    assert r.status_code == 200

    # ladda upp en minimal giltig PDF
    # (PDF header + EOF – duger för pypdf-läsning i upload-endpointen)
    fake_pdf = b"%PDF-1.4\n%...\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    data = {
        "name": "sample.pdf",
        "file": (io.BytesIO(fake_pdf), "sample.pdf"),
    }
    r = _post(client, "/api/upload-document", headers=headers, data=data, content_type="multipart/form-data")
    assert r.status_code == 201

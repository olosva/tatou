import os, itertools, os as _os, requests

BASE = os.getenv("TARGET_URL", "http://localhost:5000")
URL  = f"{BASE}/upload-document"

CASES = [
    b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n",     # minimal header
    b"%PDF-1.7\n" + b"A"*10000 + b"\n%%EOF\n",                # stor body
    b"",                                                      # tom fil
    b"\x00\x00\x00%PDF-1.4\n%%EOF\n",                         # NUL-prefix
    _os.urandom(2048),                                        # slumpbytes
    b"%PDF-1.4\nstream\nendstream\n%%EOF",                    # trasig stream
]

def test_upload_document_robustness_no_5xx():
    for ct, payload in itertools.product(["application/pdf", "application/octet-stream"], CASES):
        r = requests.post(URL, data=payload, headers={"Content-Type": ct})
        assert r.status_code < 500, (
            f"500 on upload with CT={ct}, size={len(payload)}; body={r.text[:300]}"
        )

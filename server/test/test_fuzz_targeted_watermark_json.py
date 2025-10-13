import os, requests, itertools, json, random, string

BASE = os.getenv("TARGET_URL", "http://localhost:5000")

def weird_strings():
    yield ""                            # tom
    yield "A"*50000                     # jättelång
    yield "\udcff"                      # surrogat
    yield "".join(chr(i) for i in range(1,128))  # kontrolltecken
    yield json.dumps({"nested":"x"})    # JSON-in-string

def ints():
    for v in [ -1, 0, 1, 2**31-1, 2**31, 999999999999 ]:
        yield v

def test_create_watermark_robustness_no_5xx():
    for doc_id in itertools.islice(ints(), 0, 6):
        url = f"{BASE}/create-watermark/{doc_id}"
        bodies = [
            {"method":"visible-stamp-gs"},
            {"method":"visible-stamp-gs","position":"top","key":"k"},
            {"method":"visible-stamp-gs","position": next(weird_strings()), "key": next(weird_strings()), "secret": next(weird_strings()), "intended_for": next(weird_strings())},
            {"method": ""},                             # saknad/ogiltig
            {"method": "nonexistent-method"},          # okänd metod
        ]
        for body in bodies:
            r = requests.post(url, json=body)
            assert r.status_code < 500, f"{url} body={body} -> {r.status_code} {r.text[:300]}"

def test_read_watermark_robustness_no_5xx():
    for doc_id in itertools.islice(ints(), 0, 6):
        url = f"{BASE}/read-watermark/{doc_id}"
        bodies = [
            {"method":"visible-stamp-gs","key":"k"},
            {"method":"visible-stamp-gs","position": next(weird_strings()), "key": next(weird_strings())},
            {"method":"", "key":""},                   # tomma fält
            {"method":"nonexistent-method","key":"x"}, # okänd metod
        ]
        for body in bodies:
            r = requests.post(url, json=body)
            assert r.status_code < 500, f"{url} body={body} -> {r.status_code} {r.text[:300]}"
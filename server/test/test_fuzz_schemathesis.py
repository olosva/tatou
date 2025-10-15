import os
import copy
import schemathesis
from hypothesis import settings, HealthCheck

BASE_URL = os.getenv("TARGET_URL", "http://localhost:5000")

# 1) Load full schema
_full = schemathesis.openapi.from_path("openapi.yml")

# 2) Remove the upload endpoint from the raw spec
raw = copy.deepcopy(_full.raw_schema)
raw.setdefault("paths", {}).pop("/upload-document", None)

# 3) Build a new schema without /upload-document
schema = schemathesis.openapi.from_dict(raw)

# Hypothesis tuning
settings.register_profile(
    "ci",
    max_examples=int(os.getenv("FUZZ_MAX_EXAMPLES", "200")),
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow,),
)
settings.load_profile("ci")

@schema.parametrize()
def test_api_fuzz(case):
    response = case.call(base_url=BASE_URL)
    assert response.status_code < 500, (
        f"Server error on {case.method} {case.path} "
        f"status={response.status_code} body={response.text[:500]}"
    )

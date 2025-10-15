## Bugs found via fuzzing 
## BUG-001: 403 on GET /create-user (should be 405 Method Not Allowed)
- Date: 2025-10-13
- Endpoint: GET /create-user
- Problem: Wrong methods are answered with 403 instead of 405.
- Risk: Low (standard deviation), but can make error handling difficult for clients.
- Status: UNFIXED
- Regression test: test/test_regression_001_method_semantics.py (xfail until fixed)
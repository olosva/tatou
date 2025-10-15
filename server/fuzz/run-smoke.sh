#!/usr/bin/env bash
set -euo pipefail

: "${TEST_HTTP_BASE:=http://localhost:5000}"

mkdir -p fuzz

schemathesis run openapi/openapi.yaml \
  --url "$TEST_HTTP_BASE" \
  --phases=examples,fuzzing,stateful \
  --checks=all \
  -n 100 \
  --report-junit-path fuzz/junit-smoke.xml \
  --report-har-path fuzz/fuzz.har || true

# Spara dockerloggar om du kör i container
if command -v docker >/dev/null 2>&1; then
  docker compose logs --no-color > fuzz/docker-logs.txt || true
fi

echo "Fuzz smoke run done. Artifacts in ./fuzz/"

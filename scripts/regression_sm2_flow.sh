#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

./bin/sm2_server > /tmp/sm2_server.log 2>&1 &
SERVER_PID=$!
cleanup() {
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for i in $(seq 1 20); do
  if curl -sS http://localhost:8888/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! curl -sS http://localhost:8888/health | grep -q '"status":"ok"'; then
  echo "server health check failed"
  cat /tmp/sm2_server.log || true
  exit 1
fi

INIT_RESP="$(curl -sS -X POST http://localhost:8888/init -H 'Content-Type: application/json' -d '{"user_count":3}')"
echo "init: $INIT_RESP"

GROUP_RESP="$(curl -sS -X POST http://localhost:8888/gen-group-key -H 'Content-Type: application/json' -d '{"user_count":3}')"
echo "group-key: $GROUP_RESP"

SIGN_RESP="$(curl -sS -X POST http://localhost:8888/sign -H 'Content-Type: application/json' -d '{"message":"message digest"}')"
echo "sign: $SIGN_RESP"

R="$(echo "$SIGN_RESP" | python3 -c 'import sys, json; print(json.load(sys.stdin)["r"])')"
S="$(echo "$SIGN_RESP" | python3 -c 'import sys, json; print(json.load(sys.stdin)["s"])')"

VERIFY_RESP="$(curl -sS -X POST http://localhost:8888/verify -H 'Content-Type: application/json' -d "{\"message\":\"message digest\",\"r\":\"$R\",\"s\":\"$S\"}")"
echo "verify: $VERIFY_RESP"

echo "$VERIFY_RESP" | grep -q '"valid":true'
echo "regression flow passed"

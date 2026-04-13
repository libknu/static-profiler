#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${WORKSPACE_ROOT:-$HOME/workspace}"
PROJECT_ROOT="${PROJECT_ROOT:-$WORKSPACE_ROOT/glibc-src/glibc-2.41}"
PYTHON_BIN="${PYTHON_BIN:-python}"

cd "$WORKSPACE_ROOT"

exec "$PYTHON_BIN" -m LLM_icall_resolver.main \
  --project-root "$PROJECT_ROOT" \
  --project glibc \
  --version glibc-2.41 \
  --family C \
  --caller-symbol key_call_socket \
  --icall-expr 'clnt_call(clnt, proc, xdr_arg, arg, xdr_rslt, rslt, wait_time)' \
  --icall-location sunrpc/key_call.c \
  --max-hops 6 \
  --stream


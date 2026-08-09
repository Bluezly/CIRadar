#!/usr/bin/env sh
set -eu

formatted="$(gofmt -l .)"
if [ -n "$formatted" ]; then
  printf '%s\n' 'gofmt check failed; unformatted files:'
  printf '%s\n' "$formatted"
  exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
fi

comments="$(grep -RInE '^[[:space:]]*//' --include='*.go' --include='*.js' --exclude-dir=.git --exclude-dir=dist . || true)"
if [ -n "$comments" ]; then
  printf '%s\n' "$comments"
  exit 1
fi

node --check internal/server/dashboard.js
python3 scripts/check-doc-links.py
python3 - <<'PY'
from pathlib import Path
import json

for path in Path('.').rglob('*.json'):
    json.loads(path.read_text(encoding='utf-8'))

for path in Path('.').rglob('*'):
    if not path.is_file() or '.git' in path.parts or path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.zip', '.exe'}:
        continue
    data = path.read_bytes()
    if b'\x00' in data:
        continue
    text = data.decode('utf-8')
    if text and not text.endswith('\n'):
        raise SystemExit(f'missing final newline: {path}')
    if path.suffix.lower() != '.bat' and '\r\n' in text:
        raise SystemExit(f'unexpected CRLF line endings: {path}')
    if path.suffix.lower() == '.bat' and '\r\n' not in text:
        raise SystemExit(f'Windows batch file must use CRLF: {path}')
PY

for script in scripts/*.sh; do
  sh -n "$script"
done

printf 'Repository checks: OK\n'

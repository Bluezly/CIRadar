from pathlib import Path
import re
import sys
import urllib.parse

root = Path(__file__).resolve().parents[1]
pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
errors = []
for doc in root.rglob("*.md"):
    text = doc.read_text(encoding="utf-8")
    for match in pattern.finditer(text):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = raw.split("#", 1)[0].strip()
        if not target:
            continue
        target = urllib.parse.unquote(target)
        resolved = (doc.parent / target).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            errors.append(f"{doc.relative_to(root)}: link escapes repository: {raw}")
            continue
        if not resolved.exists():
            errors.append(f"{doc.relative_to(root)}: missing link target: {raw}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("Markdown links: OK")

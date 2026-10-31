"""One disposable, stdlib-only regex operation. Parent enforces a hard deadline."""

import json
import re
import sys
import time

try:
    raw = sys.stdin.buffer.read(4_000_001)
    if len(raw) > 4_000_000:
        raise ValueError("regex batch exceeds limit")
    body = json.loads(raw)
    pattern = re.compile(body["pattern"])
    started = time.perf_counter()
    matches = [bool(pattern.search(text)) for text in body["texts"]]
    print(json.dumps({"matches": matches, "scan_ms": (time.perf_counter() - started) * 1000}))
except (ValueError, KeyError, TypeError, OverflowError, re.error):
    print(json.dumps({"error": "invalid regex operation"}))

"""Execute untrusted regex matches in killable processes, including live WAF use."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

HARD_TIMEOUT = 1.0


class BoundedPattern:
    def __init__(self, pattern):
        if len(pattern) > 300:
            raise re.error("regex longer than 300 characters")
        try:
            re.compile(pattern)  # Validate syntax; matching happens outside the server.
        except (OverflowError, ValueError) as exception:
            raise re.error("regex exceeds compilation limits") from exception
        self.pattern = pattern
        self.scan_ms = 0.0

    def search_many(self, texts):
        body = json.dumps({"pattern": self.pattern, "texts": texts}, ensure_ascii=True)
        if len(body) > 4_000_000:
            raise ValueError("regex batch exceeds 4 MB limit")
        try:
            result = subprocess.run(
                # Windows venv launchers may spawn another interpreter; killing a
                # launcher alone leaves its child alive. The worker is stdlib-only.
                [
                    getattr(sys, "_base_executable", sys.executable),
                    "-I",
                    str(Path(__file__).with_name("regex_worker.py")),
                ],
                input=body,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=HARD_TIMEOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                check=False,
            )
        except subprocess.TimeoutExpired as exception:
            # subprocess.run kills and waits for the child before raising.
            raise TimeoutError("regex hard process deadline exceeded") from exception
        if result.returncode:
            raise TimeoutError("regex worker exited")
        try:
            payload = json.loads(result.stdout)
            matches = payload["matches"]
            if len(matches) != len(texts):
                raise ValueError("incomplete regex batch")
            self.scan_ms = float(payload["scan_ms"])
            return matches
        except (KeyError, ValueError, TypeError) as exception:
            raise TimeoutError("regex worker rejected operation") from exception

    def search(self, text):
        return self.search_many([text])[0]

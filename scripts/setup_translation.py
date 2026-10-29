"""Download and verify the optional offline English → Chinese model (about 71 MB).

Install runtime first: python -m pip install -c requirements.lock -e '.[translation]'
Then: python scripts/setup_translation.py
"""

import hashlib
import json
import zipfile
from pathlib import Path

import httpx

MODEL_URL = "https://argos-net.com/v1/translate-en_zh-1_9.argosmodel"
SHA256 = "433e7c4f034d87fbe2353161e05f18646d7999452f801a4e1f0378522b9850ab"
ROOT = Path(__file__).resolve().parents[1] / "data/models"


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    path = ROOT / "en-zh.argosmodel"
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != SHA256:
        with httpx.stream("GET", MODEL_URL, timeout=120, follow_redirects=True) as response:
            response.raise_for_status()
            size = 0
            with path.open("wb") as output:
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 100_000_000:
                        raise ValueError("model download exceeds 100 MB")
                    output.write(chunk)
    if hashlib.sha256(path.read_bytes()).hexdigest() != SHA256:
        raise ValueError("model SHA-256 mismatch; not extracting")
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            target = (ROOT / member.filename).resolve()
            if not target.is_relative_to(ROOT.resolve()):
                raise ValueError("unsafe archive member")
            # Only data required for inference and attribution; no Python or pickle files.
            if member.filename.endswith((".json", ".bin", ".model", "README.md")):
                archive.extract(member, ROOT)
    manifest = {
        "url": MODEL_URL,
        "sha256": SHA256,
        "model": "Argos en-zh 1.9 / OPUS-MT",
        "license": "CC-BY 4.0",
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("Offline model ready:", ROOT / "translate-en_zh-1_9")


if __name__ == "__main__":
    main()

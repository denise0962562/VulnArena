"""Download a pinned multilingual CPU embedding model, verifying every file."""

import argparse
import hashlib
import json
from pathlib import Path

import httpx

REPOSITORY = "Xenova/multilingual-e5-small"
REVISION = "761b726dd34fb83930e26aab4e9ac3899aa1fa78"
MODEL_ID = "multilingual-e5-small-int8@" + REVISION[:12]
DESTINATION = Path(__file__).resolve().parents[1] / "data/models/nvd-e5-small-int8"
FILES = [
    "onnx/model_quantized.onnx",
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "README.md",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trust-env", action="store_true", help="Use configured HTTP proxy variables"
    )
    args = parser.parse_args()
    DESTINATION.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=90, follow_redirects=True, trust_env=args.trust_env) as client:
        response = client.get(
            f"https://huggingface.co/api/models/{REPOSITORY}/revision/{REVISION}",
            params={"blobs": "true"},
        )
        response.raise_for_status()
        metadata = {item["rfilename"]: item for item in response.json()["siblings"]}
        manifest = {"model": MODEL_ID, "repository": REPOSITORY, "revision": REVISION, "files": {}}
        for filename in FILES:
            item = metadata[filename]
            destination = DESTINATION / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            sha = item.get("lfs", {}).get("sha256")
            git_sha = item.get("blobId")
            size = item.get("size")
            existing = destination.read_bytes() if destination.is_file() else b""
            if existing and (
                (sha and hashlib.sha256(existing).hexdigest() == sha)
                or (
                    git_sha
                    and hashlib.sha1(
                        b"blob " + str(len(existing)).encode() + b"\0" + existing
                    ).hexdigest()
                    == git_sha
                )
            ):
                data = existing
            else:
                part = destination.with_suffix(destination.suffix + ".part")
                with client.stream(
                    "GET", f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{filename}"
                ) as download:
                    download.raise_for_status()
                    with part.open("wb") as handle:
                        for block in download.iter_bytes(1024 * 1024):
                            handle.write(block)
                data = part.read_bytes()
                if size and len(data) != size:
                    raise ValueError("model download size mismatch: " + filename)
                if sha:
                    valid = hashlib.sha256(data).hexdigest() == sha
                elif git_sha:
                    valid = (
                        hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                        == git_sha
                    )
                else:
                    raise ValueError("missing repository checksum: " + filename)
                if not valid:
                    raise ValueError("model download checksum mismatch: " + filename)
                part.replace(destination)
            manifest["files"][filename] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
            print(f"Verified {filename}: {len(data)} bytes", flush=True)
        (DESTINATION / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print("CPU embedding model ready: " + MODEL_ID, flush=True)


if __name__ == "__main__":
    main()

"""Create an isolated Python 3.12 CPU runtime from checksummed platform wheels."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
from packaging.requirements import Requirement
from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trust-env", action="store_true", help="Use configured HTTP proxy variables"
    )
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("CPU lock requires Python 3.12.")
    runtime = ROOT / ".tools/ai-runtime"
    python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        subprocess.run([sys.executable, "-m", "venv", str(runtime)], check=True)
    wheel_dir = ROOT / ".tools/ai-runtime-wheels"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    tag_order = {tag: index for index, tag in enumerate(sys_tags())}
    paths = []
    manifest = {}
    with httpx.Client(timeout=90, follow_redirects=True, trust_env=args.trust_env) as client:
        for specification in (ROOT / "requirements-ai.lock").read_text().splitlines():
            if not specification or specification.startswith("#"):
                continue
            requirement = Requirement(specification)
            if requirement.marker and not requirement.marker.evaluate():
                continue
            pinned = list(requirement.specifier)
            if len(pinned) != 1 or pinned[0].operator != "==":
                raise ValueError("Runtime dependencies must be exactly pinned.")
            name, version = requirement.name, pinned[0].version
            response = client.get(f"https://pypi.org/pypi/{name}/{version}/json")
            response.raise_for_status()
            candidates = []
            for file in response.json()["urls"]:
                if not file["filename"].endswith(".whl"):
                    continue
                tags = parse_wheel_filename(file["filename"])[3]
                ranks = [tag_order[tag] for tag in tags if tag in tag_order]
                if ranks:
                    candidates.append((min(ranks), file))
            if not candidates:
                raise RuntimeError("No compatible binary wheel: " + specification)
            file = min(candidates, key=lambda item: item[0])[1]
            destination = wheel_dir / file["filename"]
            expected = file["digests"]["sha256"]
            if (
                not destination.is_file()
                or hashlib.sha256(destination.read_bytes()).hexdigest() != expected
            ):
                with client.stream("GET", file["url"]) as download:
                    download.raise_for_status()
                    with destination.open("wb") as handle:
                        for block in download.iter_bytes(1024 * 1024):
                            handle.write(block)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
                raise RuntimeError("Wheel checksum mismatch: " + file["filename"])
            paths.append(str(destination))
            manifest[specification] = {"file": file["filename"], "sha256": expected}
            print("Verified " + specification, flush=True)
    (runtime / "Lib/site-packages/nvd_shared_dependencies.pth").unlink(missing_ok=True)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            *paths,
            "--disable-pip-version-check",
        ],
        check=True,
    )
    (runtime / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    subprocess.run(
        [str(python), "-c", "import numpy, onnxruntime, fastembed; print('CPU runtime ready')"],
        check=True,
    )


if __name__ == "__main__":
    main()

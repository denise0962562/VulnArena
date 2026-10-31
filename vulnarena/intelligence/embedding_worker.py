"""JSON-lines CPU worker. Native inference libraries never enter the web process."""

import argparse
import contextlib
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--threads", type=int, default=2, choices=range(1, 5))
    arguments = parser.parse_args()
    directory = Path(arguments.directory).resolve()
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    # All downloaded data are pinned and checksummed by setup_ai_embedding.py.
    with contextlib.redirect_stdout(sys.stderr):
        from fastembed import TextEmbedding
        from fastembed.common.model_description import ModelSource, PoolingType

        TextEmbedding.add_custom_model(
            model=manifest["model"],
            pooling=PoolingType.MEAN,
            normalization=True,
            sources=ModelSource(hf=manifest["repository"]),
            dim=384,
            model_file="onnx/model_quantized.onnx",
        )
        model = TextEmbedding(
            model_name=manifest["model"],
            specific_model_path=directory,
            threads=arguments.threads,
            providers=["CPUExecutionProvider"],
            local_files_only=True,
            enable_cpu_mem_arena=False,
        )
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request["texts"], list) or len(request["texts"]) > 64:
                raise ValueError("invalid bounded batch")
            prefix = "query: " if request.get("query") else "passage: "
            texts = [prefix + text[:6000] for text in request["texts"]]
            with contextlib.redirect_stdout(sys.stderr):
                vectors = [
                    vector.tolist() for vector in model.embed(texts, batch_size=8, parallel=None)
                ]
            output = {"vectors": vectors}
        except Exception as exception:
            output = {"error": type(exception).__name__}
        print(json.dumps(output, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()

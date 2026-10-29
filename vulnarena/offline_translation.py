"""Bounded CPU/CUDA translator for the Argos English → Chinese model.

Only CTranslate2 weights and SentencePiece vocabulary are loaded. No model Python
code is executed. Optional dependencies are installed with ``.[translation]``.
"""

import re
from functools import lru_cache
from pathlib import Path


class OfflineTranslator:
    def __init__(self, directory: str):
        import ctranslate2
        import sentencepiece

        root = Path(directory)
        self.tokenizer = sentencepiece.SentencePieceProcessor(
            model_file=str(root / "sentencepiece.model")
        )
        self.model_directory = str(root / "model")
        self.runtime = ctranslate2
        self.device = "cuda" if ctranslate2.get_cuda_device_count() else "cpu"
        try:
            self.model = self._model(self.device)
        except RuntimeError:
            self.device = "cpu"
            self.model = self._model("cpu")

    def _model(self, device):
        return self.runtime.Translator(
            self.model_directory,
            device=device,
            compute_type="float16" if device == "cuda" else "int8",
            inter_threads=1 if device == "cuda" else 2,
            intra_threads=4,
        )

    def translate(self, text: str) -> str:
        return self.translate_many([text])[0]

    def translate_many(
        self,
        texts: list[str],
        *,
        beam_size: int = 2,
        max_batch_size: int = 64,
        allow_partial: bool = False,
    ) -> list[str]:
        if not 1 <= max_batch_size <= 256 or beam_size not in {1, 2}:
            raise ValueError("invalid bounded translation batch options")
        segments = []
        positions = []
        output = []
        for text_index, text in enumerate(texts):
            lines = text.split("\n")
            output.append([""] * len(lines))
            in_code = False
            for index, line in enumerate(lines):
                if line.lstrip().startswith(("```", "~~~")):
                    in_code = not in_code
                    output[text_index][index] = line
                    continue
                # Kernel advisories also contain unfenced assembly, indented code,
                # and punctuation-only diagram lines. Keep those byte-for-byte;
                # translating an ellipsis can produce an empty model result.
                if (
                    in_code
                    or not re.search(r"[A-Za-z]", line)
                    or line.startswith(("\t", "    "))
                    or re.match(r"^\w+\|\s", line)
                    or re.fullmatch(r"[A-Za-z_][\w.]*:", line.strip())
                ):
                    output[text_index][index] = line
                    continue
                sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", line)
                for sentence in sentences:
                    tokens = self.tokenizer.encode(sentence, out_type=str)
                    for offset in range(0, len(tokens), 220):
                        segments.append(tokens[offset : offset + 220])
                        positions.append((text_index, index))

        def infer():
            return (
                self.model.translate_batch(
                    segments,
                    beam_size=beam_size,
                    no_repeat_ngram_size=3,
                    repetition_penalty=1.1,
                    max_batch_size=max_batch_size,
                    replace_unknowns=True,
                    max_input_length=0,
                    max_decoding_length=1024,
                    length_penalty=0.2,
                )
                if segments
                else []
            )

        try:
            results = infer()
        except RuntimeError:
            if self.device != "cuda":
                raise
            self.device = "cpu"
            self.model = self._model("cpu")
            results = infer()
        invalid = set()
        for (text_index, index), result in zip(positions, results, strict=True):
            tokens = result.hypotheses[0]
            if len(tokens) >= 1024:
                if allow_partial:
                    invalid.add(text_index)
                    continue
                raise ValueError("translation decoding limit reached")
            value = self.tokenizer.decode(tokens).replace("▁", " ").strip()
            if not value:
                if allow_partial:
                    invalid.add(text_index)
                    continue
                raise ValueError("empty offline translation")
            output[text_index][index] += value
        return ["" if index in invalid else "\n".join(lines) for index, lines in enumerate(output)]


@lru_cache(maxsize=1)
def load_translator(directory: str) -> OfflineTranslator:
    return OfflineTranslator(directory)

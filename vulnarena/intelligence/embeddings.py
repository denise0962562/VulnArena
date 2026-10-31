import asyncio
import json
import math
import os
import subprocess
import sys
from collections import OrderedDict, deque
from pathlib import Path

MODEL_ID = "multilingual-e5-small-int8@761b726dd34f"


class EmbeddingUnavailable(RuntimeError):
    pass


class CPUEncoder:
    model_name = MODEL_ID

    def __init__(self, settings):
        self.settings = settings
        self.process = None
        self.lock = asyncio.Lock()
        self.idle_task = None
        self.stderr_task = None
        self.diagnostics = deque(maxlen=12)
        self.query_cache = OrderedDict()

    @property
    def available(self):
        return (
            Path(self.settings.ai_embedding_directory, "manifest.json").is_file()
            and Path(self.settings.ai_embedding_python).is_file()
        )

    @property
    def loaded(self):
        return self.process is not None and self.process.returncode is None

    async def _start(self):
        if not self.available:
            raise EmbeddingUnavailable("请先运行 scripts/setup_ai_embedding.py 配置语义模型。")
        manifest_path = Path(self.settings.ai_embedding_directory, "manifest.json")
        manifest = json.loads(await asyncio.to_thread(manifest_path.read_text, encoding="utf-8"))
        if manifest.get("model") != MODEL_ID:
            raise EmbeddingUnavailable("语义模型目录版本不匹配，请重新运行模型配置脚本。")
        python = self.settings.ai_embedding_python
        python = python if await asyncio.to_thread(Path(python).is_file) else sys.executable
        environment = dict(os.environ)
        environment.update(
            TOKENIZERS_PARALLELISM="false",
            OMP_NUM_THREADS=str(self.settings.ai_embedding_threads),
            OPENBLAS_NUM_THREADS=str(self.settings.ai_embedding_threads),
            MKL_NUM_THREADS=str(self.settings.ai_embedding_threads),
            HF_HUB_OFFLINE="1",
            HF_HUB_DISABLE_PROGRESS_BARS="1",
            PYTHONIOENCODING="utf-8",
        )
        flags = (
            subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS
            if os.name == "nt"
            else 0
        )
        self.process = await asyncio.create_subprocess_exec(
            python,
            "-u",
            str(Path(__file__).with_name("embedding_worker.py")),
            "--directory",
            str(await asyncio.to_thread(Path(self.settings.ai_embedding_directory).resolve)),
            "--threads",
            str(self.settings.ai_embedding_threads),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
            creationflags=flags,
            limit=4 * 1024 * 1024,
        )

        async def drain(process):
            async for line in process.stderr:
                self.diagnostics.append(line.decode("utf-8", errors="replace")[:500])

        self.stderr_task = asyncio.create_task(drain(self.process))

    async def encode(self, texts: list[str], *, query=False) -> list[list[float]]:
        if not texts:
            return []
        if len(texts) > 32:
            output = []
            for offset in range(0, len(texts), 32):
                output.extend(await self.encode(texts[offset : offset + 32], query=query))
                await asyncio.sleep(self.settings.ai_index_pause)
            return output
        cache_key = texts[0] if query and len(texts) == 1 else None
        if cache_key and cache_key in self.query_cache:
            return [self.query_cache[cache_key]]
        async with self.lock:
            if self.idle_task:
                self.idle_task.cancel()
            if not self.loaded:
                await self._start()
            try:
                request = json.dumps({"texts": texts, "query": query}, ensure_ascii=True) + "\n"
                self.process.stdin.write(request.encode())
                await self.process.stdin.drain()
                line = await asyncio.wait_for(self.process.stdout.readline(), timeout=180)
                if not line:
                    raise EmbeddingUnavailable("CPU 语义模型进程退出，请检查独立推理环境。")
                response = json.loads(line)
                vectors = response.get("vectors")
                if response.get("error") or not vectors or len(vectors) != len(texts):
                    raise EmbeddingUnavailable("语义模型未返回完整向量。")
                if any(
                    len(vector) != 384 or not all(math.isfinite(v) for v in vector)
                    for vector in vectors
                ):
                    raise EmbeddingUnavailable("语义向量格式无效。")
            except asyncio.CancelledError:
                await self._stop()
                raise
            except (TimeoutError, OSError, ValueError, EmbeddingUnavailable) as exception:
                await self._stop()
                raise EmbeddingUnavailable("语义模型暂不可用，可先使用关键词检索。") from exception
            finally:
                self.idle_task = asyncio.create_task(self._unload_when_idle())
        if cache_key:
            self.query_cache[cache_key] = vectors[0]
            if len(self.query_cache) > 256:
                self.query_cache.popitem(last=False)
        return vectors

    async def _unload_when_idle(self):
        await asyncio.sleep(120)
        async with self.lock:
            await self._stop()

    async def _stop(self):
        process, self.process = self.process, None
        if process and process.returncode is None:
            process.terminate()
            await process.wait()
        if self.stderr_task:
            await asyncio.gather(self.stderr_task, return_exceptions=True)

    async def close(self):
        if self.idle_task:
            self.idle_task.cancel()
            await asyncio.gather(self.idle_task, return_exceptions=True)
        async with self.lock:
            await self._stop()

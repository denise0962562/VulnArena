"""Real local multilingual inference check; no model API requests."""

import asyncio
import json

from vulnarena.config import Settings
from vulnarena.intelligence.embeddings import CPUEncoder


async def main():
    encoder = CPUEncoder(Settings())
    try:
        documents = await encoder.encode(
            [
                "Apache Log4j JNDI message lookup allows remote code execution.",
                "A recipe for cooking rice and vegetables.",
            ]
        )
        query = (await encoder.encode(["Log4j 日志查找导致远程代码执行的漏洞"], query=True))[0]
        scores = [sum(x * y for x, y in zip(query, vector, strict=True)) for vector in documents]
        assert len(query) == 384 and scores[0] > scores[1], scores
        print(json.dumps({"dimensions": len(query), "scores": scores, "provider": "CPU"}))
    finally:
        await encoder.close()


if __name__ == "__main__":
    asyncio.run(main())

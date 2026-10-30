"""DeepSeek 异步客户端：重试、JSON 契约、预算上限、失败即降级。

设计原则：**AI 永远是可选项**。没有 key、超预算、返回不合契约——一律返回 None，
调用方走确定性路径，演练绝不会因为模型抽风而失败。
"""

import asyncio
import logging

import httpx
from pydantic import BaseModel, ValidationError

from vulnarena.config import Settings

logger = logging.getLogger(__name__)


class DeepSeekClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep=asyncio.sleep,
    ):
        self.settings = settings
        self.sleep = sleep
        self.api_key = settings.deepseek_api_key.get_secret_value()
        self.calls = 0
        self.http = httpx.AsyncClient(
            timeout=settings.arena_timeout,
            transport=transport,
            base_url=settings.deepseek_base_url,
            # 不继承系统/环境代理：代理对 github 有用，却会让 api.deepseek.com
            # 的 TLS 握手直接断开，客户端只按自己的配置出网。
            trust_env=False,
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
        )

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    @property
    def budget_left(self) -> int:
        return max(0, self.settings.arena_max_llm_calls - self.calls)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def json_chat(
        self, system: str, user: str, schema: type[BaseModel], *, max_tokens: int = 700
    ) -> BaseModel | None:
        """返回校验过的 Pydantic 对象；任何异常都不外抛，只返回 None。"""
        if not self.available or self.budget_left <= 0:
            return None
        body = {
            "model": self.settings.deepseek_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        for attempt in range(3):
            self.calls += 1
            try:
                response = await self.http.post("/chat/completions", json=body)
            except httpx.RequestError:
                await self.sleep(2**attempt)
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                await self.sleep(2**attempt)
                continue
            if response.status_code != 200:
                logger.warning("deepseek returned %s; falling back", response.status_code)
                return None
            try:
                content = response.json()["choices"][0]["message"]["content"]
                return schema.model_validate_json(content)
            except (KeyError, IndexError, TypeError, ValueError, ValidationError) as exc:
                logger.warning("deepseek payload rejected: %s", type(exc).__name__)
                return None
        return None

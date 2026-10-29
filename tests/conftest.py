import copy
import os
import socket
from pathlib import Path
from uuid import uuid4

import fakeredis.aioredis
import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from vulnarena.config import Settings
from vulnarena.db import Database
from vulnarena.main import create_app
from vulnarena.nvd import NVDClient, RateLimiter


def pytest_configure(config: pytest.Config) -> None:
    # pytest creates basetemp itself, but its parent must exist on a fresh checkout.
    (Path(config.rootpath) / ".tools" / "tmp").mkdir(parents=True, exist_ok=True)


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    original = socket.socket.connect

    def local_only(sock, address):
        if isinstance(address, tuple) and address[0] not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError("tests must not access external networks")
        return original(sock, address)

    monkeypatch.setattr(socket.socket, "connect", local_only)


@pytest.fixture
def settings():
    return Settings(_env_file=None)


@pytest_asyncio.fixture
async def database_settings(settings):
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set; PostgreSQL integration not executed")
    parsed = make_url(url)
    if parsed.drivername != "postgresql+asyncpg" or not parsed.database.endswith("_test"):
        raise ValueError("TEST_DATABASE_URL must name a dedicated PostgreSQL *_test database")
    schema = "vs_test_" + uuid4().hex
    admin = create_async_engine(url, connect_args={"timeout": 5}, hide_parameters=True)
    async with admin.begin() as connection:
        await connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    isolated = settings.model_copy(
        update={"database_url": SecretStr(url), "database_schema": schema}
    )
    try:
        yield isolated
    finally:
        async with admin.begin() as connection:
            await connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        await admin.dispose()


@pytest_asyncio.fixture
async def redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def db(database_settings):
    database = Database(
        database_settings.database_url.get_secret_value(), schema=database_settings.database_schema
    )
    await database.initialize()
    yield database
    await database.aclose()


@pytest.fixture
def raw_cve():
    return {
        "id": "CVE-2024-1234",
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00Z",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "Descripción"},
            {"lang": "en", "value": "Example vulnerability"},
        ],
        "references": [{"url": "https://example.org/advisory", "tags": ["Patch"]}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
        "futureField": {"preserve": True},
    }


@pytest.fixture
def envelope(raw_cve):
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-02-01T00:00:00.000",
        "vulnerabilities": [{"cve": copy.deepcopy(raw_cve)}],
    }


class Clock:
    def __init__(self):
        self.now = 100.0
        self.waits = []

    def time(self):
        return self.now

    async def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest_asyncio.fixture
async def api(database_settings, redis, envelope, clock):
    settings = database_settings
    nvd = NVDClient(
        settings,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=envelope)),
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
        sleep=clock.sleep,
    )
    app = create_app(settings, redis=redis, nvd=nvd)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client, app

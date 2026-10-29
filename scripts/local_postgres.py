"""Manage this workspace's portable PostgreSQL without elevation or a Windows service."""

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import socket
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import httpx
from dotenv import dotenv_values
from sqlalchemy.engine import URL

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT
BIN = ROOT / ".tools/postgresql/pgsql/bin"
DATA = ROOT / "data/postgresql"
CREDENTIALS = ROOT / "data/postgresql-local.json"
DOWNLOAD = "https://get.enterprisedb.com/postgresql/postgresql-18.6-5-windows-x64-binaries.zip"
ARCHIVE_SHA256 = "e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2"


def configure_paths() -> None:
    global RUNTIME, BIN, DATA
    if not str(ROOT).isascii():
        # EDB tools on Windows can misinterpret non-ASCII paths during UTF-8 initdb.
        # A directory junction keeps the actual files in the workspace.
        parent = Path(ROOT.anchor) / "VulnScopeRuntime"
        parent.mkdir(exist_ok=True)
        RUNTIME = parent / hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
        if not str(RUNTIME).isascii():
            raise RuntimeError("PostgreSQL runtime alias must have an ASCII path")
        if not RUNTIME.exists():
            subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "$ErrorActionPreference='Stop'; New-Item -ItemType Junction "
                    "-Path $env:VULNARENA_LINK_PATH -Target $env:VULNARENA_LINK_TARGET | Out-Null",
                ],
                env=dict(
                    os.environ, VULNARENA_LINK_PATH=str(RUNTIME), VULNARENA_LINK_TARGET=str(ROOT)
                ),
                check=True,
            )
        if RUNTIME.resolve() != ROOT:
            raise RuntimeError("Runtime alias points to another workspace; left unchanged")
        BIN = RUNTIME / ".tools/postgresql/pgsql/bin"
        DATA = RUNTIME / "data/postgresql"


def command(name: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([str(BIN / (name + ".exe")), *args], cwd=RUNTIME, check=check)


def install_binaries() -> None:
    if (BIN / "pg_ctl.exe").is_file():
        return
    archive = ROOT / ".tools/installers/postgresql-18.6-5-windows-x64-binaries.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        print("Downloading PostgreSQL 18.6 from EDB ...", flush=True)
        partial = archive.with_suffix(".zip.part")
        with httpx.stream("GET", DOWNLOAD, follow_redirects=True, timeout=90) as response:
            response.raise_for_status()
            with partial.open("wb") as output:
                for chunk in response.iter_bytes(1024 * 1024):
                    output.write(chunk)
        partial.replace(archive)
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != ARCHIVE_SHA256:
            raise ValueError("PostgreSQL archive does not match the pinned SHA-256")
    target = BIN.parents[1]
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            if entry.filename.startswith(("pgsql/bin/", "pgsql/lib/", "pgsql/share/")):
                if not (target / entry.filename).resolve().is_relative_to(target.resolve()):
                    raise ValueError("Archive entry outside install directory")
                bundle.extract(entry, target)


def start() -> None:
    if not (DATA / "PG_VERSION").is_file():
        raise RuntimeError("Run scripts\\postgres.cmd setup first")
    result = subprocess.run(
        [str(BIN / "pg_ctl.exe"), "-D", str(DATA), "status"],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        print("This workspace's PostgreSQL is already running.")
        return
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 5432)) == 0:
            raise RuntimeError("Port 5432 is occupied by another instance; no process was stopped")
    command("pg_ctl", "-D", str(DATA), "-l", str(RUNTIME / "data/postgresql.log"), "-w", "start")
    print("PostgreSQL started in background on 127.0.0.1:5432. Use postgres.cmd stop to stop it.")


async def create_databases(credentials: dict[str, str]) -> None:
    connection = await asyncpg.connect(
        host="127.0.0.1",
        port=5432,
        user="postgres",
        password=credentials["admin_password"],
        database="postgres",
        timeout=5,
    )
    try:
        for role, password_key in (
            ("vulnscope", "app_password"),
            ("vulnscope_test", "test_password"),
        ):
            exists = await connection.fetchval("SELECT 1 FROM pg_roles WHERE rolname=$1", role)
            password_literal = await connection.fetchval(
                "SELECT quote_literal($1::text)", credentials[password_key]
            )
            verb = "ALTER" if exists else "CREATE"
            await connection.execute(
                f'{verb} ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                f"PASSWORD {password_literal}"
            )
            owner = await connection.fetchval(
                "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1", role
            )
            if owner is None:
                await connection.execute(f'CREATE DATABASE "{role}" OWNER "{role}"')
            elif owner != role:
                raise RuntimeError(f"Existing database {role} has another owner; left unchanged")
            await connection.execute(f'REVOKE CONNECT ON DATABASE "{role}" FROM PUBLIC')
    finally:
        await connection.close()


def database_url(user: str, password: str) -> str:
    return URL.create(
        "postgresql+asyncpg",
        username=user,
        password=password,
        host="127.0.0.1",
        port=5432,
        database=user,
    ).render_as_string(hide_password=False)


def configure_env(credentials: dict[str, str]) -> None:
    path = ROOT / ".env"
    content = (
        path.read_text(encoding="utf-8-sig")
        if path.exists()
        else (ROOT / ".env.example").read_text(encoding="utf-8")
    )
    updates = {
        "VULNARENA_DATABASE_URL": database_url("vulnscope", credentials["app_password"]),
        "POSTGRES_PASSWORD": credentials["app_password"],
        "POSTGRES_ADMIN_PASSWORD": credentials["admin_password"],
        "TEST_DATABASE_URL": database_url("vulnscope_test", credentials["test_password"]),
    }
    lines = []
    for line in content.splitlines():
        key = line.split("=", 1)[0].strip()
        if key == "VULNARENA_DATABASE_PATH" or key in updates:
            continue
        lines.append(line)
    lines.extend(f"{key}={value}" for key, value in updates.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Local .env configured. Existing NVD/Redis settings preserved. No passwords printed.")


def setup() -> None:
    install_binaries()
    CREDENTIALS.parent.mkdir(exist_ok=True)
    if CREDENTIALS.exists():
        credentials = json.loads(CREDENTIALS.read_text(encoding="utf-8"))
    else:
        if (DATA / "PG_VERSION").exists():
            raise RuntimeError(
                "Cluster exists but its local credentials are missing; left unchanged"
            )
        credentials = {
            key: secrets.token_hex(24)
            for key in ("admin_password", "app_password", "test_password")
        }
        CREDENTIALS.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    if not (DATA / "PG_VERSION").exists():
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=RUNTIME / "data", delete=False
        ) as password:
            password.write(credentials["admin_password"] + "\n")
            password_file = Path(password.name)
        try:
            command(
                "initdb",
                "-D",
                str(DATA),
                "--username=postgres",
                "--encoding=UTF8",
                "--locale=C",
                "--auth=scram-sha-256",
                "--pwfile=" + str(password_file),
            )
        finally:
            password_file.unlink(missing_ok=True)
        with (DATA / "postgresql.conf").open("a", encoding="utf-8") as config:
            config.write(
                "\n# VulnArena local learning instance\nlisten_addresses = '127.0.0.1'\n"
                "port = 5432\ntimezone = 'UTC'\nmax_connections = 30\nshared_buffers = '64MB'\n"
            )
    start()
    asyncio.run(create_databases(credentials))
    configure_env(credentials)


def shell(*, test: bool = False) -> None:
    user = "vulnscope_test" if test else "vulnscope"
    credentials = json.loads(CREDENTIALS.read_text(encoding="utf-8"))
    key = "test_password" if test else "app_password"
    environment = dict(os.environ, PGPASSWORD=credentials[key])
    subprocess.run(
        [str(BIN / "psql.exe"), "-h", "127.0.0.1", "-p", "5432", "-U", user, "-d", user],
        env=environment,
        check=True,
    )


def backup() -> None:
    credentials = json.loads(CREDENTIALS.read_text(encoding="utf-8"))
    directory = ROOT / "data/backups"
    directory.mkdir(exist_ok=True)
    path = directory / ("vulnscope-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + ".dump")
    subprocess.run(
        [
            str(BIN / "pg_dump.exe"),
            "-h",
            "127.0.0.1",
            "-p",
            "5432",
            "-U",
            "vulnscope",
            "-d",
            "vulnscope",
            "--format=custom",
            "--file=" + str(path),
        ],
        env=dict(os.environ, PGPASSWORD=credentials["app_password"]),
        check=True,
    )
    print("PostgreSQL backup saved:", path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("setup", "start", "stop", "status", "shell", "backup", "test")
    )
    args = parser.parse_args()
    configure_paths()
    if args.action == "setup":
        setup()
    elif args.action == "start":
        start()
    elif args.action == "stop":
        command("pg_ctl", "-D", str(DATA), "-m", "fast", "-w", "stop")
    elif args.action == "status":
        command("pg_ctl", "-D", str(DATA), "status")
    elif args.action == "shell":
        shell()
    elif args.action == "backup":
        backup()
    else:
        # Child-only test configuration: no persistent changes to shell environment.
        values = dotenv_values(ROOT / ".env")
        environment = dict(os.environ)
        environment["TEST_DATABASE_URL"] = values["TEST_DATABASE_URL"]
        environment.setdefault("TEST_REDIS_URL", "redis://127.0.0.1:6380/15")
        raise SystemExit(
            subprocess.call(
                [str(ROOT / ".venv/Scripts/python.exe"), "-m", "pytest"],
                cwd=ROOT,
                env=environment,
            )
        )


if __name__ == "__main__":
    main()

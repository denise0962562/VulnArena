"""Bounded public advisory downloads and explicitly labelled machine translations.

Remote HTML/Markdown is stored as inert text; it is never executed or rendered as HTML.
"""

import asyncio
import copy
import hashlib
import io
import ipaddress
import json
import re
import socket
import time
import zipfile
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from vulnarena.db import Database
from vulnarena.offline_translation import load_translator
from vulnarena.schemas import Vulnerability
from vulnarena.study_contract import (
    description_fingerprint,
    record_fingerprint,
    study_matches,
    usable_chinese,
)
from vulnarena.topics import classify

USER_AGENT = "VulnArena-Learning/0.2 (local public vulnerability research)"
MAX_BYTES = 2_000_000
MAX_TEXT = 80_000
ALLOWED_DOMAINS = (
    "cveawg.mitre.org",
    "raw.githubusercontent.com",
    "api.github.com",
    "github.com",
    "kernel.org",
    "lore.kernel.org",
    "linux.org",
    "ubuntu.com",
    "debian.org",
    "redhat.com",
    "access.redhat.com",
    "suse.com",
    "microsoft.com",
    "msrc.microsoft.com",
    "python.org",
    "docs.djangoproject.com",
    "djangoproject.com",
    "palletsprojects.com",
    "php.net",
    "go.dev",
    "golang.org",
    "rustsec.org",
    "rust-lang.org",
    "apache.org",
    "openssl.org",
    "openwall.com",
    "curl.se",
    "gnu.org",
    "nginx.org",
    "nodejs.org",
    "wordpress.org",
    "drupal.org",
    "nvd.nist.gov",
    "security.snyk.io",
    "devco.re",
    "blog.orange.tw",
    "labs.watchtowr.com",
    "blog.qualys.com",
    "isc.sans.edu",
    "googleprojectzero.blogspot.com",
    "project-zero.issues.chromium.org",
)


class SourceError(Exception):
    pass


def allowed_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        return (
            parsed.scheme == "https"
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
            and any(host == domain or host.endswith("." + domain) for domain in ALLOWED_DOMAINS)
        )
    except ValueError:
        return False


class ArticleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []
        self.title = []
        self.in_title = False
        self.main_depth = 0
        self.main_parts = []
        self.anchors = {}
        self.headings = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in {"id", "name"} and value:
                self.anchors[value] = len(self.parts)
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append((len(self.parts), int(tag[1])))
        if tag in {"script", "style", "nav", "footer", "noscript", "svg"}:
            self.hidden += 1
        if tag == "title":
            self.in_title = True
        if tag in {"main", "article"}:
            self.main_depth += 1
        if tag in {"p", "br", "div", "li", "h1", "h2", "h3", "pre", "tr", "section"}:
            self.handle_data("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "nav", "footer", "noscript", "svg"}:
            self.hidden = max(0, self.hidden - 1)
        if tag == "title":
            self.in_title = False
        if tag in {"main", "article"}:
            self.main_depth = max(0, self.main_depth - 1)
        if tag in {"p", "div", "li", "pre", "tr", "section"}:
            self.handle_data("\n")

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)
        if not self.hidden:
            self.parts.append(data)
            if self.main_depth:
                self.main_parts.append(data)

    def result(self, fragment: str = ""):
        main = " ".join(self.main_parts)
        text = main if len(main.strip()) >= 150 else " ".join(self.parts)
        if fragment:
            start = self.anchors.get(unquote(fragment))
            if start is None:
                raise SourceError("linked article section not present in static HTML")
            before = [(position, level) for position, level in self.headings if position <= start]
            level = before[-1][1] if before else 6
            end = next((p for p, h in self.headings if p > start and h <= level), len(self.parts))
            text = " ".join(self.parts[start:end])
        text = re.sub(r"[^\S\n]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
        return " ".join(self.title).strip(), text


def weakness_ids(raw: dict) -> list[str]:
    return sorted(set(re.findall(r"CWE-\d+", json.dumps(raw.get("weaknesses", [])))))


def cpe_products(raw: dict) -> list[dict]:
    products = []

    def walk(value):
        if isinstance(value, dict):
            criteria = value.get("criteria")
            if value.get("vulnerable") is True and isinstance(criteria, str):
                parts = criteria.split(":")
                products.append(
                    {
                        "vendor": parts[3] if len(parts) > 3 else "",
                        "product": parts[4] if len(parts) > 4 else criteria,
                        "criteria": criteria,
                        **{k: v for k, v in value.items() if k.startswith("version")},
                    }
                )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(raw.get("configurations", []))
    return products[:200]


class StudyCollector:
    def __init__(
        self,
        db: Database,
        *,
        transport=None,
        translate: bool = True,
        translation_model: str = "",
        online_translation: bool = False,
    ):
        self.db = db
        self.translate_enabled = translate
        self.http = httpx.AsyncClient(
            timeout=25,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": USER_AGENT},
        )
        self.mock_transport = transport is not None
        self.robot_cache = {}
        self.last_host_request = {}
        self.translation_lock = asyncio.Lock()
        self.offline_slots = asyncio.Semaphore(2)
        self.translation_model = translation_model
        self.online_translation = online_translation
        self.online_blocked = False
        self.provider = (
            "Argos en-zh 1.9 / CTranslate2 (offline)"
            if translation_model
            else "Google Translate (gtx)"
        )

    async def aclose(self):
        await self.http.aclose()

    async def _save_current_description(self, record, text, status):
        if status == "complete" and usable_chinese(record.description, text):
            await self.db.save_chinese(
                [
                    {
                        "cve_id": record.cve_id,
                        "source_sha256": description_fingerprint(record.description),
                        "text_zh": text,
                        "provider": self.provider,
                        "translated_at": datetime.now(UTC),
                    }
                ]
            )

    async def _public_host(self, url):
        if not allowed_url(url):
            raise SourceError("domain outside public advisory allowlist")
        if not self.mock_transport:
            host = urlsplit(url).hostname
            addresses = await asyncio.to_thread(
                socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM
            )
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise SourceError("non-public network address blocked")

    async def download(self, url: str, *, robots: bool = True) -> tuple[str, str]:
        for _ in range(5):
            await self._public_host(url)
            parsed = urlsplit(url)
            origin = f"https://{parsed.hostname}"
            if robots and parsed.hostname not in {
                "raw.githubusercontent.com",
                "api.github.com",
                "cveawg.mitre.org",
            }:
                if origin not in self.robot_cache:
                    try:
                        _, body = await self.download(origin + "/robots.txt", robots=False)
                        parser = RobotFileParser()
                        parser.parse(body.splitlines())
                        self.robot_cache[origin] = parser
                    except SourceError as exc:
                        if "HTTP 404" not in str(exc):
                            raise SourceError("robots.txt unavailable; reference skipped") from exc
                        self.robot_cache[origin] = None
                parser = self.robot_cache[origin]
                if parser and not parser.can_fetch(USER_AGENT, url):
                    raise SourceError("robots.txt disallows download")
            delay = 0.6 - (time.monotonic() - self.last_host_request.get(origin, 0))
            if delay > 0 and not self.mock_transport:
                await asyncio.sleep(delay)
            self.last_host_request[origin] = time.monotonic()
            async with self.http.stream("GET", url) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    url = urljoin(url, response.headers.get("location", ""))
                    continue
                if response.status_code != 200:
                    raise SourceError(f"HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "").lower()
                if not any(kind in content_type for kind in ("text/", "json", "xml")):
                    raise SourceError("unsupported document type")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_BYTES:
                        raise SourceError("document exceeds 2 MB download limit")
                return content_type, data.decode(response.encoding or "utf-8", errors="replace")
        raise SourceError("too many redirects")

    async def translate(self, text: str) -> dict:
        if not text.strip():
            return {"status": "empty", "text": ""}
        if not self.translate_enabled:
            return {"status": "disabled", "text": ""}
        digest = hashlib.sha256((self.provider + ":en:zh-CN:v1:" + text).encode()).hexdigest()
        cached = await self.db.get_translation(digest)
        if cached and usable_chinese(text, cached):
            return {
                "status": "complete",
                "text": cached.replace("▁", " "),
                "provider": self.provider,
            }
        if self.translation_model:
            try:
                async with self.translation_lock:
                    model = await asyncio.to_thread(load_translator, self.translation_model)
                async with self.offline_slots:
                    result = await asyncio.to_thread(model.translate, text)
                if not usable_chinese(text, result):
                    raise ValueError("translation did not produce Chinese")
                await self.db.save_translation(digest, result)
                return {"status": "complete", "text": result, "provider": self.provider}
            except (ImportError, RuntimeError, OSError, ValueError):
                return {
                    "status": "failed",
                    "text": "",
                    "error": "offline model unavailable; install translation extra and model",
                }
        if not self.online_translation or self.online_blocked:
            return {"status": "disabled", "text": ""}
        # Retain paragraph order; incomplete output is never labelled complete.
        chunks = [text[i : i + 3000] for i in range(0, len(text), 3000)]
        translated = []
        try:
            for chunk in chunks:
                async with self.translation_lock:
                    response = await self.http.post(
                        "https://translate.googleapis.com/translate_a/single",
                        data={"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": chunk},
                    )
                    if response.status_code in {429, 302, 403}:
                        self.online_blocked = True
                    response.raise_for_status()
                    payload = response.json()
                    value = "".join(
                        part[0] for part in payload[0] if part and isinstance(part[0], str)
                    )
                    if not value.strip():
                        raise ValueError("empty translation")
                    translated.append(value)
                    if not self.mock_transport:
                        await asyncio.sleep(0.15)
            result = "\n".join(translated)
            await self.db.save_translation(digest, result)
            return {"status": "complete", "text": result, "provider": self.provider}
        except (httpx.HTTPError, ValueError, TypeError, IndexError):
            return {"status": "failed", "text": "", "error": "translation unavailable; retry later"}

    async def collect(
        self,
        record: Vulnerability,
        *,
        advisories: list | None = None,
        references: int = 2,
        force: bool = False,
    ) -> dict:
        previous = await self.db.get_study(record.cve_id)
        fingerprint = record_fingerprint(record)
        if not force and study_matches(record, previous) and previous.get("status") == "complete":
            await self._save_current_description(
                record, previous.get("description_zh", ""), previous.get("translation_status")
            )
            return previous
        if (
            not force
            and study_matches(record, previous)
            and previous.get("documents")
            and references == 0
        ):
            translated = await self.translate(record.description)
            previous["description_zh"] = translated["text"] or previous.get("description_zh", "")
            previous["translation_status"] = translated["status"]
            previous["translation_provider"] = self.provider
            await self._save_current_description(record, translated["text"], translated["status"])
            for doc in previous["documents"]:
                translated = await self.translate(doc["text_en"])
                doc["text_zh"] = translated["text"] or doc.get("text_zh", "")
                doc["translation_status"] = translated["status"]
                doc["translation_provider"] = self.provider
            previous["status"] = (
                "complete"
                if (
                    previous["translation_status"] == "complete"
                    and all(d["translation_status"] == "complete" for d in previous["documents"])
                    and not previous.get("errors")
                )
                else "partial"
            )
            await self.db.save_study(record.cve_id, previous)
            return previous
        docs = []
        errors = []
        affected = cpe_products(record.raw)
        weaknesses = weakness_ids(record.raw)
        title = record.cve_id
        cna_raw = None
        solutions = []
        year, number = record.cve_id.split("-")[1:]
        bucket = number[:-3] + "xxx"
        source_url = (
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
            f"{year}/{bucket}/{record.cve_id}.json"
        )
        try:
            try:
                _, body = await self.download(source_url)
            except (SourceError, httpx.HTTPError):
                source_url = f"https://cveawg.mitre.org/api/cve/{record.cve_id}"
                _, body = await self.download(source_url)
            cna_raw = json.loads(body)
            if cna_raw.get("cveMetadata", {}).get("cveId") != record.cve_id:
                raise SourceError("CVE source identifier mismatch")
            cna = cna_raw.get("containers", {}).get("cna", {})
            title = cna.get("title") or title
            if cna.get("affected"):
                affected = copy.deepcopy(cna["affected"])
            weaknesses = sorted(
                set(weaknesses + re.findall(r"CWE-\d+", json.dumps(cna.get("problemTypes", []))))
            )
            sections = []
            for key in (
                "descriptions",
                "impacts",
                "scenarios",
                "solutions",
                "workarounds",
                "exploits",
                "rejectedReasons",
            ):
                values = [
                    v.get("value", "")
                    for v in cna.get(key, [])
                    if isinstance(v, dict) and v.get("lang", "en").lower().startswith("en")
                ]
                if values:
                    sections.append(
                        (key.upper() + "\n" if key != "descriptions" else "") + "\n\n".join(values)
                    )
                    if key in {"solutions", "workarounds"}:
                        solutions.extend(values)
            if sections:
                docs.append(
                    {
                        "title": title,
                        "source": "CVE CNA",
                        "url": source_url,
                        "text_en": "\n\n".join(sections),
                    }
                )
        except (SourceError, httpx.HTTPError, OSError, ValueError, TypeError, AttributeError):
            errors.append({"url": source_url, "error": "CVE CNA source unavailable or invalid"})

        provided_advisories = advisories is not None
        advisories = list(advisories or [])
        known_ghsa = set(
            re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", json.dumps(advisories))
        )
        if not provided_advisories or references:
            ghsa_ids = sorted(
                set(
                    re.findall(
                        r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", json.dumps(record.references)
                    )
                )
            )
            for ghsa in ghsa_ids[:2]:
                if ghsa in known_ghsa:
                    continue
                url = f"https://api.github.com/advisories/{ghsa}"
                try:
                    _, body = await self.download(url)
                    advisory = json.loads(body)
                    if advisory.get("cve_id") == record.cve_id:
                        advisories.append(advisory)
                except (SourceError, httpx.HTTPError, ValueError, AttributeError):
                    errors.append({"url": url, "error": "GitHub advisory unavailable"})
        for advisory in advisories[:3]:
            if advisory.get("cve_id") != record.cve_id:
                continue
            summary = advisory.get("summary") or ""
            if summary and len(summary) < 200:
                title = summary
            docs.append(
                {
                    "title": title,
                    "source": "GitHub Advisory",
                    "url": advisory.get("html_url", ""),
                    "text_en": advisory.get("description") or advisory.get("summary") or "",
                }
            )
            for v in advisory.get("vulnerabilities", []):
                affected.append(
                    {
                        "vendor": v.get("package", {}).get("ecosystem", ""),
                        "product": v.get("package", {}).get("name", ""),
                        "range": v.get("vulnerable_version_range"),
                        "fixed": v.get("first_patched_version"),
                    }
                )
            weaknesses.extend(v.get("cwe_id", "") for v in advisory.get("cwes", []))

        candidates = sorted(
            record.references,
            key=lambda r: (
                not bool(set(r.get("tags", [])) & {"Vendor Advisory", "Patch", "Mitigation"})
            ),
        )
        attempted = 0
        seen = set()
        seen_hosts = set()
        for reference in candidates:
            url = reference.get("url", "")
            if attempted >= references:
                break
            if not allowed_url(url) or "github.com" in url or "nvd.nist.gov" in url:
                continue
            if url in seen:
                continue
            seen.add(url)
            host = urlsplit(url).hostname
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            attempted += 1
            try:
                content_type, body = await self.download(url)
                if "html" in content_type:
                    parser = ArticleParser()
                    parser.feed(body)
                    doc_title, text = parser.result(urlsplit(url).fragment)
                else:
                    doc_title, text = urlsplit(url).path.split("/")[-1], body
                if len(text.strip()) < 150:
                    raise SourceError("no static article body (may require JavaScript)")
                docs.append(
                    {"title": doc_title or url, "source": "参考公告", "url": url, "text_en": text}
                )
            except (SourceError, httpx.HTTPError, OSError, ValueError) as exc:
                errors.append(
                    {
                        "url": url,
                        "error": str(exc)
                        if isinstance(exc, SourceError)
                        else "reference network unavailable",
                    }
                )

        if not docs and record.description:
            docs.append(
                {
                    "title": "仅 NVD 摘要（未获取到完整公告）",
                    "source": "NVD 摘要",
                    "url": f"https://nvd.nist.gov/vuln/detail/{record.cve_id}",
                    "text_en": record.description,
                }
            )
        # Commit downloaded originals before potentially slow inference. A cancelled API
        # task must not lose already downloaded learning material.
        checkpoint = {
            "title": title,
            "description_zh": previous.get("description_zh", "")
            if study_matches(record, previous)
            else "",
            "translation_status": "pending",
            "translation_provider": self.provider,
            "topics": classify(record.description + " " + title) or ["其他"],
            "weaknesses": sorted(set(filter(None, weaknesses))),
            "affected": affected,
            "solutions": solutions,
            "documents": docs,
            "document_count": len(docs),
            "cna_raw": cna_raw,
            "github_raw": advisories,
            "fingerprint": fingerprint,
            "status": "partial",
            "fetched_at": datetime.now(UTC).isoformat(),
            "errors": errors,
        }
        for doc in docs:
            doc["truncated"] = len(doc["text_en"]) > MAX_TEXT
            doc["text_en"] = doc["text_en"][:MAX_TEXT]
            doc["translation_status"] = "pending"
        await self.db.save_study(record.cve_id, checkpoint)
        description_translation = await self.translate(record.description)
        await self._save_current_description(
            record, description_translation["text"], description_translation["status"]
        )
        checkpoint["description_zh"] = description_translation["text"]
        checkpoint["translation_status"] = description_translation["status"]
        await self.db.save_study(record.cve_id, checkpoint)
        for doc in docs:
            doc["sha256"] = hashlib.sha256(doc["text_en"].encode()).hexdigest()
            translation = await self.translate(doc["text_en"])
            doc["text_zh"] = translation["text"]
            doc["translation_status"] = translation["status"]
            doc["translation_provider"] = self.provider
            doc["fetched_at"] = datetime.now(UTC).isoformat()
        topics = classify(
            " ".join([record.description, title, json.dumps(affected, ensure_ascii=False)])
        )
        all_translated = description_translation["status"] in {"complete", "empty"} and all(
            d["translation_status"] in {"complete", "empty"} for d in docs
        )
        content = {
            "title": title,
            "description_zh": description_translation["text"],
            "translation_status": description_translation["status"],
            "translation_provider": self.provider,
            "topics": topics or ["其他"],
            "weaknesses": sorted(set(filter(None, weaknesses))),
            "affected": affected,
            "solutions": solutions,
            "documents": docs,
            "document_count": len(docs),
            "cna_raw": cna_raw,
            "github_raw": advisories,
            "fetched_at": datetime.now(UTC).isoformat(),
            "fingerprint": fingerprint,
            "status": "complete" if all_translated and not errors and docs else "partial",
            "errors": errors,
        }
        # Keep previous successful translations/documents when an upstream temporarily fails.
        if (
            not content["description_zh"]
            and previous.get("description_zh")
            and previous.get("fingerprint") == fingerprint
        ):
            content["description_zh"] = previous["description_zh"]
            content["translation_status"] = previous.get("translation_status", "complete")
        if not docs and previous.get("documents"):
            content["documents"] = previous["documents"]
            content["document_count"] = len(previous["documents"])
        await self.db.save_study(record.cve_id, content)
        return content


def study_bundle(record: Vulnerability, study: dict) -> bytes:
    """Portable UTF-8 bundle; fixed filenames never depend on upstream titles or paths."""
    output = io.BytesIO()
    study = {**study, "stale": not study_matches(record, study)}
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("record.json", record.model_dump_json(indent=2))
        archive.writestr("study.json", json.dumps(study, ensure_ascii=False, indent=2))
        source = (
            record.raw.get("advisory", {}).get("html_url")
            if record.raw.get("source") == "GitHub Advisory"
            else f"https://nvd.nist.gov/vuln/detail/{record.cve_id}"
        )
        overview = (
            f"# {record.cve_id} — {study.get('title', '')}\n\n"
            f"## English original\n\n{record.description}\n\n"
            f"## 中文机器翻译\n\n{study.get('description_zh') or '暂未获取翻译'}\n\n"
            f"CVSS: {record.cvss_score} / 10\n\n"
            f"Source: {source}\n\n"
            "机器翻译仅作学习辅助；版本范围与修复信息以原文为准。\n"
        )
        archive.writestr("README.md", overview)
        if study["stale"]:
            archive.writestr(
                "SOURCE-UPDATED.txt", "原始记录已更新，请核对各篇公告的采集时间与版本信息。"
            )
        for index, doc in enumerate(study.get("documents", []), 1):
            header = f"# {doc.get('title', '')}\n\nSource: {doc.get('url', '')}\n\n"
            archive.writestr(f"articles/{index:02d}.en.md", header + doc.get("text_en", ""))
            archive.writestr(
                f"articles/{index:02d}.zh.md", header + (doc.get("text_zh") or "暂未获取翻译")
            )
    return output.getvalue()

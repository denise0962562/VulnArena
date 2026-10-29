import hashlib
import json
import re

from vulnarena.schemas import Vulnerability


def record_fingerprint(record: Vulnerability) -> str:
    serialized = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, ensure_ascii=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def study_matches(record: Vulnerability, study: dict) -> bool:
    fingerprint = study.get("fingerprint")
    # Older/imported study documents may not carry a source fingerprint.
    return not fingerprint or fingerprint in {
        record_fingerprint(record),
        hashlib.sha256(record.model_dump_json().encode()).hexdigest(),
    }


def description_fingerprint(description: str) -> str:
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def usable_chinese(source: str, translated: str) -> bool:
    return bool(translated.strip()) and (
        bool(re.search(r"[\u3400-\u9fff]", translated)) or not re.search(r"[A-Za-z]{3}", source)
    )


def merge_description(record: Vulnerability, study: dict, translated: dict | None) -> dict:
    result = dict(study)
    result["stale"] = not study_matches(record, study)
    result["description_stale"] = result["stale"]
    if result.get("description_zh") and not usable_chinese(
        record.description, result["description_zh"]
    ):
        result.pop("description_zh", None)
        result["translation_status"] = "missing"
    if (
        translated
        and translated.get("source_sha256") == description_fingerprint(record.description)
        and translated.get("text_zh")
    ):
        result.update(
            description_zh=translated["text_zh"],
            translation_status="complete",
            translation_provider=translated["provider"],
            description_stale=False,
            description_translated_at=translated["translated_at"],
        )
    return result

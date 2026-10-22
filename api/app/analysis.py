import hashlib
import io
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image, ImageOps

from app.evidence import EVIDENCE_DIR
from app.models import AnalysisRun, CaseEntityLink, CorrelationEntity, EntityMention, Evidence

LANGUAGE_CUES = {
    "secrecy": (
        r"\bkeep (?:this|our )?conversation (?:a )?(?:secret|private)\b",
        r"\bkeep it (?:a )?secret\b",
        r"\bdon't tell (?:anyone|them)\b",
    ),
    "isolation": (r"\b(?:just|only) (?:the two of us|between us)\b", r"\bmove (?:this|our chat) to (?:a )?private\b"),
    "trust_pressure": (r"\byou can trust me\b", r"\bprove you trust me\b"),
    "urgency_pressure": (r"\bdon't waste time\b", r"\bdo (?:it|this) right now\b"),
    "boundary_pressure": (r"\byou owe me\b", r"\bdon't be difficult\b"),
}
ENTITY_PATTERNS = {
    "username": re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{2,31})"),
    "wallet": re.compile(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE),
    "invite_link": re.compile(r"\bhttps?://(?:t\.me/joinchat/|discord\.gg/)[^\s<>\"']+", re.IGNORECASE),
}
KNOWN_HASH_FILE = Path(__file__).with_name("known_hashes.json")


def load_local_hash_list(path: Path = KNOWN_HASH_FILE) -> dict[str, str]:
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(f"Local synthetic hash list is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Local synthetic hash list is invalid JSON: {path}") from error
    if not isinstance(records, list):
        raise RuntimeError("Local synthetic hash list must be a JSON array")
    hashes: dict[str, str] = {}
    for row in records:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
            or row.get("label") != "harmless_synthetic_fixture"
        ):
            raise RuntimeError("Hash list rows must contain a SHA-256 and harmless synthetic fixture label")
        hashes[row["sha256"]] = row["label"]
    return hashes


KNOWN_BENIGN_HASHES = load_local_hash_list()


def _text_from_export(payload: dict) -> tuple[str, list[dict]]:
    messages = payload.get("messages", [])
    if not isinstance(messages, list):
        return "", []
    normalized: list[dict] = []
    texts: list[str] = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        text = item.get("text", "")
        if isinstance(text, list):
            text = " ".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in text)
        if not isinstance(text, str):
            continue
        sender = item.get("from", item.get("sender", "unknown"))
        date = item.get("date", item.get("timestamp"))
        normalized.append({"sender": str(sender)[:128], "date": str(date) if date else None, "text": text[:20_000]})
        texts.append(text)
    return "\n".join(texts), normalized


def analyze_language(text: str) -> dict:
    lowered = text.lower()
    matched = []
    for category, patterns in LANGUAGE_CUES.items():
        examples = [pattern for pattern in patterns if re.search(pattern, lowered, re.IGNORECASE)]
        if examples:
            matched.append({"category": category, "cue_count": len(examples)})
    entities: dict[str, list[str]] = {}
    for entity_type, pattern in ENTITY_PATTERNS.items():
        values: set[str] = set()
        for match in pattern.finditer(text):
            value = f"@{match.group(1)}" if entity_type == "username" else match.group(0).rstrip(".,);]")
            if entity_type in {"url", "invite_link"}:
                parsed = urlparse(value)
                if parsed.scheme not in {"http", "https"}:
                    continue
            values.add(value)
        entities[entity_type] = sorted(values, key=str.casefold)
    token_count = len(re.findall(r"\b[\w']+\b", text))
    stop_words = {
        "about", "after", "again", "also", "been", "before", "being", "could",
        "from", "have", "here", "into", "just", "more", "only", "other", "over",
        "some", "than", "that", "their", "them", "then", "there", "these", "they",
        "this", "through", "very", "were", "what", "when", "where", "which", "with",
        "would", "your", "you", "the", "and", "for", "are", "was", "but", "not",
    }
    frequencies = Counter(
        word.casefold()
        for word in re.findall(r"\b[a-zA-Z][a-zA-Z'-]{3,}\b", text)
        if word.casefold() not in stop_words
    )
    return {
        "status": "complete",
        "method": "transparent phrase-pattern cues; not a classifier",
        "message_count": 0,
        "token_count": token_count,
        "language_cue_categories": matched,
        "cue_category_count": len(matched),
        "keywords": [{"term": word, "count": count} for word, count in frequencies.most_common(12)],
        "entities": entities,
        "review_note": "Cues are contextual review prompts, not conclusions about intent or a person.",
    }


def analyze_behavior(messages: list[dict]) -> dict:
    senders = Counter(message["sender"] for message in messages)
    dated = []
    for message in messages:
        date_value = message.get("date")
        if not date_value:
            continue
        try:
            dated.append(datetime.fromisoformat(date_value.replace("Z", "+00:00")))
        except ValueError:
            continue
    dated.sort()
    elapsed_hours = (
        max((dated[-1] - dated[0]).total_seconds() / 3600, 0)
        if len(dated) > 1
        else 0
    )
    return {
        "status": "complete",
        "message_count": len(messages),
        "distinct_senders": len(senders),
        "repeated_senders": [
            {"sender": sender, "message_count": count}
            for sender, count in senders.most_common()
            if count > 1
        ],
        "observed_span_hours": round(elapsed_hours, 2),
        "messages_per_hour": round(len(messages) / elapsed_hours, 2) if elapsed_hours else None,
        "source": "uploaded JSON export only",
    }


def _perceptual_hash(image_source: Path | bytes) -> tuple[str, int, int, str]:
    source_stream = io.BytesIO(image_source) if isinstance(image_source, bytes) else image_source
    with Image.open(source_stream) as source:
        image = ImageOps.exif_transpose(source)
        width, height = image.size
        if width * height > 20_000_000:
            raise ValueError("Image dimensions exceed the 20-megapixel local analysis limit")
        mode = image.mode
        pixels = list(image.convert("L").resize((9, 8), Image.Resampling.LANCZOS).getdata())
    bits = [pixels[row * 9 + col] > pixels[row * 9 + col + 1] for row in range(8) for col in range(8)]
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:016x}", width, height, mode


def _run_ocr(image_source: Path | bytes) -> dict:
    try:
        import pytesseract
    except ImportError:
        return {
            "status": "not_installed",
            "message": "Optional OCR dependency is absent; no text was inferred.",
        }
    try:
        source_stream = io.BytesIO(image_source) if isinstance(image_source, bytes) else image_source
        with Image.open(source_stream) as source:
            text = pytesseract.image_to_string(source.convert("RGB"), timeout=10).strip()
    except pytesseract.TesseractNotFoundError:
        return {
            "status": "engine_unavailable",
            "message": "Tesseract OCR executable is not installed/configured; no text was inferred.",
        }
    except RuntimeError as error:
        return {"status": "failed", "message": f"OCR failed: {error}"}
    return {
        "status": "complete",
        "text": text[:5000],
        "message": "OCR output is extracted text only and requires investigator review.",
    }


def _hamming_distance(first: str, second: str) -> int:
    return (int(first, 16) ^ int(second, 16)).bit_count()


def _persist_entities(db, case_id: int, evidence: Evidence, entities: dict[str, list[str]]) -> None:
    for entity_type, values in entities.items():
        for display_value in values:
            normalized = display_value.casefold()
            entity = (
                db.query(CorrelationEntity)
                .filter(
                    CorrelationEntity.entity_type == entity_type,
                    CorrelationEntity.normalized_value == normalized,
                )
                .first()
            )
            if entity is None:
                entity = CorrelationEntity(
                    entity_type=entity_type,
                    normalized_value=normalized,
                    display_value=display_value[:512],
                )
                db.add(entity)
                db.flush()
            mention = (
                db.query(EntityMention)
                .filter_by(entity_id=entity.id, case_id=case_id, evidence_id=evidence.id)
                .first()
            )
            if mention is None:
                db.add(EntityMention(entity_id=entity.id, case_id=case_id, evidence_id=evidence.id))
            case_link = (
                db.query(CaseEntityLink)
                .filter_by(case_id=case_id, entity_id=entity.id)
                .first()
            )
            if case_link is None:
                db.add(CaseEntityLink(case_id=case_id, entity_id=entity.id))


def analyze_evidence(
    db,
    evidence: Evidence,
    previous_runs: list[AnalysisRun],
    evidence_content: bytes | None = None,
) -> dict:
    result: dict = {
        "evidence": {
            "id": evidence.id,
            "filename": evidence.original_filename,
            "sha256": evidence.sha256,
            "media_type": evidence.media_type,
            "size_bytes": evidence.size_bytes,
        },
        "visual": {"status": "not_applicable"},
        "language": {"status": "not_applicable"},
        "behavior": {"status": "not_applicable"},
        "known_hash": {
            "status": "complete",
            "match": KNOWN_BENIGN_HASHES.get(evidence.sha256),
            "source": "local harmless synthetic fixture list",
        },
    }
    content = evidence_content
    path = EVIDENCE_DIR / evidence.storage_key
    entities: dict[str, list[str]] = {}
    text = ""
    messages = []
    if evidence.media_type == "application/json":
        try:
            if content is None:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
            else:
                payload = json.loads(content.decode("utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"Uploaded JSON evidence is no longer readable: {error}") from error
        if not isinstance(payload, dict):
            raise ValueError("Uploaded JSON export must contain an object at its root")
        text, messages = _text_from_export(payload)
        sender_context = "\n".join(message["sender"] for message in messages)
        result["language"] = analyze_language(f"{text}\n{sender_context}")
        result["language"]["message_count"] = len(messages)
        result["behavior"] = analyze_behavior(messages)
        entities = result["language"]["entities"]
    elif evidence.media_type.startswith("image/"):
        try:
            visual_hash, width, height, mode = _perceptual_hash(content if content is not None else path)
        except (OSError, ValueError) as error:
            raise ValueError(f"Uploaded image could not be decoded: {error}") from error
        duplicates = []
        for run in previous_runs:
            try:
                old = json.loads(run.signals_json).get("visual", {})
            except json.JSONDecodeError:
                continue
            old_hash = old.get("perceptual_hash")
            if old_hash:
                distance = _hamming_distance(visual_hash, old_hash)
                if distance <= 6:
                    duplicates.append(
                        {
                            "analysis_id": run.id,
                            "case_id": run.case_id,
                            "distance": distance,
                            "match": "exact" if distance == 0 else "near_duplicate",
                        }
                    )
        result["visual"] = {
            "status": "complete",
            "perceptual_hash": visual_hash,
            "width": width,
            "height": height,
            "mode": mode,
            "duplicate_candidates": duplicates,
            "ocr": _run_ocr(content if content is not None else path),
            "scope": "non-identifying image metadata and duplicate matching only",
        }
    elif evidence.media_type.startswith("audio/"):
        result["voice"] = {
            "status": "not_configured",
            "message": "Speech-to-text model is not configured; no speaker attributes are inferred.",
        }

    if entities:
        _persist_entities(db, evidence.case_id, evidence, entities)
    return result

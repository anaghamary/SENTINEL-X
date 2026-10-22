import hashlib
import json
import os
import re
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, UploadFile, status

from app.config import EVIDENCE_ENCRYPTION_KEY

MAX_EVIDENCE_BYTES = 15 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", Path(__file__).resolve().parents[1] / "evidence_store"))
ENCRYPTED_PREFIX = b"SENTINEL-X-ENC-1:"

_EXTENSIONS = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".wav": "audio/wav",
    ".mp3": "audio/mpeg",
    ".json": "application/json",
}


def safe_filename(filename: str | None) -> str:
    name = (filename or "").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)[:255]
    if not name or name in {".", ".."}:
        raise HTTPException(status_code=400, detail="A valid filename is required")
    return name


def verify_file_signature(content: bytes, extension: str, media_type: str) -> None:
    head = content[:16]
    valid = False
    if extension == ".png":
        valid = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif extension in {".jpg", ".jpeg"}:
        valid = head.startswith(b"\xff\xd8\xff")
    elif extension == ".webp":
        valid = head.startswith(b"RIFF") and head[8:12] == b"WEBP"
    elif extension == ".wav":
        valid = head.startswith(b"RIFF") and head[8:12] == b"WAVE"
    elif extension == ".mp3":
        valid = head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0)
    elif extension == ".json":
        try:
            payload = json.loads(content.decode("utf-8-sig"))
            valid = isinstance(payload, dict)
        except (UnicodeDecodeError, json.JSONDecodeError):
            valid = False
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File content does not match an accepted benign image, audio, or JSON export format",
        )


async def stage_upload(upload: UploadFile) -> tuple[bytes, str, str, int, str]:
    filename = safe_filename(upload.filename)
    extension = Path(filename).suffix.lower()
    expected_type = _EXTENSIONS.get(extension)
    if expected_type is None:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Accepted formats: PNG, JPEG, WebP, WAV, MP3, and JSON exports",
        )
    if upload.content_type not in {expected_type, "application/octet-stream"}:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Declared file type does not match the filename format",
        )

    digest = hashlib.sha256()
    size = 0
    content = bytearray()
    while chunk := await upload.read(CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_EVIDENCE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence must be {MAX_EVIDENCE_BYTES // (1024 * 1024)} MiB or smaller",
            )
        digest.update(chunk)
        content.extend(chunk)
    if size == 0:
        raise HTTPException(status_code=400, detail="Empty evidence files are not accepted")
    content_bytes = bytes(content)
    verify_file_signature(content_bytes, extension, expected_type)
    return content_bytes, filename, expected_type, size, digest.hexdigest()


def commit_upload(content: bytes, original_filename: str) -> str:
    extension = Path(original_filename).suffix.lower()
    storage_key = f"{uuid4().hex}{extension}"
    store_evidence_bytes(storage_key, content)
    return storage_key


def evidence_path(storage_key: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}\.[a-z]+", storage_key):
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return EVIDENCE_DIR / storage_key


def _fernet() -> Fernet:
    if not EVIDENCE_ENCRYPTION_KEY:
        raise RuntimeError(
            "Evidence encryption is not configured. Set EVIDENCE_ENCRYPTION_KEY before uploading evidence."
        )
    try:
        return Fernet(EVIDENCE_ENCRYPTION_KEY.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise RuntimeError("EVIDENCE_ENCRYPTION_KEY must be a valid Fernet URL-safe base64 key") from error


def ensure_evidence_encryption() -> None:
    _fernet()


def evidence_encryption_enabled() -> bool:
    try:
        _fernet()
    except RuntimeError:
        return False
    return True


def store_evidence_bytes(storage_key: str, content: bytes) -> None:
    encrypted = ENCRYPTED_PREFIX + _fernet().encrypt(content)
    path = evidence_path(storage_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.part")
    try:
        temporary.write_bytes(encrypted)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_evidence_bytes(storage_key: str, expected_sha256: str | None = None) -> bytes:
    try:
        stored = evidence_path(storage_key).read_bytes()
    except FileNotFoundError as error:
        raise FileNotFoundError("Evidence file is unavailable") from error
    if not stored.startswith(ENCRYPTED_PREFIX):
        content = stored
    else:
        try:
            content = _fernet().decrypt(stored[len(ENCRYPTED_PREFIX) :])
        except InvalidToken as error:
            raise RuntimeError("Evidence decryption failed; verify the configured encryption key") from error
    if expected_sha256 and hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("Evidence SHA-256 integrity verification failed")
    return content

import logging as stdlib_logging
import re
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_VALUE = "[REDACTED]"
MAX_COLLECTION_ITEMS = 100
MAX_TEXT_LENGTH = 500
SENSITIVE_KEY_FRAGMENTS = frozenset(
    {
        "password",
        "passwd",
        "otp",
        "sid",
        "session",
        "synotoken",
        "token",
        "cookie",
        "authorization",
        "x_syno_token",
        "x_syno_hash",
        "hash",
        "ssid",
    }
)
SENSITIVE_HEADER_PATTERN = re.compile(
    r"(?im)(authorization|cookie|x-syno-token|x-syno-hash|_ssid)\s*:\s*[^\r\n]+"
)
SENSITIVE_PAIR_PATTERN = re.compile(
    r"(?ix)[\"']?(password|passwd|otp_code|_?sid|session(?:[_-]?id)?|synotoken|token|cookie|authorization|x-syno-token|x-syno-hash|hash|_ssid)[\"']?\s*(?:=|:)\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^,\s&;}\]]+)"
)


def configure_logging(
    verbose: bool,
    *,
    stream: TextIO = sys.stderr,
) -> stdlib_logging.Logger:
    logger = stdlib_logging.getLogger("synology")
    logger.handlers.clear()
    logger.setLevel(stdlib_logging.DEBUG if verbose else stdlib_logging.INFO)
    handler = stdlib_logging.StreamHandler(stream)
    handler.setLevel(stdlib_logging.DEBUG)
    handler.setFormatter(stdlib_logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def sanitize(value: object, *, key: str | None = None) -> object:
    if key is not None and _is_sensitive_key(key):
        return REDACTED_VALUE
    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        for index, (entry_key, entry_value) in enumerate(value.items()):
            if index >= MAX_COLLECTION_ITEMS:
                sanitized["truncated"] = "[TRUNCATED]"
                break
            key_text = str(entry_key)
            sanitized[key_text] = sanitize(entry_value, key=key_text)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sanitized_items: list[object] = []
        for index, item in enumerate(value):
            if index >= MAX_COLLECTION_ITEMS:
                sanitized_items.append("[TRUNCATED]")
                break
            sanitized_items.append(sanitize(item, key=key))
        return sanitized_items
    if isinstance(value, bytes):
        return _sanitize_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, str):
        return _sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def _sanitize_text(value: str) -> str:
    sanitized_url = _sanitize_url(value)
    sanitized_headers = SENSITIVE_HEADER_PATTERN.sub(
        lambda match: f"{match.group(1)}: {REDACTED_VALUE}",
        sanitized_url,
    )
    sanitized_pairs = SENSITIVE_PAIR_PATTERN.sub(
        lambda match: f"{match.group(1)}={REDACTED_VALUE}",
        sanitized_headers,
    )
    return sanitized_pairs[:MAX_TEXT_LENGTH]


def _sanitize_url(value: str) -> str:
    parsed = urlsplit(value)
    netloc = parsed.netloc
    if "@" in netloc:
        _, host = netloc.rsplit("@", maxsplit=1)
        netloc = f"{REDACTED_VALUE}@{host}"
    if not parsed.query and netloc == parsed.netloc:
        return value
    query = parse_qsl(parsed.query, keep_blank_values=True)
    sanitized_query = [
        (name, REDACTED_VALUE if _is_sensitive_key(name) else item)
        for name, item in query
    ]
    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            urlencode(sanitized_query),
            parsed.fragment,
        )
    )

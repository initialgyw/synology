from io import StringIO

from synology.logging import REDACTED_VALUE, configure_logging, sanitize


def test_sanitize_redacts_nested_credentials_headers_and_urls() -> None:
    value = {
        "password": "password-secret",
        "tokens": ["sequence-token-secret"],
        "nested": {"X-SYNO-TOKEN": "token-secret", "session_id": "session-secret"},
        "headers": [
            "Authorization: Bearer authorization-secret",
            "Cookie: cookie-secret",
        ],
        "url": "https://nas.example.test/webapi?token=url-secret&safe=value",
        "url_with_credentials": "https://user:embedded-secret@nas.example.test/webapi",
    }

    rendered = str(sanitize(value))

    assert "password-secret" not in rendered
    assert "sequence-token-secret" not in rendered
    assert "token-secret" not in rendered
    assert "session-secret" not in rendered
    assert "authorization-secret" not in rendered
    assert "cookie-secret" not in rendered
    assert "url-secret" not in rendered
    assert "embedded-secret" not in rendered
    assert REDACTED_VALUE in rendered
    assert "safe" in rendered


def test_configured_logger_uses_only_requested_debug_level() -> None:
    quiet_stream = StringIO()
    quiet_logger = configure_logging(False, stream=quiet_stream)
    quiet_logger.debug("hidden diagnostic")
    quiet_logger.warning("visible warning")

    assert "hidden diagnostic" not in quiet_stream.getvalue()
    assert "visible warning" in quiet_stream.getvalue()

    verbose_stream = StringIO()
    verbose_logger = configure_logging(True, stream=verbose_stream)
    verbose_logger.debug("payload=%s", sanitize({"passwd": "secret"}))

    assert "DEBUG: payload=" in verbose_stream.getvalue()
    assert "secret" not in verbose_stream.getvalue()
    assert REDACTED_VALUE in verbose_stream.getvalue()

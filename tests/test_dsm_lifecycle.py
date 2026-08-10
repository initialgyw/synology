from __future__ import annotations

import pytest

from synology_manager.dsm import Credentials, DsmClient, DsmError


class Session:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.closed = False
        self.close_error = close_error

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


def client(session: Session | None = None, timeout: object = 15) -> DsmClient:
    return DsmClient(
        Credentials("https://example.invalid:5001", "user", "password"),
        session=session,
        timeout=timeout,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), float("inf"), "15"])
def test_constructor_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        client(timeout=timeout)


def test_constructor_normalizes_timeout() -> None:
    assert client(timeout=15).timeout == 15.0


def test_exit_closes_owned_session_after_logout(monkeypatch: pytest.MonkeyPatch) -> None:
    owned = Session()
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    calls: list[str] = []
    monkeypatch.setattr(managed, "_logout_request", lambda: calls.append("logout"))
    managed.__exit__(None, None, None)
    assert calls == ["logout"] and owned.closed


def test_exit_does_not_close_injected_session(monkeypatch: pytest.MonkeyPatch) -> None:
    injected = Session()
    managed = client(injected)
    monkeypatch.setattr(managed, "_logout_request", lambda: None)
    managed.__exit__(None, None, None)
    assert not injected.closed


def test_exit_preserves_primary_error_while_attempting_all_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = Session(close_error=RuntimeError("close failed"))
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    called: list[str] = []

    def failing_logout() -> None:
        called.append("logout")
        raise DsmError("logout failed")

    monkeypatch.setattr(managed, "_logout_request", failing_logout)
    # A context-body error is represented by a non-None exception type and must not be masked.
    managed.__exit__(RuntimeError, RuntimeError("primary"), None)
    assert called == ["logout"] and owned.closed
    assert managed.cleanup_failed
    assert managed.cleanup_message == "DSM session cleanup did not complete"
    assert managed.cleanup_operation == "logout_and_close"
    assert managed.cleanup_metadata == {
        "category": "session_cleanup",
        "operation": "logout_and_close",
    }


def test_exit_suppresses_logout_error_after_closing_owned_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = Session()
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    monkeypatch.setattr(
        managed, "_logout_request", lambda: (_ for _ in ()).throw(RuntimeError("logout failed"))
    )
    managed.__exit__(None, None, None)
    assert owned.closed and managed.cleanup_failed
    assert managed.cleanup_operation == "logout"


def test_enter_failure_cleans_owned_session_and_records_close_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = Session(close_error=RuntimeError("close failed"))
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    monkeypatch.setattr(managed, "discover", lambda: (_ for _ in ()).throw(RuntimeError("setup")))
    monkeypatch.setattr(managed, "_logout_request", lambda: None)

    with pytest.raises(RuntimeError, match="setup"):
        managed.__enter__()

    assert owned.closed and managed.cleanup_failed
    assert managed.cleanup_operation == "close"
    assert managed.cleanup_error is not None
    assert str(managed.cleanup_error) == "DSM session cleanup did not complete"


def test_enter_login_failure_composes_logout_and_close_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owned = Session(close_error=RuntimeError("close failed"))
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    monkeypatch.setattr(managed, "discover", lambda: None)

    def failing_login() -> None:
        managed.sid = "safe-session"
        raise DsmError("setup failed")

    monkeypatch.setattr(managed, "login", failing_login)
    monkeypatch.setattr(
        managed, "_logout_request", lambda: (_ for _ in ()).throw(DsmError("logout failed"))
    )

    with pytest.raises(DsmError, match="setup failed"):
        managed.__enter__()

    assert owned.closed and managed.cleanup_failed
    assert managed.cleanup_operation == "logout_and_close"
    assert managed.cleanup_metadata == {
        "category": "session_cleanup",
        "operation": "logout_and_close",
    }


def test_enter_failure_does_not_close_injected_session(monkeypatch: pytest.MonkeyPatch) -> None:
    injected = Session()
    managed = client(injected)
    monkeypatch.setattr(managed, "discover", lambda: (_ for _ in ()).throw(RuntimeError("setup")))
    monkeypatch.setattr(managed, "_logout_request", lambda: None)

    with pytest.raises(RuntimeError, match="setup"):
        managed.__enter__()

    assert not injected.closed and not managed.cleanup_failed


def test_exit_records_close_cleanup_category(monkeypatch: pytest.MonkeyPatch) -> None:
    owned = Session(close_error=RuntimeError("close failed"))
    monkeypatch.setattr("synology_manager.dsm.requests.Session", lambda: owned)
    managed = client()
    monkeypatch.setattr(managed, "_logout_request", lambda: None)

    managed.__exit__(None, None, None)

    assert managed.cleanup_operation == "close"
    assert managed.cleanup_metadata == {"category": "session_cleanup", "operation": "close"}

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from synology_manager.config import ConfigError, Host, load_config
from synology_manager.dsm import (
    AuthenticationError,
    CredentialValidationError,
    DsmClient,
    DsmError,
    UnsupportedCapability,
    credentials,
    validate_ca_bundle,
)
from synology_manager.engine import (
    ApplyResult,
    DriftError,
    PartialApplyError,
    ProgressEvent,
    SafetyError,
)
from synology_manager.engine import apply as run_apply
from synology_manager.engine import plan as make_plan
from synology_manager.plan import ActionPlan

_DESCRIPTION = "Safely observe or apply one explicit Synology configuration."
_EPILOG = "Global connection options must precede apply-config; command options must follow it."


def _json_requested(argv: Sequence[str]) -> bool:
    return any(
        token == "--output=json"
        or (token == "--output" and index + 1 < len(argv) and argv[index + 1] == "json")
        for index, token in enumerate(argv)
    )


def _parser_error_payload(argv: Sequence[str]) -> dict[str, object]:
    return {
        "applied": False,
        "current_plan": None,
        "cleanup": {"status": "not_started"},
        "current_plan_hash": None,
        "error": {"message": "invalid command line", "type": "validation"},
        "events": [],
        "exit_code": 2,
        "expected_plan_hash": None,
        "mode": "apply" if "--do-it" in argv else "dry_run",
        "pre_apply_plan": None,
        "status": "error",
    }


@dataclass(frozen=True)
class _ParserContext:
    argv: tuple[str, ...]
    json_output: bool


class _JsonAwareParser(argparse.ArgumentParser):
    _context = _ParserContext((), False)

    def error(self, message: str) -> NoReturn:
        if self._context.json_output:
            print(_json(_parser_error_payload(self._context.argv)))
            self.exit(2)
        super().error(message)


def _finite_positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return timeout


def _parser(context: _ParserContext | None = None) -> argparse.ArgumentParser:
    context = context or _ParserContext((), False)
    parser = _JsonAwareParser(
        prog="synology-manager", description=_DESCRIPTION, epilog=_EPILOG, allow_abbrev=False
    )
    parser._context = context
    parser.add_argument("--host", metavar="DSM_ENDPOINT")
    parser.add_argument("--username")
    parser.add_argument(
        "--password",
        help="DSM password (may appear in process listings/history; prefer SYN_PASSWORD)",
    )
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--insecure", action="store_true")

    subcommands = parser.add_subparsers(dest="command", required=True)
    apply_config = subcommands.add_parser(
        "apply-config", description=_DESCRIPTION, epilog=_EPILOG, allow_abbrev=False
    )
    apply_config._context = context
    apply_config.add_argument("-c", "--config", type=Path, required=True)
    apply_config.add_argument("--do-it", action="store_true")
    apply_config.add_argument("--verbose", action="store_true")
    apply_config.add_argument("--timeout", type=_finite_positive_timeout, default=15.0)
    apply_config.add_argument("--output", choices=("text", "json"), default="text")
    return parser


def _load_host(config_path: Path) -> Host:
    """Load the one informational logical host declared by a configuration."""
    return load_config(config_path).host


def _option_or_env(args: argparse.Namespace, option: str, environment: str) -> str | None:
    """Prefer an explicitly supplied option, including an intentionally empty value."""
    value = getattr(args, option)
    return value if isinstance(value, str) else os.environ.get(environment)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


_CLEANUP_MESSAGE = "DSM session cleanup did not complete"


@dataclass
class _PendingOutcome:
    """A completed command result which is rendered only after client cleanup."""

    exit_code: int
    payload: dict[str, object] | None
    render_text: Callable[[dict[str, object]], None] | None


def _cleanup_payload(client: object | None) -> dict[str, object]:
    if client is None:
        return {"status": "not_started"}
    if getattr(client, "cleanup_failed", False):
        return {"message": _CLEANUP_MESSAGE, "status": "failed"}
    return {"status": "ok"}


def _with_cleanup(payload: dict[str, object], client: object | None) -> dict[str, object]:
    payload["cleanup"] = _cleanup_payload(client)
    return payload


def _render_outcome(
    args: argparse.Namespace, outcome: _PendingOutcome, client: object | None
) -> int:
    if outcome.payload is not None:
        cleanup = _cleanup_payload(client)
        _with_cleanup(outcome.payload, client)
        exit_code = (
            1 if cleanup["status"] == "failed" and outcome.exit_code == 0 else outcome.exit_code
        )
        if cleanup["status"] == "failed":
            outcome.payload["exit_code"] = exit_code
        if args.output == "json":
            print(_json(outcome.payload))
        elif outcome.render_text is not None:
            outcome.render_text(outcome.payload)
        return exit_code
    return outcome.exit_code


def _action_counts(plan: ActionPlan) -> str:
    counts = Counter(action.kind for action in plan.actions)
    return " ".join(f"{kind}={counts.get(kind, 0)}" for kind in sorted(counts)) or "actions=0"


def _dry_run_payload(plan: ActionPlan) -> dict[str, object]:
    return {
        "applied": False,
        "mode": "dry_run",
        "plan": plan.as_dict(),
        "plan_hash": plan.digest,
        "status": "dry_run",
    }


def _render_cleanup_warning(cleanup: dict[str, object]) -> None:
    if cleanup["status"] == "failed":
        print(f"WARNING: {_CLEANUP_MESSAGE}", file=sys.stderr)


def _render_dry_run_text(plan: ActionPlan, verbose: bool, cleanup: dict[str, object]) -> None:
    print(f"Dry run: status=dry_run applied=false plan_hash={plan.digest} {_action_counts(plan)}")
    print("WARNING: omitted ACL/NFS for configured present shares means authoritative empty state.")
    if verbose:
        print(plan.as_text())
    _render_cleanup_warning(cleanup)


def _apply_payload(
    pre_apply_plan: ActionPlan, result: ApplyResult, events: list[ProgressEvent]
) -> dict[str, object]:
    payload = result.as_dict()
    # Bind JSON to the exact locally rendered plan, not an untrusted result field.
    payload["pre_apply_plan"] = pre_apply_plan.as_dict()
    payload["expected_plan_hash"] = pre_apply_plan.digest
    return {
        "events": [event.as_dict() for event in events],
        "exit_code": 0 if result.applied else 6,
        "mode": "apply",
        **payload,
    }


def _partial_payload(
    plan: ActionPlan,
    error: PartialApplyError,
    events: list[ProgressEvent],
    current_plan: ActionPlan | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "applied": False,
        "error": _error_detail(error, "partial_apply"),
        "events": [event.as_dict() for event in events],
        "exit_code": 6,
        "expected_plan_hash": plan.digest,
        "mode": "apply",
        "pre_apply_plan": plan.as_dict(),
        "recovery_observation": "available" if current_plan is not None else "unavailable",
        "status": "partial_failure",
    }
    if current_plan is not None:
        payload["current_plan"] = current_plan.as_dict()
        payload["current_plan_hash"] = current_plan.digest
    return payload


def _error_detail(error: Exception, error_type: str) -> dict[str, object]:
    message = (
        "an unexpected internal error occurred"
        if error_type in {"internal_error", "partial_apply"} and not isinstance(error, DsmError)
        else str(error)
    )
    detail: dict[str, object] = {"message": message, "type": error_type}
    if isinstance(error, PartialApplyError):
        detail.update(
            {"phase": error.phase, "recovery": error.recovery, "resource": error.resource}
        )
    if isinstance(error, DsmError) and (operation := error.operation()) is not None:
        detail["operation"] = operation
    return detail


def _render_apply_text(
    result: ApplyResult, events: list[ProgressEvent], verbose: bool, cleanup: dict[str, object]
) -> None:
    if verbose:
        for event in events:
            print(f"Progress: {event.sequence} {event.phase} {event.kind} {event.resource}")
    print("Apply result")
    print(
        f"status={result.status} applied={str(result.applied).lower()} "
        f"expected_plan_hash={result.expected_plan_hash} current_plan_hash={result.current_plan_hash}"
    )
    rendered_plan = result.final_plan if result.applied else result.current_plan
    if rendered_plan is not None:
        print(rendered_plan.as_text())
    _render_cleanup_warning(cleanup)


def _apply_error_payload(
    plan: ActionPlan,
    events: list[ProgressEvent],
    error: Exception,
    code: int,
    error_type: str,
    current_plan: ActionPlan | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "applied": False,
        "error": _error_detail(error, error_type),
        "events": [event.as_dict() for event in events],
        "exit_code": code,
        "expected_plan_hash": plan.digest,
        "mode": "apply",
        "pre_apply_plan": plan.as_dict(),
        "recovery_observation": "available" if current_plan is not None else "unavailable",
        "status": "error",
    }
    if current_plan is not None:
        payload["current_plan"] = current_plan.as_dict()
        payload["current_plan_hash"] = current_plan.digest
    return payload


def _error_result(args: argparse.Namespace, error: Exception, code: int, error_type: str) -> int:
    mode = "apply" if args.do_it else "dry_run"
    if args.output == "json":
        print(
            _json(
                {
                    "applied": False,
                    "cleanup": {"status": "not_started"},
                    "current_plan": None,
                    "current_plan_hash": None,
                    "error": _error_detail(error, error_type),
                    "events": [],
                    "exit_code": code,
                    "expected_plan_hash": None,
                    "mode": mode,
                    "pre_apply_plan": None,
                    "status": "error",
                }
            )
        )
    else:
        labels = {
            "authentication": "authentication or TLS error",
            "dsm": "DSM error",
            "drift": "drift or partial state",
            "internal_error": "internal error",
            "partial_apply": "partial apply",
            "safety": "safety error",
            "unsupported_capability": "unsupported capability",
            "validation": "validation error",
        }
        label = labels[error_type]
        message = (
            "an unexpected internal error occurred"
            if error_type == "internal_error"
            else str(error)
        )
        print(f"{label}: {message}", file=sys.stderr)
    return code


def _apply_error_code(error: Exception) -> tuple[int, str]:
    if isinstance(error, SafetyError):
        return 4, "safety"
    if isinstance(error, UnsupportedCapability):
        return 5, "unsupported_capability"
    if isinstance(error, DriftError):
        return 6, "drift"
    if isinstance(error, AuthenticationError):
        return 3, "authentication"
    if isinstance(error, DsmError):
        return 3, "dsm"
    return 1, "internal_error"


def _partial_current_plan(client: DsmClient, host: Host) -> ActionPlan | None:
    """Best-effort observation after a partial mutation; never masks the original error."""
    try:
        return make_plan(client, host)
    except Exception:
        return None


def _render_apply_error_text(
    plan: ActionPlan,
    events: list[ProgressEvent],
    payload: dict[str, object],
    *,
    verbose: bool,
    cleanup: dict[str, object],
    current_plan: ActionPlan | None,
) -> None:
    """Render one safe apply failure section after client cleanup."""
    stream = sys.stderr
    if verbose:
        for event in events:
            print(
                f"Progress: {event.sequence} {event.phase} {event.kind} {event.resource}",
                file=stream,
            )
    print("Apply result", file=stream)
    print(f"status={payload['status']} applied=false expected_plan_hash={plan.digest}", file=stream)
    current_hash = payload.get("current_plan_hash")
    if isinstance(current_hash, str):
        print(f"current_plan_hash={current_hash}", file=stream)
    if current_plan is not None:
        print(current_plan.as_text(), file=stream)
    error = payload["error"]
    if isinstance(error, dict):
        print(f"error: type={error['type']} message={error['message']}", file=stream)
    _render_cleanup_warning(cleanup)


def _pending_error_outcome(
    args: argparse.Namespace, error: Exception, code: int, error_type: str
) -> _PendingOutcome:
    """Defer an error result until any constructed client's cleanup is observable."""

    def render_error(rendered: dict[str, object]) -> None:
        _error_result(args, error, code, error_type)
        _render_cleanup_warning(rendered["cleanup"])  # type: ignore[arg-type]

    return _PendingOutcome(
        code,
        _generic_error_payload(args, error, code, error_type),
        render_error,
    )


def _generic_error_payload(
    args: argparse.Namespace, error: Exception, code: int, error_type: str
) -> dict[str, object]:
    return {
        "applied": False,
        "current_plan": None,
        "current_plan_hash": None,
        "error": _error_detail(error, error_type),
        "events": [],
        "exit_code": code,
        "expected_plan_hash": None,
        "mode": "apply" if args.do_it else "dry_run",
        "pre_apply_plan": None,
        "status": "error",
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command, deferring its final result until DSM cleanup has completed."""
    parser_argv = tuple(sys.argv[1:] if argv is None else argv)
    parser_context = _ParserContext(parser_argv, _json_requested(parser_argv))
    args = _parser(parser_context).parse_args(parser_argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        return _error_result(
            args, ValueError("--timeout must be a finite positive number"), 2, "validation"
        )
    if args.insecure and args.output == "text":
        print("WARNING: TLS certificate verification is disabled by --insecure.", file=sys.stderr)

    try:
        host = _load_host(args.config)
        connection = credentials(
            _option_or_env(args, "host", "SYN_HOST"),
            _option_or_env(args, "username", "SYN_USERNAME"),
            _option_or_env(args, "password", "SYN_PASSWORD"),
        )
        ca_bundle = validate_ca_bundle(args.ca_bundle)
        verify: bool | str = ca_bundle if ca_bundle is not None else not args.insecure
    except (ConfigError, CredentialValidationError) as error:
        return _error_result(args, error, 2, "validation")
    except AuthenticationError as error:
        return _error_result(args, error, 3, "authentication")
    except Exception as error:
        return _error_result(args, error, 1, "internal_error")

    client: DsmClient | None = None
    outcome: _PendingOutcome | None = None
    try:
        client = DsmClient(connection, timeout=args.timeout, verify=verify)
        client.suppress_logout_logging = args.output == "json"
        with client as active_client:
            events: list[ProgressEvent] = []
            pre_apply_plan: ActionPlan | None = None
            try:
                pre_apply_plan = make_plan(active_client, host)
                if not args.do_it:
                    plan = pre_apply_plan
                    outcome = _PendingOutcome(
                        0,
                        _dry_run_payload(plan),
                        lambda payload: _render_dry_run_text(
                            plan,
                            args.verbose,
                            payload["cleanup"],  # type: ignore[arg-type]
                        ),
                    )
                else:
                    if args.output == "text":
                        print("Plan to apply")
                        print(pre_apply_plan.as_text())
                    try:
                        result = run_apply(
                            active_client, host, pre_apply_plan, progress=events.append
                        )
                    except PartialApplyError as error:
                        current_plan = _partial_current_plan(active_client, host)
                        payload = _partial_payload(pre_apply_plan, error, events, current_plan)

                        def render_partial(rendered: dict[str, object]) -> None:
                            _render_apply_error_text(
                                pre_apply_plan,
                                events,
                                rendered,
                                verbose=args.verbose,
                                cleanup=rendered["cleanup"],  # type: ignore[arg-type]
                                current_plan=current_plan,
                            )

                        outcome = _PendingOutcome(6, payload, render_partial)
                    except Exception as error:
                        code, error_type = _apply_error_code(error)
                        current_plan = _partial_current_plan(active_client, host)
                        mutation_started = bool(events)
                        if mutation_started:
                            code, error_type = 6, "partial_apply"
                        payload = _apply_error_payload(
                            pre_apply_plan, events, error, code, error_type, current_plan
                        )
                        if mutation_started:
                            payload["status"] = "partial_failure"

                        def render_error(rendered: dict[str, object]) -> None:
                            _render_apply_error_text(
                                pre_apply_plan,
                                events,
                                rendered,
                                verbose=args.verbose,
                                cleanup=rendered["cleanup"],  # type: ignore[arg-type]
                                current_plan=current_plan,
                            )

                        outcome = _PendingOutcome(code, payload, render_error)
                    else:
                        payload = _apply_payload(pre_apply_plan, result, events)
                        outcome = _PendingOutcome(
                            0 if result.applied else 6,
                            payload,
                            lambda rendered: _render_apply_text(
                                result,
                                events,
                                args.verbose,
                                rendered["cleanup"],  # type: ignore[arg-type]
                            ),
                        )
            except Exception as error:
                code, error_type = _apply_error_code(error)
                outcome = _pending_error_outcome(args, error, code, error_type)
    except Exception as error:
        code, error_type = _apply_error_code(error)
        if client is None:
            return _error_result(args, error, code, error_type)
        outcome = _pending_error_outcome(args, error, code, error_type)

    if outcome is None:
        return _error_result(args, RuntimeError("missing command result"), 1, "internal_error")
    return _render_outcome(args, outcome, client)


if __name__ == "__main__":
    raise SystemExit(main())

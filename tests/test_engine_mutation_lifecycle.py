from __future__ import annotations

import pytest

from synology_manager import engine
from synology_manager.config import Host
from synology_manager.dsm import DsmError
from synology_manager.engine import PartialApplyError
from synology_manager.plan import ActionPlan


@pytest.mark.parametrize(
    ("kind", "resource", "phase"),
    [
        ("update", "acl:data", "acl_apply"),
        ("update", "share:data", "share_set"),
        ("delete", "share:data", "share_delete"),
    ],
)
def test_post_mutation_failures_are_partial_with_current_safe_phase(
    monkeypatch: pytest.MonkeyPatch, kind: str, resource: str, phase: str
) -> None:
    def failing(
        client: object,
        host: Host,
        plan: ActionPlan,
        tracker: engine.MutationTracker,
        **kwargs: object,
    ) -> engine.ApplyResult:
        tracker.begin(kind, resource)
        raise DsmError("DSM API error", api="SYNO.Core.ACL", method="set", version=1)

    monkeypatch.setattr(engine, "_apply", failing)
    with pytest.raises(PartialApplyError) as raised:
        engine.apply(object(), Host("host", ("/volume1",), ()), ActionPlan(()))  # type: ignore[arg-type]
    assert raised.value.resource == resource and raised.value.phase == phase
    assert raised.value.operation() == {"api": "SYNO.Core.ACL", "method": "set", "version": 1}


def test_final_verification_failure_is_partial_after_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing(
        client: object,
        host: Host,
        plan: ActionPlan,
        tracker: engine.MutationTracker,
        **kwargs: object,
    ) -> engine.ApplyResult:
        tracker.begin("update", "share:data")
        tracker.begin_final_verification()
        raise DsmError("DSM API error", api="SYNO.Core.Share", method="list", version=1)

    monkeypatch.setattr(engine, "_apply", failing)
    with pytest.raises(PartialApplyError) as raised:
        engine.apply(object(), Host("host", ("/volume1",), ()), ActionPlan(()))  # type: ignore[arg-type]
    assert raised.value.resource == "configuration" and raised.value.phase == "final_verify"

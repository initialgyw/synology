import json

import pytest
import yaml

from synology.models import (
    OperationStatus,
    OutputFormat,
    ShareOperationStep,
    SubshareCreateResult,
)
from synology.output import render_subshare_create


@pytest.mark.parametrize(
    "fmt", [OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.YAML]
)
def test_subshare_output_created(fmt: OutputFormat) -> None:
    result = SubshareCreateResult(
        "projects",
        "archive",
        "/volume1/projects/archive",
        True,
        (ShareOperationStep("create", OperationStatus.SUCCEEDED),),
    )
    rendered = render_subshare_create(result, fmt)
    if fmt is OutputFormat.TABLE:
        assert "created" in rendered and "/volume1/projects/archive" in rendered
    elif fmt is OutputFormat.JSON:
        assert json.loads(rendered)["created"] is True
    else:
        assert yaml.safe_load(rendered)["created"] is True


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (OperationStatus.PLANNED, "planned"),
        (OperationStatus.FAILED, "failed"),
        (OperationStatus.UNKNOWN, "unknown"),
    ],
)
def test_subshare_output_noncreated_statuses(
    status: OperationStatus, expected: str
) -> None:
    result = SubshareCreateResult(
        "projects", "archive", None, False, (ShareOperationStep("verify", status),)
    )
    for fmt in (OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.YAML):
        rendered = render_subshare_create(result, fmt)
        assert expected in rendered

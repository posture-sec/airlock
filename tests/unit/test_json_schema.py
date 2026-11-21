"""Unit tests validating JSON report output against schema (issue #69).

Uses a standard-library-only JSON Schema validator (no external packages permitted).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from airlock.model import (
    EXIT_FINDINGS,
    Finding,
    Mode,
    ScanReport,
    Severity,
)
from airlock.report import jsonout

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "json-report.schema.json"
GOLDEN_PATH = Path(__file__).resolve().parents[1] / "golden" / "report-v1.json"


def _matches_type(val: Any, t: str) -> bool:
    if t == "object":
        return isinstance(val, dict)
    if t == "array":
        return isinstance(val, list)
    if t == "string":
        return isinstance(val, str)
    if t == "integer":
        return isinstance(val, int) and not isinstance(val, bool)
    if t == "boolean":
        return isinstance(val, bool)
    if t == "null":
        return val is None
    return False


def validate_schema(
    instance: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    """Validate an instance against a JSON schema subset using stdlib only.

    Supports: type, const, enum, required, additionalProperties, properties, items,
    pattern, minimum, $ref.
    """
    if root_schema is None:
        root_schema = schema

    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"Unsupported ref: {ref}")
        def_name = ref.removeprefix("#/$defs/")
        target_schema = root_schema.get("$defs", {}).get(def_name)
        if target_schema is None:
            raise ValueError(f"Ref target not found: {ref}")
        validate_schema(instance, target_schema, root_schema, path)
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_matches_type(instance, t) for t in types):
            raise ValueError(
                f"{path}: expected type {expected_type}, got {type(instance).__name__}"
            )

    if "const" in schema and instance != schema["const"]:
        raise ValueError(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        raise ValueError(f"{path}: value {instance!r} not in enum {schema['enum']!r}")

    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        raise ValueError(f"{path}: value {instance} below minimum {schema['minimum']}")

    if (
        "pattern" in schema
        and isinstance(instance, str)
        and not re.search(schema["pattern"], instance)
    ):
        raise ValueError(f"{path}: string {instance!r} does not match pattern {schema['pattern']}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for req in required:
            if req not in instance:
                raise ValueError(f"{path}: missing required property {req!r}")

        properties = schema.get("properties", {})
        add_props = schema.get("additionalProperties", True)
        for key, val in instance.items():
            if key in properties:
                validate_schema(val, properties[key], root_schema, f"{path}.{key}")
            else:
                if add_props is False:
                    raise ValueError(f"{path}: unexpected additional property {key!r}")
                elif isinstance(add_props, dict):
                    validate_schema(val, add_props, root_schema, f"{path}.{key}")

    elif isinstance(instance, list):
        items_schema = schema.get("items")
        if items_schema is not None:
            for idx, item in enumerate(instance):
                validate_schema(item, items_schema, root_schema, f"{path}[{idx}]")


def test_schema_file_exists_and_is_valid_json() -> None:
    assert SCHEMA_PATH.is_file()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema.get("title") == "AirlockScanReport"
    assert "schema_version" in schema.get("properties", {})


def test_golden_report_validates_against_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report_data = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

    # Must validate cleanly
    validate_schema(report_data, schema)

    # Must contain 1 finding with evidence, 1 without, and 1 suppressed finding
    findings = report_data["findings"]
    suppressed = report_data["suppressed"]

    assert len(findings) == 2
    with_ev = [f for f in findings if f["evidence"] is not None]
    without_ev = [f for f in findings if f["evidence"] is None]
    assert len(with_ev) == 1
    assert len(without_ev) == 1

    assert len(suppressed) == 1
    assert suppressed[0]["suppressed_by"] is not None


def test_validator_rejects_missing_required_key() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report_data = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    del report_data["schema_version"]

    with pytest.raises(ValueError, match="missing required property 'schema_version'"):
        validate_schema(report_data, schema)


def test_validator_rejects_unknown_additional_properties() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report_data = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    report_data["unexpected_field"] = "malicious_or_unknown"

    with pytest.raises(ValueError, match="unexpected additional property 'unexpected_field'"):
        validate_schema(report_data, schema)


def test_validator_rejects_invalid_finding_severity() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report_data = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    report_data["findings"][0]["severity"] = "CRITICAL"

    with pytest.raises(ValueError, match="not in enum"):
        validate_schema(report_data, schema)


def test_jsonout_to_dict_matches_schema_and_sorts_keys() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    dummy_finding = Finding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/index.js",
        line=1,
        roles=("source",),
        message="eval call",
        evidence="eval(x)",
        occurrence=0,
        fingerprint="sha256:" + "a" * 64,
        suppressible=True,
    )
    report = ScanReport(
        tool_version="0.0.1",
        mode=Mode.FULL,
        repo_head="HEAD",
        base=None,
        files_indexed=1,
        files_scanned=1,
        files_skipped={},
        findings=(dummy_finding,),
        suppressed=(),
        exit_code=EXIT_FINDINGS,
    )

    data = jsonout.to_dict(report)
    assert data["schema_version"] == jsonout.SCHEMA_VERSION == 1
    validate_schema(data, schema)

    rendered = jsonout.render(report)
    # Check sort_keys by checking that base comes before exit_code
    assert rendered.index('"base"') < rendered.index('"exit_code"')
    assert rendered.index('"exit_code"') < rendered.index('"findings"')

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_evidence)

EVIDENCE_PATH = ROOT / "evidence" / "baseline-evidence.json"


def valid_evidence() -> dict:
    return verify_evidence.load_evidence(EVIDENCE_PATH)


def test_published_evidence_passes() -> None:
    checks = verify_evidence.verify(EVIDENCE_PATH)
    assert "tests: OK" in checks
    assert "production_deployment: OK" in checks


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("baseline_version", "MVS-001 v0.5.2"),
        ("scope", "production"),
        ("production_deployment", "ALLOWED"),
        ("high_consequence_autonomy", "ALLOWED"),
        ("frozen_path_negative_tamper_test", "FAIL"),
    ],
)
def test_fixed_governance_values_reject_drift(field: str, replacement: str) -> None:
    data = valid_evidence()
    data[field] = replacement
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


@pytest.mark.parametrize(
    "field",
    [
        "source_zip_sha256",
        "clean_extraction_manifest_sha256",
        "ci_configuration_sha256",
    ],
)
def test_sha256_fields_must_be_lowercase_64_hex(field: str) -> None:
    data = valid_evidence()
    data[field] = "A" * 64
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


@pytest.mark.parametrize(
    "field",
    ["baseline_commit", "baseline_tree", "annotated_tag_sha", "workflow_commit"],
)
def test_git_ids_must_be_lowercase_40_hex(field: str) -> None:
    data = valid_evidence()
    data[field] = "0" * 39
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


@pytest.mark.parametrize(
    "field",
    [
        "source_zip_sha256",
        "clean_extraction_manifest_sha256",
        "ci_configuration_sha256",
    ],
)
def test_well_formed_sha256_substitution_is_rejected(field: str) -> None:
    data = valid_evidence()
    data[field] = "0" * 64
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


@pytest.mark.parametrize(
    "field",
    ["baseline_commit", "baseline_tree", "annotated_tag_sha", "workflow_commit"],
)
def test_well_formed_git_id_substitution_is_rejected(field: str) -> None:
    data = valid_evidence()
    data[field] = "0" * 40
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


def test_test_totals_are_frozen() -> None:
    data = valid_evidence()
    data["tests"] = {"passed": 71, "failed": 1}
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


def test_boolean_is_not_accepted_as_test_count() -> None:
    data = valid_evidence()
    data["tests"] = {"passed": True, "failed": 0}
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


def test_unexpected_top_level_field_is_rejected() -> None:
    data = valid_evidence()
    data["private_material"] = "must not be published"
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


def test_missing_required_field_is_rejected() -> None:
    data = valid_evidence()
    del data["baseline_tree"]
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/FitsyncLmt/xroiq-cas-core/actions/runs/29196020289",
        "https://example.com/FitsyncLmt/xroiq-cas-core/actions/runs/29196020289",
        "https://github.com/FitsyncLmt/other/actions/runs/29196020289",
        "https://github.com/FitsyncLmt/xroiq-cas-core/actions/runs/not-a-number",
        "https://github.com/FitsyncLmt/xroiq-cas-core/actions/runs/99999999999",
    ],
)
def test_ci_url_is_strictly_scoped(url: str) -> None:
    data = valid_evidence()
    data["ci_run_url"] = url
    with pytest.raises(verify_evidence.EvidenceError):
        verify_evidence.validate_evidence(data)


def test_input_is_not_mutated() -> None:
    data = valid_evidence()
    original = copy.deepcopy(data)
    verify_evidence.validate_evidence(data)
    assert data == original

#!/usr/bin/env python3
"""Validate the sanitized XROIQ CAS public evidence record."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXPECTED_VALUES = {
    "system": "XROIQ CAS",
    "baseline_version": "MVS-001 v0.5.1",
    "frozen_path_negative_tamper_test": "PASS",
    "scope": "A1 local/test/shadow only",
    "production_deployment": "PROHIBITED",
    "high_consequence_autonomy": "PROHIBITED",
}

FROZEN_IDENTIFIERS = {
    "source_zip_sha256": "4fba791f0e3ea6e03991514b5492e7b0f64f439047f8f2c85e09482d7a5b653d",
    "clean_extraction_manifest_sha256": "294a25f523949531c54cdb7fcdd95c5fe2493ebed5403aa69e74ed4c454938ea",
    "baseline_commit": "27833b122c082c973bc2446c29a73b8692522795",
    "baseline_tree": "23e25d6b9d1929a1fd1387a45dcda73f9a3934d2",
    "annotated_tag_sha": "773e5f21da09bf471e674ecd0a698ed4780e7db9",
    "workflow_commit": "1b3e241261621460d9ec19732a5b4b59bddd5796",
    "ci_configuration_sha256": "974cc30d81b95d14b39b5f49310c828033ceb63cd8a3f0578364552f33aa0d93",
}

EXPECTED_CI_RUN_URL = (
    "https://github.com/FitsyncLmt/xroiq-cas-core/actions/runs/29196020289"
)

SHA256_FIELDS = {
    "source_zip_sha256",
    "clean_extraction_manifest_sha256",
    "ci_configuration_sha256",
}

GIT_SHA_FIELDS = {
    "baseline_commit",
    "baseline_tree",
    "annotated_tag_sha",
    "workflow_commit",
}

REQUIRED_TOP_LEVEL_FIELDS = {
    *EXPECTED_VALUES.keys(),
    *SHA256_FIELDS,
    *GIT_SHA_FIELDS,
    "ci_run_url",
    "tests",
}

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    """Raised when the public evidence record is invalid."""


def load_evidence(path: Path) -> dict[str, Any]:
    """Load and parse the evidence document."""
    if not path.is_file():
        raise EvidenceError(f"Evidence file not found: {path}")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceError(f"Unable to read evidence file: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvidenceError(
            f"Evidence file is not valid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise EvidenceError("Evidence root must be a JSON object.")

    return data


def _validate_url(value: Any) -> None:
    if not isinstance(value, str):
        raise EvidenceError("ci_run_url must be a string.")

    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise EvidenceError("ci_run_url must be an HTTPS github.com URL.")

    expected_prefix = "/FitsyncLmt/xroiq-cas-core/actions/runs/"
    if not parsed.path.startswith(expected_prefix):
        raise EvidenceError(
            "ci_run_url must reference the recorded xroiq-cas-core GitHub Actions run."
        )

    run_id = parsed.path.removeprefix(expected_prefix).strip("/")
    if not run_id.isdigit():
        raise EvidenceError("ci_run_url must end with a numeric GitHub Actions run ID.")


def validate_evidence(data: dict[str, Any]) -> list[str]:
    """Return human-readable checks or raise EvidenceError on failure."""
    missing = sorted(REQUIRED_TOP_LEVEL_FIELDS - data.keys())
    extra = sorted(data.keys() - REQUIRED_TOP_LEVEL_FIELDS)

    if missing:
        raise EvidenceError("Missing required field(s): " + ", ".join(missing))
    if extra:
        raise EvidenceError("Unexpected field(s): " + ", ".join(extra))

    checks: list[str] = []

    for field, expected in EXPECTED_VALUES.items():
        actual = data.get(field)
        if actual != expected:
            raise EvidenceError(
                f"{field} must be {expected!r}; received {actual!r}."
            )
        checks.append(f"{field}: OK")

    for field in sorted(SHA256_FIELDS):
        value = data.get(field)
        if not isinstance(value, str) or not HEX_64.fullmatch(value):
            raise EvidenceError(f"{field} must be a lowercase 64-character SHA-256 value.")
        if value != FROZEN_IDENTIFIERS[field]:
            raise EvidenceError(f"{field} does not match the frozen public baseline.")
        checks.append(f"{field}: OK")

    for field in sorted(GIT_SHA_FIELDS):
        value = data.get(field)
        if not isinstance(value, str) or not HEX_40.fullmatch(value):
            raise EvidenceError(f"{field} must be a lowercase 40-character Git object ID.")
        if value != FROZEN_IDENTIFIERS[field]:
            raise EvidenceError(f"{field} does not match the frozen public baseline.")
        checks.append(f"{field}: OK")

    tests = data.get("tests")
    if not isinstance(tests, dict):
        raise EvidenceError("tests must be a JSON object.")
    if set(tests) != {"passed", "failed"}:
        raise EvidenceError("tests must contain exactly 'passed' and 'failed'.")
    if isinstance(tests.get("passed"), bool) or not isinstance(tests.get("passed"), int):
        raise EvidenceError("tests.passed must be an integer.")
    if isinstance(tests.get("failed"), bool) or not isinstance(tests.get("failed"), int):
        raise EvidenceError("tests.failed must be an integer.")
    if tests != {"passed": 72, "failed": 0}:
        raise EvidenceError("tests must record exactly 72 passed and 0 failed.")
    checks.append("tests: OK")

    _validate_url(data.get("ci_run_url"))
    if data["ci_run_url"] != EXPECTED_CI_RUN_URL:
        raise EvidenceError("ci_run_url does not match the frozen public baseline.")
    checks.append("ci_run_url: OK")

    return checks


def verify(path: Path) -> list[str]:
    """Load and validate an evidence file."""
    return validate_evidence(load_evidence(path))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the sanitized XROIQ CAS public evidence record."
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path("evidence/baseline-evidence.json"),
        help="Path to the public evidence JSON file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        checks = verify(args.evidence)
    except EvidenceError as exc:
        print(f"Public evidence verification FAILED: {exc}", file=sys.stderr)
        return 1

    print("Public evidence verification PASSED.")
    for check in checks:
        print(f"- {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

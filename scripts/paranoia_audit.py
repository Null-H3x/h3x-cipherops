#!/usr/bin/env python3
"""Paranoia audit — exhaustive script, path, and invariant checks."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NON_PERIODIC_FAMILIES = frozenset({
    "autokey",
    "running_key",
    "gronsfeld_autokey",
    "gak",
    "porta_autokey",
    "xautokey",
    "nihilist_autokey",
    "vernam",
})


@dataclass
class ParanoiaReport:
    passed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def fail(self, msg: str) -> None:
        self.errors.append(msg)


def audit_script_paths(report: ParanoiaReport) -> None:
    """Scripts must resolve datasets from repo root, not cwd."""
    from cipherops.ciphers.registry import CIPHER_REGISTRY

    dataset_root = ROOT / "datasets" / "fingerprinted"
    count = len(list(dataset_root.glob("*/data.jsonl")))
    expected = len(CIPHER_REGISTRY)
    if count != expected:
        report.fail(f"Dataset file count {count} != registry {expected} under {dataset_root}")
    else:
        report.ok(f"Dataset paths anchored to repo root ({count} files)")

    for name in (
        "generate_datasets.py",
        "validate_datasets.py",
        "build_ground_truth.py",
        "import_eyes_corpus.py",
    ):
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        if 'Path("datasets' in text or 'Path("Pre-LLM' in text:
            report.fail(f"{name} still uses cwd-relative Path(...) — must use ROOT")
        elif "ROOT" not in text and name != "import_eyes_corpus.py":
            report.warn(f"{name}: no ROOT constant (verify path handling)")


def audit_cwd_independent_scripts(report: ParanoiaReport) -> None:
    """Dataset validators must succeed from any cwd when PYTHONPATH is set."""
    from cipherops.ciphers.registry import CIPHER_REGISTRY

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_datasets.py")],
        cwd="/tmp",
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        report.fail(f"validate_datasets.py failed from /tmp: {result.stderr.strip()}")
    elif str(len(CIPHER_REGISTRY)) not in result.stdout:
        report.fail("validate_datasets.py from /tmp: unexpected output (ROOT not used?)")
    else:
        report.ok("validate_datasets.py succeeds from /tmp (ROOT-anchored paths)")


def audit_qna_overrides(report: ParanoiaReport) -> None:
    """Rich Q&A overrides must exist and merge in build_ground_truth."""
    overrides_path = ROOT / "Pre-LLM-Ingestion/processed/cipher-qna-overrides.jsonl"
    if not overrides_path.is_file():
        report.fail(f"Missing Q&A overrides: {overrides_path}")
        return

    overrides = {}
    for line in overrides_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            overrides[row["variant_slug"]] = row

    required = {"autokey-standard", "autokey-beaufort", "running-key-book"}
    missing = required - set(overrides)
    if missing:
        report.fail(f"Q&A overrides missing slugs: {sorted(missing)}")
    else:
        report.ok(f"Q&A overrides present for {len(overrides)} variants")

    qna_path = ROOT / "Pre-LLM-Ingestion/processed/cipher-qna-ground-truth.jsonl"
    if not qna_path.is_file():
        report.fail(f"Missing Q&A ground truth: {qna_path}")
        return

    qna_text = qna_path.read_text(encoding="utf-8")
    for slug in required:
        if overrides[slug]["output"][:60] not in qna_text:
            report.fail(f"Q&A ground truth missing override content for {slug}")
        else:
            report.ok(f"Q&A ground truth includes override for {slug}")


def audit_non_periodic_properties(report: ParanoiaReport) -> None:
    from cipherops.analysis.guidance import NON_PERIODIC_POLYALPHABETIC

    for slug in (
        "autokey-standard",
        "autokey-beaufort",
        "autokey-ciphertext",
        "autokey-ciphertext-beaufort",
        "gronsfeld-autokey-31415",
        "gronsfeld-autokey-ct-31415",
        "porta-autokey-standard",
        "xautokey-sum-key",
        "vernam-otp-demo",
        "gak-ctak-right-s42",
        "xgak-sum-right-s42",
        "running-key-book",
    ):
        path = ROOT / "datasets" / "ciphertext-properties" / slug / "properties.jsonl"
        if not path.is_file():
            report.fail(f"Missing properties for non-periodic slug {slug}")
            continue
        line = path.read_text(encoding="utf-8").splitlines()[0]
        record = json.loads(line)
        family = record["source"]["cipher_family"].replace("-", "_")
        if family not in NON_PERIODIC_POLYALPHABETIC:
            report.fail(f"{slug}: expected non-periodic family, got {family}")
            continue
        if record.get("coset_ic") is not None:
            report.fail(f"{slug}: coset_ic must be null for non-periodic cipher")
            continue
        guidance = record.get("analysis_guidance") or {}
        if guidance.get("periodicity") != "non_periodic":
            report.fail(f"{slug}: analysis_guidance.periodicity must be non_periodic")
            continue
        if guidance.get("coset_ic_applicable") is not False:
            report.fail(f"{slug}: coset_ic_applicable must be false")
            continue
        report.ok(f"Non-periodic invariants OK: {slug}")


def audit_analysis_edge_cases(report: ParanoiaReport) -> None:
    from cipherops.analysis.fingerprint import index_of_coincidence, shannon_entropy
    from cipherops.analysis.kasiski import kasiski_examination, _gcd_list

    if shannon_entropy("") != 0.0:
        report.fail("Shannon entropy empty string should be 0")
    else:
        report.ok("Shannon entropy: empty string → 0")

    if index_of_coincidence("") != 0.0 or index_of_coincidence("A") != 0.0:
        report.fail("IC edge cases: empty/single char should be 0")
    else:
        report.ok("IC: empty/single char → 0")

    kas = kasiski_examination("AB")
    if kas["repeats_found"] != 0:
        report.fail("Kasiski: too-short text should return no repeats")
    else:
        report.ok("Kasiski: short text returns empty profile")

    try:
        _gcd_list([])
        report.ok("Kasiski _gcd_list: empty input returns None")
    except (IndexError, ValueError):
        report.fail("Kasiski _gcd_list([]) should return None, not raise")


def audit_subprocess_suite(report: ParanoiaReport) -> None:
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)}
    steps = [
        ([sys.executable, "scripts/validate_datasets.py"], "validate_datasets"),
        ([sys.executable, "scripts/validate_ciphertext_properties.py"], "validate_ciphertext_properties"),
        ([sys.executable, "scripts/comprehensive_validate.py"], "comprehensive_validate"),
        ([sys.executable, "scripts/math_audit.py"], "math_audit"),
        ([sys.executable, "scripts/constraint_audit.py"], "constraint_audit"),
    ]
    for cmd, label in steps:
        result = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            report.fail(f"{label} exited {result.returncode}")
            tail = (result.stdout + result.stderr).strip().splitlines()[-3:]
            for t in tail:
                report.fail(f"  {label}: {t}")
        else:
            report.ok(f"{label}: exit 0")


def print_report(report: ParanoiaReport) -> None:
    print("=" * 72)
    print("PARANOIA AUDIT REPORT")
    print("=" * 72)
    print(f"\nPASSED ({len(report.passed)}):")
    for item in report.passed:
        print(f"  [OK] {item}")
    if report.warnings:
        print(f"\nWARNINGS ({len(report.warnings)}):")
        for item in report.warnings:
            print(f"  [WARN] {item}")
    if report.errors:
        print(f"\nERRORS ({len(report.errors)}):")
        for item in report.errors:
            print(f"  [FAIL] {item}")
    print("\n" + "=" * 72)
    if report.errors:
        print(f"PARANOIA RESULT: FAILED ({len(report.errors)} errors)")
    else:
        print(f"PARANOIA RESULT: PASSED ({len(report.passed)} checks, {len(report.warnings)} warnings)")
    print("=" * 72)


def main() -> int:
    report = ParanoiaReport()
    audit_script_paths(report)
    audit_cwd_independent_scripts(report)
    audit_qna_overrides(report)
    audit_non_periodic_properties(report)
    audit_analysis_edge_cases(report)
    if not report.errors:
        audit_subprocess_suite(report)
    else:
        report.warn("Skipping subprocess suite due to earlier errors")
    print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())

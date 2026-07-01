#!/usr/bin/env python3
"""Comprehensive validation of math refs, registry, datasets, and cipher I/O."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY, PLAIN_SAMPLES, get_cipher
from cipherops.ciphers.utils import sha256_text
from scripts.generate_datasets import _roundtrip_ok


def sha256_json(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = ROOT / "datasets" / "fingerprinted"
UNSOLVED_ROOT = ROOT / "datasets" / "unsolved"
PROPERTIES_ROOT = ROOT / "datasets" / "ciphertext-properties"
GROUND_TRUTH = ROOT / "Pre-LLM-Ingestion" / "processed" / "cipher-ground-truth.jsonl"
MANIFEST = DATASET_ROOT / "manifest.json"
UNSOLVED_MANIFEST = UNSOLVED_ROOT / "manifest.json"
PROPERTIES_MANIFEST = PROPERTIES_ROOT / "manifest.json"

REQUIRED_FIELDS = {
    "id",
    "plaintext",
    "ciphertext",
    "cipher_family",
    "params",
    "math_ref",
    "validation",
    "difficulty",
}

# Ciphers whose ciphertext includes per-run entropy (timestamp, OAEP padding, etc.)
NON_DETERMINISTIC = {"fernet", "rsa-oaep-hybrid"}


@dataclass
class ValidationReport:
    passed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def fail(self, msg: str) -> None:
        self.errors.append(msg)

    def inc(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n


def validate_registry(report: ValidationReport) -> None:
    slugs = [s.slug for s in CIPHER_REGISTRY]
    if len(slugs) != len(set(slugs)):
        report.fail("Registry contains duplicate slugs")
    else:
        report.ok(f"Registry: {len(slugs)} unique cipher variants")

    for spec in CIPHER_REGISTRY:
        math_path = ROOT / spec.math_ref
        if not math_path.is_file():
            report.fail(f"Missing math doc: {spec.math_ref} (slug={spec.slug})")
        elif math_path.stat().st_size < 50:
            report.warn(f"Math doc very short: {spec.math_ref}")

    classical = sum(1 for s in CIPHER_REGISTRY if s.era == "classical")
    modern = sum(1 for s in CIPHER_REGISTRY if s.era == "modern")
    report.ok(f"Era split: {classical} classical, {modern} modern")


def validate_manifest(report: ValidationReport) -> None:
    if not MANIFEST.is_file():
        report.fail(f"Missing manifest: {MANIFEST}")
        return

    manifest = json.loads(MANIFEST.read_text())
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}
    manifest_slugs = {entry["slug"] for entry in manifest}

    missing = registry_slugs - manifest_slugs
    extra = manifest_slugs - registry_slugs
    if missing:
        report.fail(f"Manifest missing slugs: {sorted(missing)}")
    if extra:
        report.fail(f"Manifest has unknown slugs: {sorted(extra)}")
    if not missing and not extra:
        report.ok(f"Manifest aligned with registry ({len(manifest)} entries)")


def validate_ground_truth(report: ValidationReport) -> None:
    if not GROUND_TRUTH.is_file():
        report.fail(f"Missing ground truth: {GROUND_TRUTH}")
        return

    records = [json.loads(line) for line in GROUND_TRUTH.read_text().splitlines() if line.strip()]
    solved_records = [r for r in records if r.get("status", "solved") == "solved"]
    unsolved_records = [r for r in records if r.get("status") == "unsolved"]
    gt_solved_slugs = {r["variant_slug"] for r in solved_records}
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}

    if gt_solved_slugs != registry_slugs:
        report.fail(
            f"Ground truth slug mismatch. missing={sorted(registry_slugs - gt_solved_slugs)} "
            f"extra={sorted(gt_solved_slugs - registry_slugs)}"
        )
    else:
        report.ok(f"Ground truth aligned ({len(solved_records)} solved records)")

    if unsolved_records:
        report.ok(f"Ground truth unsolved corpora: {len(unsolved_records)}")

    for record in solved_records:
        spec = get_cipher(record["variant_slug"])
        if record["math_ref"] != spec.math_ref:
            report.fail(f"Ground truth math_ref mismatch for {record['variant_slug']}")
        if record["cipher_family"] != spec.family:
            report.fail(f"Ground truth family mismatch for {record['variant_slug']}")
        expected_props = f"datasets/ciphertext-properties/{record['variant_slug']}/properties.jsonl"
        if record.get("properties_path") != expected_props:
            report.fail(f"Ground truth properties_path mismatch for {record['variant_slug']}")

    for record in unsolved_records:
        math_path = ROOT / record["math_ref"]
        if not math_path.is_file():
            report.fail(f"Missing unsolved math doc: {record['math_ref']}")
        dataset_path = ROOT / record["dataset_path"]
        if not dataset_path.is_file():
            report.fail(f"Missing unsolved dataset: {record['dataset_path']}")
        props_path = ROOT / record.get("properties_path", "")
        if not props_path.is_file():
            report.fail(f"Missing unsolved properties: {record.get('properties_path')}")


def validate_dataset_file(path: Path, report: ValidationReport) -> int:
    slug = path.parent.name
    spec = get_cipher(slug)
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    record_count = 0

    if len(lines) != len(PLAIN_SAMPLES):
        report.fail(f"{slug}: expected {len(PLAIN_SAMPLES)} records, found {len(lines)}")

    seen_ids: set[str] = set()
    for line_no, line in enumerate(lines, start=1):
        record_count += 1
        prefix = f"{slug}:{line_no}"

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            report.fail(f"{prefix}: invalid JSON: {exc}")
            continue

        missing = REQUIRED_FIELDS - set(record)
        if missing:
            report.fail(f"{prefix}: missing fields {sorted(missing)}")
            continue

        if record["id"] in seen_ids:
            report.fail(f"{prefix}: duplicate id {record['id']}")
        seen_ids.add(record["id"])

        if not record["id"].startswith(slug):
            report.warn(f"{prefix}: id {record['id']!r} does not start with slug {slug}")

        if record["cipher_family"] != spec.family:
            report.fail(f"{prefix}: family {record['cipher_family']!r} != {spec.family!r}")

        if record["math_ref"] != spec.math_ref:
            report.fail(f"{prefix}: math_ref mismatch")

        if record.get("era", spec.era) != spec.era:
            report.fail(f"{prefix}: era mismatch")

        validation = record["validation"]
        if validation.get("encrypt_only") != spec.encrypt_only:
            report.fail(f"{prefix}: encrypt_only flag mismatch")

        expected_hash = sha256_text(record["plaintext"])
        stored_hash = validation.get("plaintext_sha256")
        if stored_hash != expected_hash:
            report.fail(f"{prefix}: plaintext_sha256 mismatch for {record['id']}")
        else:
            report.inc("plaintext_sha256_ok")

        plaintext = record["plaintext"]
        ciphertext = record["ciphertext"]

        if not ciphertext:
            report.fail(f"{prefix}: empty ciphertext")
        if spec.encrypt_only:
            recomputed = spec.encrypt(plaintext)
            if recomputed != ciphertext:
                report.fail(f"{prefix}: encrypt_only digest mismatch for {record['id']}")
            else:
                report.inc("encrypt_only_ok")
            if validation.get("roundtrip_verified") is True:
                report.fail(f"{prefix}: encrypt_only should not be roundtrip_verified")
        else:
            decrypted = spec.decrypt(ciphertext)
            if not _roundtrip_ok(plaintext, decrypted, spec.family):
                report.fail(
                    f"{prefix}: roundtrip failed "
                    f"plaintext={plaintext!r} decrypted={decrypted!r}"
                )
            else:
                report.inc("roundtrip_ok")
            if slug not in NON_DETERMINISTIC:
                reencrypted = spec.encrypt(plaintext)
                if reencrypted != ciphertext:
                    report.fail(f"{prefix}: re-encrypt mismatch (non-deterministic output?)")
                else:
                    report.inc("reencrypt_ok")
            else:
                report.inc("reencrypt_skipped")
            if validation.get("roundtrip_verified") is not True:
                report.fail(f"{prefix}: roundtrip_verified should be true")

        report.inc("records_checked")

    return record_count


def validate_datasets(report: ValidationReport) -> None:
    dataset_files = sorted(DATASET_ROOT.glob("*/data.jsonl"))
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}
    dataset_slugs = {p.parent.name for p in dataset_files}

    missing_dirs = registry_slugs - dataset_slugs
    orphan_dirs = dataset_slugs - registry_slugs
    if missing_dirs:
        report.fail(f"Missing dataset directories: {sorted(missing_dirs)}")
    if orphan_dirs:
        report.fail(f"Orphan dataset directories: {sorted(orphan_dirs)}")

    total_records = 0
    for path in dataset_files:
        total_records += validate_dataset_file(path, report)

    report.ok(f"Dataset files scanned: {len(dataset_files)} ({total_records} total records)")


def validate_plaintext_corpus(report: ValidationReport) -> None:
    """Ensure all datasets use the canonical PLAIN_SAMPLES corpus in order."""
    for path in sorted(DATASET_ROOT.glob("*/data.jsonl")):
        slug = path.parent.name
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        for idx, (record, expected) in enumerate(zip(lines, PLAIN_SAMPLES)):
            if record["plaintext"] != expected:
                report.fail(
                    f"{slug}: plaintext sample {idx + 1} deviates from PLAIN_SAMPLES corpus"
                )
                break
    report.ok(f"Plaintext corpus: {len(PLAIN_SAMPLES)} canonical samples verified across datasets")


UNSOLVED_REQUIRED_FIELDS = {
    "id",
    "plaintext",
    "ciphertext",
    "cipher_family",
    "params",
    "math_ref",
    "validation",
    "era",
    "source",
}


def validate_unsolved_datasets(report: ValidationReport) -> None:
    if not UNSOLVED_MANIFEST.is_file():
        report.warn(f"No unsolved manifest at {UNSOLVED_MANIFEST}")
        return

    manifest = json.loads(UNSOLVED_MANIFEST.read_text())
    for entry in manifest:
        slug = entry["slug"]
        path = ROOT / entry["path"]
        if not path.is_file():
            report.fail(f"Unsolved dataset missing: {path}")
            continue

        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(lines) != entry["count"]:
            report.fail(f"{slug}: expected {entry['count']} records, found {len(lines)}")

        corpus_path = path.parent / "corpus.json"
        if not corpus_path.is_file():
            report.fail(f"{slug}: missing bundled corpus.json")
            continue

        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        deck_size = int(corpus["deck_size"])

        for line_no, line in enumerate(lines, start=1):
            prefix = f"unsolved:{slug}:{line_no}"
            record = json.loads(line)

            missing = UNSOLVED_REQUIRED_FIELDS - set(record)
            if missing:
                report.fail(f"{prefix}: missing fields {sorted(missing)}")
                continue

            if record["plaintext"] is not None:
                report.fail(f"{prefix}: plaintext must be null for unsolved corpus")
            if record.get("era") != "unsolved":
                report.fail(f"{prefix}: era must be 'unsolved'")
            if record["validation"].get("status") != "unsolved":
                report.fail(f"{prefix}: validation.status must be 'unsolved'")
            if record["validation"].get("roundtrip_verified") is not False:
                report.fail(f"{prefix}: roundtrip_verified must be false")

            ct = record["ciphertext"]
            if not isinstance(ct, list) or not ct:
                report.fail(f"{prefix}: ciphertext must be a non-empty integer list")
                continue

            for symbol in ct:
                if not isinstance(symbol, int) or not 0 <= symbol < deck_size:
                    report.fail(f"{prefix}: symbol {symbol!r} out of [0,{deck_size})")
                    break

            expected_hash = sha256_json(ct)
            if record["validation"].get("ciphertext_sha256") != expected_hash:
                report.fail(f"{prefix}: ciphertext_sha256 mismatch")

            idx = record["params"].get("message_index")
            if idx is not None:
                corpus_ct = corpus["ciphertexts"][idx]
                if ct != corpus_ct:
                    report.fail(f"{prefix}: ciphertext diverges from corpus.json message {idx}")
                if ct[1] != 66 or ct[2] != 5:
                    report.fail(f"{prefix}: expected header anomaly CT[1]=66, CT[2]=5")

            report.inc("unsolved_records_checked")

    report.ok(f"Unsolved datasets validated ({len(manifest)} corpora)")


def validate_ciphertext_properties(report: ValidationReport) -> None:
    if not PROPERTIES_MANIFEST.is_file():
        report.fail(f"Missing properties manifest: {PROPERTIES_MANIFEST}")
        return

    from cipherops.analysis.profile import ANALYZER_VERSION, analyze_ciphertext

    manifest = json.loads(PROPERTIES_MANIFEST.read_text())
    attack_vectors = {
        "crib_dragging",
        "brute_force",
        "dictionary",
        "hill_climbing",
        "metaheuristic",
        "side_channel",
    }

    for entry in manifest:
        slug = entry["slug"]
        path = ROOT / entry["path"]
        source = ROOT / entry["source_path"]
        if not path.is_file():
            report.fail(f"Properties missing: {path}")
            continue
        if not source.is_file():
            report.fail(f"Properties source missing: {source}")
            continue

        source_by_id = {
            json.loads(line)["id"]: json.loads(line)
            for line in source.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(lines) != entry["count"]:
            report.fail(f"{slug}: expected {entry['count']} property records, found {len(lines)}")

        for line_no, line in enumerate(lines, start=1):
            prefix = f"properties:{slug}:{line_no}"
            record = json.loads(line)
            if record["id"] not in source_by_id:
                report.fail(f"{prefix}: unknown id {record['id']!r}")
                continue
            if set(record.get("attacks", {})) != attack_vectors:
                report.fail(f"{prefix}: incomplete attack surface")

            src = source_by_id[record["id"]]
            status = "unsolved" if src.get("plaintext") is None else "solved"
            recomputed = analyze_ciphertext(
                src["ciphertext"],
                cipher_family=src["cipher_family"],
                era=src.get("era", "classical"),
                status=status,
                params=src.get("params"),
                deck_size=src.get("params", {}).get("deck_size"),
            )
            stored = record["validation"].get("properties_sha256")
            payload = json.dumps(recomputed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if stored != expected:
                report.fail(f"{prefix}: properties_sha256 mismatch")
            elif record["validation"].get("analyzer_version") != ANALYZER_VERSION:
                report.fail(f"{prefix}: analyzer_version mismatch")
            else:
                report.inc("properties_records_ok")

    report.ok(f"Ciphertext properties validated ({len(manifest)} corpora)")


def validate_live_registry_roundtrip(report: ValidationReport) -> None:
    """Fresh encrypt/decrypt from registry (independent of stored ciphertext)."""
    for spec in CIPHER_REGISTRY:
        for idx, plaintext in enumerate(PLAIN_SAMPLES[:3], start=1):
            ciphertext = spec.encrypt(plaintext)
            if spec.encrypt_only:
                if not ciphertext:
                    report.fail(f"{spec.slug}: live encrypt_only produced empty output sample {idx}")
                continue
            decrypted = spec.decrypt(ciphertext)
            if not _roundtrip_ok(plaintext, decrypted, spec.family):
                report.fail(
                    f"{spec.slug}: live roundtrip failed sample {idx} "
                    f"decrypted={decrypted!r}"
                )
    report.ok("Live registry roundtrip: first 3 PLAIN_SAMPLES per cipher passed")


def print_report(report: ValidationReport) -> None:
    print("=" * 72)
    print("COMPREHENSIVE VALIDATION REPORT")
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

    if report.stats:
        print(f"\nRECORD-LEVEL STATS:")
        for key in sorted(report.stats):
            print(f"  {key}: {report.stats[key]}")

    print("\n" + "=" * 72)
    if report.errors:
        print(f"RESULT: FAILED ({len(report.errors)} errors, {len(report.warnings)} warnings)")
    else:
        print(f"RESULT: PASSED ({len(report.passed)} checks, {len(report.warnings)} warnings)")
    print("=" * 72)


def main() -> int:
    report = ValidationReport()
    validate_registry(report)
    validate_manifest(report)
    validate_ground_truth(report)
    validate_plaintext_corpus(report)
    validate_datasets(report)
    validate_unsolved_datasets(report)
    validate_ciphertext_properties(report)
    validate_live_registry_roundtrip(report)
    print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())

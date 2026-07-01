#!/usr/bin/env python3
"""Validate ciphertext property datasets against live analysis."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cipherops.analysis.profile import ANALYZER_VERSION, analyze_ciphertext

ROOT = Path(__file__).resolve().parents[1]
PROPERTIES_ROOT = ROOT / "datasets" / "ciphertext-properties"
MANIFEST = PROPERTIES_ROOT / "manifest.json"

REQUIRED_TOP = {
    "id",
    "source",
    "stream",
    "fingerprint",
    "frequency",
    "kasiski",
    "ngrams",
    "patterns",
    "attacks",
    "validation",
}

ATTACK_VECTORS = {
    "crib_dragging",
    "brute_force",
    "dictionary",
    "hill_climbing",
    "metaheuristic",
    "side_channel",
}


def _properties_digest(properties: dict) -> str:
    payload = json.dumps(properties, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_file(path: Path, source_path: Path) -> tuple[int, list[str]]:
    errors: list[str] = []
    source_records = {
        json.loads(line)["id"]: json.loads(line)
        for line in source_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    checked = 0

    for line_no, line in enumerate(lines, start=1):
        checked += 1
        prefix = f"{path.parent.name}:{line_no}"
        record = json.loads(line)

        missing = REQUIRED_TOP - set(record)
        if missing:
            errors.append(f"{prefix}: missing fields {sorted(missing)}")
            continue

        if record["id"] not in source_records:
            errors.append(f"{prefix}: id {record['id']!r} not in source corpus")
            continue

        src = source_records[record["id"]]
        attacks = record.get("attacks", {})
        if set(attacks) != ATTACK_VECTORS:
            errors.append(f"{prefix}: attacks must include all vectors {sorted(ATTACK_VECTORS)}")

        for name, entry in attacks.items():
            if entry.get("viable") is None:
                errors.append(f"{prefix}: attacks.{name}.viable missing")

        status = src.get("validation", {}).get("status", "solved")
        if src.get("plaintext") is None:
            status = "unsolved"

        recomputed = analyze_ciphertext(
            src["ciphertext"],
            cipher_family=src["cipher_family"],
            era=src.get("era", "classical"),
            status=status,
            params=src.get("params"),
            deck_size=src.get("params", {}).get("deck_size"),
        )
        stored_hash = record["validation"].get("properties_sha256")
        expected_hash = _properties_digest(recomputed)

        if stored_hash != expected_hash:
            errors.append(f"{prefix}: properties_sha256 mismatch for {record['id']}")
        if record["validation"].get("analyzer_version") != ANALYZER_VERSION:
            errors.append(f"{prefix}: analyzer_version mismatch")

    if len(lines) != len(source_records):
        errors.append(f"{path.parent.name}: expected {len(source_records)} records, found {len(lines)}")

    return checked, errors


def main() -> int:
    if not MANIFEST.is_file():
        print(f"Missing manifest: {MANIFEST}", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    total = 0
    errors: list[str] = []

    for entry in manifest:
        path = ROOT / entry["path"]
        source = ROOT / entry["source_path"]
        if not path.is_file():
            errors.append(f"Missing properties file: {path}")
            continue
        if not source.is_file():
            errors.append(f"Missing source file: {source}")
            continue
        count, file_errors = validate_file(path, source)
        total += count
        errors.extend(file_errors)

    if errors:
        print(f"FAILED: {len(errors)} errors across {total} records")
        for err in errors[:50]:
            print(f"  [FAIL] {err}")
        if len(errors) > 50:
            print(f"  ... and {len(errors) - 50} more")
        return 1

    print(f"validated {len(manifest)} property corpora ({total} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

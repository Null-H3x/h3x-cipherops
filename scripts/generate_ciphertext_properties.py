#!/usr/bin/env python3
"""Generate ciphertext property profiles for fingerprinted and unsolved corpora."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cipherops.analysis.profile import profile_record
from cipherops.ciphers.utils import sha256_text

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINTED = ROOT / "datasets" / "fingerprinted"
UNSOLVED = ROOT / "datasets" / "unsolved"
OUT_ROOT = ROOT / "datasets" / "ciphertext-properties"


def _ciphertext_sha256(ciphertext: str | list) -> str:
    if isinstance(ciphertext, list):
        payload = json.dumps(ciphertext, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return sha256_text(ciphertext)


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def generate_from_source(
    *,
    slug: str,
    source_path: Path,
    out_root: Path,
    corpus_type: str,
) -> dict:
    records = _load_jsonl(source_path)
    out_dir = out_root / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "properties.jsonl"

    properties_records = []
    for record in records:
        ciphertext = record["ciphertext"]
        deck_size = record.get("params", {}).get("deck_size")
        status = record.get("validation", {}).get("status", "solved")
        if record.get("plaintext") is None:
            status = "unsolved"

        prop = profile_record(
            record_id=record["id"],
            ciphertext=ciphertext,
            cipher_family=record["cipher_family"],
            variant_slug=slug,
            era=record.get("era", "classical"),
            status=status,
            params=record.get("params"),
            source_path=str(source_path.relative_to(ROOT)),
            ciphertext_sha256=_ciphertext_sha256(ciphertext),
            deck_size=deck_size,
        )
        properties_records.append(prop)

    with out_path.open("w", encoding="utf-8") as fh:
        for prop in properties_records:
            fh.write(json.dumps(prop, ensure_ascii=False) + "\n")

    return {
        "slug": slug,
        "count": len(properties_records),
        "path": str(out_path.relative_to(ROOT)),
        "corpus_type": corpus_type,
        "source_path": str(source_path.relative_to(ROOT)),
    }


def main() -> None:
    summary = []

    manifest_path = FINGERPRINTED / "manifest.json"
    if manifest_path.is_file():
        for entry in json.loads(manifest_path.read_text(encoding="utf-8")):
            slug = entry["slug"]
            source = ROOT / entry["path"]
            summary.append(
                generate_from_source(
                    slug=slug,
                    source_path=source,
                    out_root=OUT_ROOT,
                    corpus_type="fingerprinted",
                )
            )
            print(f"generated properties for {slug}: {summary[-1]['count']} records")

    unsolved_manifest = UNSOLVED / "manifest.json"
    if unsolved_manifest.is_file():
        for entry in json.loads(unsolved_manifest.read_text(encoding="utf-8")):
            slug = entry["slug"]
            source = ROOT / entry["path"]
            summary.append(
                generate_from_source(
                    slug=slug,
                    source_path=source,
                    out_root=OUT_ROOT,
                    corpus_type="unsolved",
                )
            )
            print(f"generated properties for {slug}: {summary[-1]['count']} records")

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = OUT_ROOT / "manifest.json"
    manifest.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"wrote manifest: {manifest} ({len(summary)} corpora)")


if __name__ == "__main__":
    main()

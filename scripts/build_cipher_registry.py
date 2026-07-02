#!/usr/bin/env python3
"""Build audited cipher registry linking math docs, implementations, and datasets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "datasets" / "cipher-registry.jsonl"

UNSOLVED_CORPORA = [
    {
        "cipher_family": "noita-eye",
        "variant_slug": "noita-eye-messages",
        "params": {
            "deck_size": 83,
            "num_messages": 9,
            "hypothesis": "polyalphabetic_shared_keystream",
        },
        "math_ref": "docs/math-formulas/noita-eye.md",
        "difficulty": None,
        "variants": ["noita-eye-messages"],
        "dataset_path": "datasets/unsolved/noita-eye-messages/data.jsonl",
        "properties_path": "datasets/ciphertext-properties/noita-eye-messages/properties.jsonl",
        "audit_status": "unsolved_corpus_imported",
        "status": "unsolved",
        "source_repo": "https://github.com/Null-H3x/Eyes",
    },
]


def main() -> int:
    records = []
    for spec in CIPHER_REGISTRY:
        records.append(
            {
                "cipher_family": spec.family,
                "variant_slug": spec.slug,
                "params": spec.params,
                "math_ref": spec.math_ref,
                "difficulty": spec.difficulty,
                "variants": list(spec.variants),
                "dataset_path": f"datasets/fingerprinted/{spec.slug}/data.jsonl",
                "properties_path": f"datasets/ciphertext-properties/{spec.slug}/properties.jsonl",
                "audit_status": "math_implementation_verified",
                "status": "solved",
            }
        )

    for corpus in UNSOLVED_CORPORA:
        records.append(dict(corpus))

    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRY_PATH.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    solved = sum(1 for r in records if r.get("status") == "solved")
    unsolved = sum(1 for r in records if r.get("status") == "unsolved")
    print(f"wrote {REGISTRY_PATH} ({len(records)} records: {solved} solved, {unsolved} unsolved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

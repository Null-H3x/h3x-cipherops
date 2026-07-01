#!/usr/bin/env python3
"""Generate validated fingerprinted cipher datasets."""

from __future__ import annotations

import json
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY, PLAIN_SAMPLES
from cipherops.ciphers.utils import clean_alpha, sha256_text


def _normalize_for_compare(text: str, family: str) -> str:
    text = text.upper().replace("J", "I")
    if family in {"playfair", "four_square"}:
        from cipherops.ciphers.polygraphic import _prepare_digraphs

        return "".join(a + b for a, b in _prepare_digraphs(text))
    if family == "hill":
        return clean_alpha(text).rstrip("X")
    if family in {"adfgx", "adfgvx", "bifid", "trifid", "fractionated_morse"}:
        return clean_alpha(text)
    if family in {"baconian", "homophonic", "straddle_checkerboard"}:
        return "".join(ch for ch in text.upper() if ch.isalnum() or ch in "AB")
    if family == "polybius":
        return "".join(ch for ch in text if ch.isdigit())
    return text


def _roundtrip_ok(plaintext: str, decrypted: str, family: str) -> bool:
    if decrypted == plaintext:
        return True
    return _normalize_for_compare(plaintext, family) == _normalize_for_compare(decrypted, family)


def generate_dataset(spec, output_root: Path) -> dict:
    out_dir = output_root / spec.slug
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for idx, plaintext in enumerate(PLAIN_SAMPLES, start=1):
        ciphertext = spec.encrypt(plaintext)
        encrypt_only = spec.encrypt_only
        if not encrypt_only:
            decrypted = spec.decrypt(ciphertext)
            if not _roundtrip_ok(plaintext, decrypted, spec.family):
                raise ValueError(f"Roundtrip failed for {spec.slug} sample {idx}: {decrypted!r} != {plaintext!r}")

        record = {
            "id": f"{spec.slug}-{idx:02d}",
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "cipher_family": spec.family,
            "params": spec.params,
            "math_ref": spec.math_ref,
            "era": spec.era,
            "validation": {
                "plaintext_sha256": sha256_text(plaintext),
                "roundtrip_verified": not encrypt_only,
                "encrypt_only": encrypt_only,
            },
            "difficulty": spec.difficulty,
        }
        if spec.variants:
            record["variants"] = list(spec.variants)
        records.append(record)

    data_path = out_dir / "data.jsonl"
    with data_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"slug": spec.slug, "count": len(records), "path": str(data_path)}


def main() -> None:
    root = Path("datasets/fingerprinted")
    summary = []
    for spec in CIPHER_REGISTRY:
        summary.append(generate_dataset(spec, root))
        print(f"generated {spec.slug}: {summary[-1]['count']} records")

    manifest = root / "manifest.json"
    manifest.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote manifest: {manifest}")


if __name__ == "__main__":
    main()

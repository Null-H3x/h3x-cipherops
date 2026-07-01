#!/usr/bin/env python3
"""Regenerate datasets, ground truth, and run full validation."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], *, label: str) -> None:
    print(f"\n==> {label}")
    print(f"    {' '.join(cmd)}")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(cmd, cwd=ROOT, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh-eyes",
        action="store_true",
        help="Re-import Noita eye corpus from GitHub (Null-H3x/Eyes)",
    )
    parser.add_argument(
        "--skip-regenerate",
        action="store_true",
        help="Skip fingerprinted dataset regeneration",
    )
    args = parser.parse_args()

    if args.refresh_eyes:
        run(
            [sys.executable, "scripts/import_eyes_corpus.py", "--clone"],
            label="Import unsolved Eyes corpus",
        )

    if not args.skip_regenerate:
        run(
            [sys.executable, "scripts/generate_datasets.py"],
            label="Regenerate fingerprinted datasets",
        )

    run(
        [sys.executable, "scripts/generate_ciphertext_properties.py"],
        label="Generate ciphertext property profiles",
    )
    run([sys.executable, "scripts/build_ground_truth.py"], label="Build ground truth")
    run([sys.executable, "scripts/validate_datasets.py"], label="Validate datasets")
    run(
        [sys.executable, "scripts/validate_ciphertext_properties.py"],
        label="Validate ciphertext properties",
    )
    run(
        [sys.executable, "scripts/comprehensive_validate.py"],
        label="Comprehensive validation",
    )

    print("\nSync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

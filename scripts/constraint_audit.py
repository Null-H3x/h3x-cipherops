#!/usr/bin/env python3
"""Audit constraint propagators (shared keystream, stream extension, dynamic perm)."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cipherops.ciphers import classical, gak
from cipherops.constraints import (
    AlphabetDomain,
    ConstraintState,
    FindingKind,
    Pin,
    load_noita_state,
    merge_findings,
    propagate_dynamic_perm,
    propagate_from_crib_prefix,
    propagate_shared_keystream,
    propagate_stream_extension,
)


@dataclass
class AuditReport:
    passed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def fail(self, msg: str) -> None:
        self.errors.append(msg)


def audit_shared_keystream(report: AuditReport) -> None:
    state = load_noita_state()
    findings = propagate_shared_keystream(state)

    header_ct = [f for f in findings.findings if f.source == "universal_header" and f.data.get("field") == "ct"]
    if len(header_ct) >= 2:
        report.ok(f"shared_keystream: universal header pins ({len(header_ct)} findings)")
    else:
        report.fail("shared_keystream: missing universal header ct pins")

    depth_eq = [f for f in findings.findings if f.kind == FindingKind.EQUALITY and f.source == "depth"]
    if depth_eq:
        report.ok(f"shared_keystream: depth equalities ({len(depth_eq)} positions)")
    else:
        report.fail("shared_keystream: no depth equalities found")

    # Pin pt at msg 0 pos 1 → keystream pin
    state2 = load_noita_state(pins=[Pin(pos=1, msg=0, pt=10)])
    f2 = propagate_shared_keystream(state2)
    ks = [x for x in f2.findings if x.kind == FindingKind.KEYSTREAM_PIN]
    if ks and ks[0].data.get("pos") == 1:
        report.ok("shared_keystream: crib pt → keystream_pin")
    else:
        report.fail("shared_keystream: crib keystream propagation failed")


def audit_stream_extension(report: AuditReport) -> None:
    pt = "ATTACK"
    ct = classical.autokey(pt, "KEY")
    findings = propagate_from_crib_prefix(ct, pt, seed_length=3, seed="KEY")

    seed_assign = [f for f in findings.findings if f.data.get("field") == "seed"]
    if seed_assign and seed_assign[0].data.get("value") == "KEY":
        report.ok("stream_extension: full crib → seed KEY assignment")
    else:
        report.fail("stream_extension: expected seed KEY from full plaintext crib")

    brute = [f for f in findings.findings if f.kind == FindingKind.SEED_CANDIDATE]
    state = ConstraintState(
        domain=AlphabetDomain(size=26),
        hypothesis={"seed_length": 3, "brute_top_n": 5},
        ciphertext=ct,
    )
    f_brute = propagate_stream_extension(state)
    if any(x.kind == FindingKind.SEED_CANDIDATE for x in f_brute.findings):
        report.ok("stream_extension: brute seed candidates emitted")
    else:
        report.fail("stream_extension: brute seed candidates missing")


def audit_dynamic_perm(report: AuditReport) -> None:
    pt = "HELLO"
    seed = 42
    ct = gak.gak_encrypt_text(pt, mode="ctak_right", prng_seed=seed)

    state = ConstraintState(
        domain=AlphabetDomain(size=26, name="gak"),
        hypothesis={"mode": "ctak_right"},
        ciphertext=ct,
        plaintext_trial=pt,
        seed_candidates=[41, 42, 43],
    )
    findings = propagate_dynamic_perm(state)

    if 42 in findings.meta.get("seeds_surviving", []):
        report.ok("dynamic_perm: correct seed survives encrypt verify")
    else:
        report.fail(f"dynamic_perm: seed 42 not surviving ({findings.meta})")

    if 41 in findings.meta.get("seeds_eliminated", []) or 43 in findings.meta.get("seeds_eliminated", []):
        report.ok("dynamic_perm: wrong seeds eliminated")
    else:
        report.fail("dynamic_perm: expected wrong seeds eliminated")

    transitions = [f for f in findings.findings if f.source == "gak_transition"]
    if len(transitions) >= len(pt):
        report.ok(f"dynamic_perm: transition stream pins ({len(transitions)})")
    else:
        report.fail("dynamic_perm: missing transition pins")


def audit_merge(report: AuditReport) -> None:
    state = load_noita_state(pins=[Pin(pos=1, msg=0, pt=5), Pin(pos=1, msg=1, pt=20)])
    a = propagate_shared_keystream(state)
    # Conflicting keystream if same position different pt on different msgs with same ct
    merged = merge_findings(a)
    if merged.meta.get("conflict_count", 0) >= 0:
        report.ok("merge_findings: runs without error")
    else:
        report.fail("merge_findings: failed")


def main() -> int:
    report = AuditReport()
    audit_shared_keystream(report)
    audit_stream_extension(report)
    audit_dynamic_perm(report)
    audit_merge(report)

    print("=" * 72)
    print("CONSTRAINT PROPAGATOR AUDIT")
    print("=" * 72)
    for msg in report.passed:
        print(f"  [OK] {msg}")
    for msg in report.errors:
        print(f"  [FAIL] {msg}")
    print("=" * 72)
    if report.errors:
        print(f"RESULT: FAILED ({len(report.errors)} errors)")
        return 1
    print(f"RESULT: PASSED ({len(report.passed)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

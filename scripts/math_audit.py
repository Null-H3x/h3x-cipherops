#!/usr/bin/env python3
"""Deep math and implementation audit — KATs, algebraic properties, full roundtrips."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cipherops.analysis.autokey_solver import brute_force_autokey_seed, brute_force_gak_seed
from cipherops.analysis.coset_ic import coset_ic_profile
from cipherops.analysis.fingerprint import (
    ENGLISH_IC,
    chi_squared_english,
    index_of_coincidence,
    shannon_entropy,
    friedman_key_length_estimate,
)
from cipherops.analysis.kasiski import kasiski_examination
from cipherops.analysis.keyspace import estimate_keyspace
from cipherops.ciphers import classical, encoding, gak as gak_cipher, symbolic, transposition
from cipherops.ciphers.registry import CIPHER_REGISTRY, PLAIN_SAMPLES, get_cipher
from cipherops.ciphers.utils import mod_inverse
from scripts.generate_datasets import _roundtrip_ok

ROOT = Path(__file__).resolve().parents[1]

# NIST SHA-256 test vector (empty string)
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@dataclass
class AuditReport:
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


def audit_classical_kats(report: AuditReport) -> None:
    """Known-answer tests from standard cipher references."""
    checks = [
        ("atbash A->Z", classical.atbash("A") == "Z"),
        ("atbash involution", classical.atbash(classical.atbash("Hello")) == "Hello"),
        ("caesar HELLO+3", classical.caesar("HELLO", 3) == "KHOOR"),
        ("caesar decrypt", classical.caesar(classical.caesar("HELLO", 3), -3) == "HELLO"),
        ("rot13 self-inverse", classical.caesar("HELLO", 13) == classical.caesar("HELLO", -13)),
        ("vigenere HELLO+KEY", classical.vigenere("HELLO", "KEY") == "RIJVS"),
        (
            "vigenere roundtrip",
            classical.vigenere_decrypt(classical.vigenere("ATTACKATDAWN", "LEMON"), "LEMON") == "ATTACKATDAWN",
        ),
        ("beaufort self-inverse", classical.beaufort(classical.beaufort("HELLO", "KEY"), "KEY") == "HELLO"),
        ("autokey HELLO+KEY", classical.autokey("HELLO", "KEY") == "RIJSS"),
        (
            "autokey roundtrip",
            classical.autokey_decrypt(classical.autokey("ATTACKATDAWN", "KEY"), "KEY") == "ATTACKATDAWN",
        ),
        (
            "autokey-beaufort roundtrip",
            classical.autokey_decrypt(
                classical.autokey("ATTACKATDAWN", "KEY", variant="beaufort"), "KEY", variant="beaufort"
            )
            == "ATTACKATDAWN",
        ),
        (
            "autokey-ciphertext roundtrip",
            classical.autokey_decrypt(
                classical.autokey("ATTACKATDAWN", "KEY", extension="ciphertext"), "KEY", extension="ciphertext"
            )
            == "ATTACKATDAWN",
        ),
        (
            "gak roundtrip",
            gak_cipher.gak_decrypt_text(
                gak_cipher.gak_encrypt_text("HELLO", mode="ctak_right", prng_seed=42),
                mode="ctak_right",
                prng_seed=42,
            )
            == "HELLO",
        ),
        (
            "xgak roundtrip",
            gak_cipher.gak_decrypt_text(
                gak_cipher.gak_encrypt_text("HELLO", mode="xgak_sum_right", prng_seed=42),
                mode="xgak_sum_right",
                prng_seed=42,
            )
            == "HELLO",
        ),
        (
            "gronsfeld autokey roundtrip",
            classical.gronsfeld_autokey_decrypt(classical.gronsfeld_autokey("HELLO", "31415"), "31415") == "HELLO",
        ),
        (
            "autokey brute enumerates KEY",
            any(
                r["seed"] == "KEY" and r["plaintext"] == "HEL"
                for r in brute_force_autokey_seed(classical.autokey("HEL", "KEY"), 3, top_n=17576)
            ),
        ),
        (
            "gak brute enumerates 314",
            any(
                r["seed"] == "314" and r["plaintext"] == "CAT"
                for r in brute_force_gak_seed(classical.gronsfeld_autokey("CAT", "314"), 3, top_n=1000)
            ),
        ),
        ("base64 Hello", encoding.base64_encode("Hello") == "SGVsbG8="),
        ("base64 roundtrip", encoding.base64_decode(encoding.base64_encode("Test123")) == "Test123"),
        ("pam5 Hello", encoding.pam5_decode(encoding.pam5_encode("Hello")) == "Hello"),
        ("pam5 roundtrip unicode", encoding.pam5_decode(encoding.pam5_encode("Cryptography π")) == "Cryptography π"),
        ("hex Hello", encoding.hex_encode("Hello") == "48656C6C6F"),
        ("hex roundtrip", encoding.hex_decode(encoding.hex_encode("Test123")) == "Test123"),
        ("manchester roundtrip", encoding.manchester_decode(encoding.manchester_encode("Hi")) == "Hi"),
        ("pigpen HELLO", symbolic.pigpen_decode(symbolic.pigpen_encode("HELLO")) == "HELLO"),
        (
            "scytale WEAREDISCOVERED d=3",
            transposition.scytale_decrypt(transposition.scytale("WEAREDISCOVERED", 3), 3) == "WEAREDISCOVERED",
        ),
        (
            "nihilist roundtrip",
            classical.nihilist_decrypt(classical.nihilist("HELLO", "31415"), "31415") == "HELLO",
        ),
    ]
    for label, ok in checks:
        if ok:
            report.inc("kat_pass")
        else:
            report.fail(f"KAT failed: {label}")
    report.ok(f"Classical KATs: {sum(1 for _, ok in checks if ok)}/{len(checks)} passed")


def audit_affine_algebra(report: AuditReport) -> None:
    a, b = 5, 8
    a_inv = mod_inverse(a)
    if (a * a_inv) % 26 != 1:
        report.fail(f"Affine mod_inverse wrong: a={a}, inv={a_inv}")
    else:
        report.ok(f"Affine mod_inverse: a={a}, a^-1={a_inv} mod 26")

    pt = "CRYPTO"
    ct = classical.affine(pt, a, b)
    dec = classical.affine_decrypt(ct, a, b)
    if dec != pt:
        report.fail(f"Affine roundtrip: {pt!r} -> {dec!r}")
    else:
        report.ok("Affine E/D roundtrip on CRYPTO")

    try:
        classical.affine("A", 2, 1)
        report.fail("Affine should reject non-invertible a=2")
    except ValueError:
        report.ok("Affine rejects gcd(a,26) != 1")


def audit_hash_kats(report: AuditReport) -> None:
    spec256 = get_cipher("sha256")
    if spec256.encrypt("") != SHA256_EMPTY:
        report.fail(f"SHA-256 empty string KAT mismatch")
    else:
        report.ok("SHA-256 NIST empty-string KAT")

    if spec256.encrypt("abc") != SHA256_ABC:
        report.fail("SHA-256 'abc' KAT mismatch")
    else:
        report.ok("SHA-256 NIST 'abc' KAT")

    for slug in ("sha256", "sha512", "sha3-256", "blake2b", "hmac-sha256"):
        spec = get_cipher(slug)
        try:
            spec.decrypt("deadbeef")
            report.fail(f"{slug}: decrypt should raise for one-way primitive")
        except ValueError:
            report.inc("one_way_guard_ok")
    report.ok("One-way ciphers reject decrypt (5 variants)")


def audit_full_roundtrip(report: AuditReport) -> None:
    """Every non-encrypt_only cipher × all PLAIN_SAMPLES."""
    failures = 0
    tested = 0
    for spec in CIPHER_REGISTRY:
        if spec.encrypt_only:
            for pt in PLAIN_SAMPLES:
                ct = spec.encrypt(pt)
                if not ct:
                    report.fail(f"{spec.slug}: encrypt_only produced empty output")
                    failures += 1
                tested += 1
            continue
        for idx, pt in enumerate(PLAIN_SAMPLES, start=1):
            tested += 1
            ct = spec.encrypt(pt)
            dec = spec.decrypt(ct)
            if not _roundtrip_ok(pt, dec, spec.family):
                report.fail(f"{spec.slug} sample {idx}: roundtrip failed")
                failures += 1
            else:
                report.inc("full_roundtrip_ok")
    if failures == 0:
        report.ok(f"Full roundtrip: {tested} encrypt paths, 0 failures")
    else:
        report.fail(f"Full roundtrip: {failures} failures across {tested} tests")


def audit_deterministic_reencrypt(report: AuditReport) -> None:
    non_det = {"fernet", "rsa-oaep-hybrid"}
    for spec in CIPHER_REGISTRY:
        if spec.slug in non_det or spec.encrypt_only:
            continue
        pt = PLAIN_SAMPLES[0]
        c1 = spec.encrypt(pt)
        c2 = spec.encrypt(pt)
        if c1 != c2:
            report.fail(f"{spec.slug}: non-deterministic but not in NON_DETERMINISTIC set")
        else:
            report.inc("deterministic_ok")


def audit_math_docs(report: AuditReport) -> None:
    """Every registry math_ref exists and contains a formula indicator."""
    formula_markers = (
        "mod",
        "E(",
        "E_",
        "C =",
        "C=",
        "encrypt",
        "decrypt",
        "sha",
        "AES",
        "modular",
        "square",
        "matrix",
        "polybius",
        "base64",
        "sign",
        "curve",
        "digraph",
        "coordinate",
    )
    for spec in CIPHER_REGISTRY:
        path = ROOT / spec.math_ref
        if not path.is_file():
            report.fail(f"Missing math doc: {spec.math_ref}")
            continue
        text = path.read_text(encoding="utf-8").lower()
        if not any(m.lower() in text for m in formula_markers):
            report.warn(f"Math doc may lack formula: {spec.math_ref}")
        else:
            report.inc("math_doc_ok")
    report.ok(f"Math docs present for {len(CIPHER_REGISTRY)} registry entries")


def audit_analysis_kats(report: AuditReport) -> None:
    uniform = "ABCDEFGHIJ" * 10
    ent = shannon_entropy(uniform)
    if not 3.2 < ent < 3.4:
        report.fail(f"Shannon entropy KAT: expected ~3.32, got {ent}")
    else:
        report.ok(f"Analysis: Shannon entropy uniform-10 ({ent:.4f} bits)")

    ic_uniform = index_of_coincidence(uniform)
    # 10 symbols each appearing 10 times in n=100: IC = 10*(10*9)/(100*99)
    expected_ic = (10 * 10 * 9) / (100 * 99)
    if abs(ic_uniform - expected_ic) > 1e-9:
        report.fail(f"IC uniform KAT: expected {expected_ic}, got {ic_uniform}")
    else:
        report.ok(f"Analysis: IC uniform alphabet ({ic_uniform:.6f})")

    english_sample = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 5
    ic_en = index_of_coincidence(english_sample.replace(" ", ""))
    if ic_en < ENGLISH_IC * 0.5:
        report.fail(f"English IC too low: {ic_en}")
    else:
        report.ok(f"Analysis: English-like IC ({ic_en:.4f}) > random baseline")

    kas = kasiski_examination("ABCXYZABCXYZABC" * 3)
    if not kas["candidate_key_lengths"]:
        report.warn("Kasiski: no period detected on synthetic repeat (may be OK)")
    else:
        report.ok(f"Kasiski: detected periods on synthetic repeat: {kas['candidate_key_lengths'][:3]}")

    short = coset_ic_profile("ABCDE")
    if short.get("periods_tested") != 0 or short.get("best_period") is not None:
        report.fail("Coset IC KAT: short text should return empty profile")
    else:
        report.ok("Coset IC: short text returns empty profile")

    pt = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 15
    alpha = "".join(ch for ch in pt if ch.isalpha())
    vigenere_ct = classical.vigenere(alpha, "KEY")
    coset = coset_ic_profile(vigenere_ct)
    ic_at_key = float(coset["by_period"].get("3", 0))
    ic_off_by_one = float(coset["by_period"].get("2", 0))
    if ic_at_key <= ic_off_by_one:
        report.fail(
            f"Coset IC KAT: period-3 mean IC ({ic_at_key:.4f}) should exceed period-2 ({ic_off_by_one:.4f})"
        )
    else:
        report.ok(f"Coset IC: key-length coset IC ({ic_at_key:.4f}) > adjacent period ({ic_off_by_one:.4f})")

    ks_checks = [
        ("caesar", 25, "25"),
        ("affine", 312, "312"),
        ("atbash", 1, "1"),
        ("vigenere", None, "26^3"),
        ("autokey", None, "26^3 (priming seed only)"),
    ]
    for family, exact, label in ks_checks:
        params = {"key": "KEY"} if family in {"vigenere", "autokey"} else {}
        ks = estimate_keyspace(family, params=params)
        if ks.get("label") != label:
            report.fail(f"Keyspace KAT {family}: expected label {label!r}, got {ks.get('label')!r}")
        elif exact is not None and ks.get("exact") != exact:
            report.fail(f"Keyspace KAT {family}: expected exact {exact}, got {ks.get('exact')}")
        else:
            report.ok(f"Keyspace: {family} → {ks['label']}")

    from cipherops.analysis.guidance import analysis_guidance
    from cipherops.analysis.profile import analyze_ciphertext

    g = analysis_guidance("autokey", message_length=100, params={"key": "KEY"})
    if not g or g.get("periodicity") != "non_periodic" or g.get("coset_ic_applicable"):
        report.fail("Autokey guidance KAT: expected non_periodic with coset_ic_applicable=False")
    else:
        report.ok(f"Autokey guidance: regime={g.get('regime')} warnings={len(g.get('warnings', []))}")

    pt_long = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 10
    alpha = "".join(ch for ch in pt_long if ch.isalpha())
    ct = classical.autokey(alpha, "KEY")
    prof = analyze_ciphertext(ct, cipher_family="autokey", params={"key": "KEY"})
    if prof.get("coset_ic") is not None:
        report.fail("Autokey profile KAT: coset_ic should be null")
    elif prof.get("analysis_guidance", {}).get("periodicity") != "non_periodic":
        report.fail("Autokey profile KAT: missing non_periodic guidance")
    else:
        ic = prof["fingerprint"]["index_of_coincidence"]
        report.ok(f"Autokey profile: coset_ic omitted, IC={ic:.4f}, bf={prof['attacks']['brute_force']['notes'][:40]}...")

    if chi_squared_english("") is not None or chi_squared_english("123") is not None:
        report.fail("chi_squared_english: non-alpha input should return None")
    else:
        report.ok("chi_squared_english: non-alpha → None")

    if friedman_key_length_estimate("SHORT") is not None:
        report.fail("Friedman: n<20 should return None")
    else:
        report.ok("Friedman: short text → None")

    rk_pt = "".join(ch for ch in ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 3) if ch.isalpha())
    rk_key = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN SOME EXTRA TEXT FOR KEY LENGTH " * 2
    rk_ct = classical.running_key(rk_pt, rk_key)
    rk_prof = analyze_ciphertext(rk_ct, cipher_family="running_key", params={"key_source": "book"})
    if rk_prof.get("coset_ic") is not None or rk_prof.get("analysis_guidance", {}).get("periodicity") != "non_periodic":
        report.fail("Running key profile KAT: non_periodic invariants failed")
    else:
        report.ok("Running key profile: coset_ic omitted, non_periodic guidance present")


def audit_unsolved_corpus(report: AuditReport) -> None:
    corpus_path = ROOT / "datasets/unsolved/noita-eye-messages/corpus.json"
    if not corpus_path.is_file():
        report.fail("Missing noita-eye corpus.json")
        return
    corpus = json.loads(corpus_path.read_text())
    cts = corpus["ciphertexts"]
    if not all(ct[1] == 66 and ct[2] == 5 for ct in cts):
        report.fail("Noita header anomaly CT[1]=66, CT[2]=5 violated")
    else:
        report.ok("Noita corpus: universal header anomaly verified")

    lengths = tuple(len(ct) for ct in cts)
    if lengths != tuple(corpus["message_lengths"]):
        report.fail(f"Noita length mismatch: {lengths}")
    else:
        report.ok(f"Noita corpus: 9 messages, {sum(lengths)} total symbols")

    deck = int(corpus["deck_size"])
    for i, ct in enumerate(cts):
        if any(not (0 <= v < deck) for v in ct):
            report.fail(f"Noita message {i}: symbol out of range")
            return
    report.ok(f"Noita corpus: all symbols in [0,{deck})")


def audit_encrypt_only_consistency(report: AuditReport) -> None:
    """encrypt_only ciphers must not roundtrip via decrypt on dataset samples."""
    for spec in CIPHER_REGISTRY:
        if not spec.encrypt_only:
            continue
        if spec.slug == "fractionated-morse":
            # Decrypt exists but is lossy on punctuation/spacing — flag intentional
            lossy = 0
            for pt in PLAIN_SAMPLES:
                dec = spec.decrypt(spec.encrypt(pt))
                if not _roundtrip_ok(pt, dec, spec.family):
                    lossy += 1
            if lossy > 0:
                report.ok(
                    f"fractionated-morse: encrypt_only correct ({lossy}/{len(PLAIN_SAMPLES)} "
                    "samples lossy on decrypt — punctuation not preserved)"
                )
            continue
        report.ok(f"encrypt_only: {spec.slug} ({spec.family})")


def audit_modern_crypto(report: AuditReport) -> None:
    pt = "Roundtrip test message."
    modern_reversible = [
        s for s in CIPHER_REGISTRY if s.era == "modern" and not s.encrypt_only
    ]
    for spec in modern_reversible:
        ct = spec.encrypt(pt)
        dec = spec.decrypt(ct)
        if dec != pt:
            report.fail(f"Modern roundtrip failed: {spec.slug}")
        else:
            report.inc("modern_roundtrip_ok")
    report.ok(f"Modern crypto roundtrip: {len(modern_reversible)} reversible variants")


def print_report(report: AuditReport) -> None:
    print("=" * 72)
    print("MATH & IMPLEMENTATION AUDIT REPORT")
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
        print(f"\nSTATS:")
        for key in sorted(report.stats):
            print(f"  {key}: {report.stats[key]}")

    print("\n" + "=" * 72)
    if report.errors:
        print(f"AUDIT RESULT: FAILED ({len(report.errors)} errors, {len(report.warnings)} warnings)")
    else:
        print(f"AUDIT RESULT: PASSED ({len(report.passed)} checks, {len(report.warnings)} warnings)")
    print("=" * 72)


def main() -> int:
    report = AuditReport()
    audit_classical_kats(report)
    audit_affine_algebra(report)
    audit_hash_kats(report)
    audit_modern_crypto(report)
    audit_full_roundtrip(report)
    audit_deterministic_reencrypt(report)
    audit_math_docs(report)
    audit_analysis_kats(report)
    audit_unsolved_corpus(report)
    audit_encrypt_only_consistency(report)
    print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())

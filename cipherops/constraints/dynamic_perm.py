"""GAK / XGAK dynamic permutation constraint propagation."""

from __future__ import annotations

from cipherops.ciphers import gak as gak_cipher
from cipherops.ciphers.utils import char_index, clean_alpha
from cipherops.constraints.domain import ConstraintState, FindingKind, FindingsMap, plaintext_as_ints


def _advance_key(p: int, c: int, mode: int, n: int) -> int:
    if mode in (gak_cipher.GAK_CTAK_RIGHT, gak_cipher.GAK_CTAK_LEFT):
        return c
    if mode in (gak_cipher.GAK_PTAK_RIGHT, gak_cipher.GAK_PTAK_LEFT):
        return p
    if mode in (gak_cipher.XGAK_SUM_RIGHT, gak_cipher.XGAK_SUM_LEFT):
        return (p + c) % n
    if mode in (gak_cipher.XGAK_DIFF_RIGHT, gak_cipher.XGAK_DIFF_LEFT):
        return (c - p) % n
    raise ValueError(f"Unknown GAK mode code: {mode}")


def _simulate_encrypt_path(
    pt: list[int],
    sigma: list[list[int]],
    n: int,
    mode: int,
) -> tuple[list[int], list[dict]]:
    """Return ciphertext and per-step transition records."""
    active = sigma[0][:]
    ct: list[int] = []
    steps: list[dict] = []
    for t, p in enumerate(pt):
        c = active[p]
        ct.append(c)
        k = _advance_key(p, c, mode, n)
        steps.append({"t": t, "p": p, "c": c, "k": k, "active_before": active[:]})
        s_k = sigma[k]
        if mode in (
            gak_cipher.GAK_CTAK_RIGHT,
            gak_cipher.GAK_PTAK_RIGHT,
            gak_cipher.XGAK_SUM_RIGHT,
            gak_cipher.XGAK_DIFF_RIGHT,
        ):
            active = [active[s_k[i]] for i in range(n)]
        else:
            active = [s_k[active[i]] for i in range(n)]
    return ct, steps


def propagate_dynamic_perm(state: ConstraintState) -> FindingsMap:
    """
    Test PRNG seed candidates against observed / trial plaintext–ciphertext streams.

    Hypothesis keys:
    - ``mode``: GAK mode name (default ``ctak_right``)
    - ``prng_seed`` or ``seed_candidates``: list of ints to test

    Requires ``ciphertext`` (A–Z) or ``ciphertexts[0]`` (ints) plus optional ``plaintext_trial``.
    """
    mode_name = state.hypothesis.get("mode", "ctak_right")
    mode_code = gak_cipher.MODE_BY_NAME[mode_name]
    n = state.domain.size

    seeds = state.seed_candidates or state.hypothesis.get("seed_candidates")
    if seeds is None and "prng_seed" in state.hypothesis:
        seeds = [int(state.hypothesis["prng_seed"])]
    if not seeds:
        raise ValueError("dynamic_perm propagator requires seed_candidates or hypothesis.prng_seed")

    if state.ciphertext:
        ct_ints = [char_index(ch) for ch in clean_alpha(state.ciphertext)]
    elif state.ciphertexts:
        ct_ints = list(state.ciphertexts[0])
    else:
        raise ValueError("dynamic_perm requires ciphertext or ciphertexts")

    pt_ints = plaintext_as_ints(state.plaintext_trial)
    compare_len = len(ct_ints)
    if pt_ints is not None:
        compare_len = min(compare_len, len(pt_ints))

    out = FindingsMap(
        meta={
            "propagator": "dynamic_perm",
            "mode": mode_name,
            "alphabet_size": n,
            "seeds_tested": len(seeds),
        }
    )

    surviving: list[int] = []

    for seed in seeds:
        sigma = gak_cipher.generate_sigma_tables(seed, n)
        eliminated = False
        reason = ""

        if pt_ints is not None and compare_len > 0:
            trial_pt = pt_ints[:compare_len]
            enc_ct, steps = _simulate_encrypt_path(trial_pt, sigma, n, mode_code)
            if enc_ct != ct_ints[:compare_len]:
                for t in range(compare_len):
                    if enc_ct[t] != ct_ints[t]:
                        reason = f"mismatch at t={t}: expected ct={ct_ints[t]}, got {enc_ct[t]}"
                        out.add(
                            FindingKind.SEED_ELIMINATION,
                            "encrypt_verify",
                            "hard",
                            prng_seed=seed,
                            pos=t,
                            expected_ct=ct_ints[t],
                            actual_ct=enc_ct[t],
                        )
                        break
                eliminated = True
            else:
                for step in steps:
                    out.add(
                        FindingKind.STREAM_PIN,
                        "gak_transition",
                        "propagated",
                        prng_seed=seed,
                        pos=step["t"],
                        p=step["p"],
                        c=step["c"],
                        k=step["k"],
                    )
                surviving.append(seed)
        else:
            # Decrypt-only consistency check on ciphertext prefix
            try:
                dec = gak_cipher.gak_decrypt_ints(ct_ints[:compare_len], sigma, n, mode_code)
                enc_back, _ = _simulate_encrypt_path(dec, sigma, n, mode_code)
                if enc_back != ct_ints[:compare_len]:
                    reason = "decrypt→encrypt roundtrip failed"
                    out.add(
                        FindingKind.SEED_ELIMINATION,
                        "roundtrip",
                        "hard",
                        prng_seed=seed,
                        reason=reason,
                    )
                    eliminated = True
                else:
                    surviving.append(seed)
                    out.add(
                        FindingKind.ASSIGNMENT,
                        "roundtrip",
                        "propagated",
                        prng_seed=seed,
                        field="decrypt_path",
                        length=compare_len,
                    )
            except Exception as exc:  # noqa: BLE001 — propagate diagnostic
                out.add(
                    FindingKind.SEED_ELIMINATION,
                    "decrypt_error",
                    "hard",
                    prng_seed=seed,
                    error=str(exc),
                )
                eliminated = True

        if not eliminated and pt_ints is None:
            continue
        if not eliminated and pt_ints is not None and seed in surviving:
            out.add(
                FindingKind.ASSIGNMENT,
                "encrypt_verify",
                "hard",
                prng_seed=seed,
                field="seed",
                value=seed,
            )

        if eliminated and reason:
            out.meta.setdefault("eliminations", []).append({"seed": seed, "reason": reason})

    out.meta["seeds_surviving"] = surviving
    out.meta["seeds_eliminated"] = [s for s in seeds if s not in surviving]
    return out

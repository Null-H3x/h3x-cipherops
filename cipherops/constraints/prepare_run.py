"""Preflight enrichment between route and run — steps 1–5 in sequence."""

from __future__ import annotations

import re
from typing import Any

from cipherops.analysis.autokey_solver import _english_score
from cipherops.analysis.brute_lane import run_brute_lane
from cipherops.analysis.deck_parse import parse_integer_decks
from cipherops.analysis.profile import analyze_ciphertext
from cipherops.ciphers import encoding
from cipherops.ciphers.classical import autokey_decrypt, gronsfeld_autokey_decrypt
from cipherops.analysis.stream_cipher import stream_decrypt
from cipherops.ciphers.utils import clean_alpha
from cipherops.constraints.crib_hints import merge_crib_pins

COMMON_CRIBS = (
    "THE",
    "AND",
    "THAT",
    "WITH",
    "THIS",
    "HAVE",
    "FROM",
    "THEY",
    "WOULD",
    "THERE",
    "ATTACK",
    "SECRET",
    "MESSAGE",
    "CIPHER",
    "HELLO",
)

NOITA_HEADER_CT = ((1, 66), (2, 5))


def _step1_preflight_brute(
    *,
    ciphertext: str | None,
    propagator: str,
    hypothesis: dict[str, Any],
    classification: dict[str, Any],
    property_profile: dict[str, Any] | None,
    seed_length: int,
) -> dict[str, Any]:
    """Autokey / GAK cheap brute → seed, plaintext_trial, prefix pins."""
    ct = (ciphertext or "").strip()
    if not ct or not clean_alpha(ct):
        return {"skipped": True, "reason": "non_alphabetic_ciphertext"}

    if propagator not in {"stream_extension", "dynamic_perm", "periodic_key", "external_keystream"}:
        return {"skipped": True, "reason": f"propagator={propagator}"}

    profile = property_profile or classification.get("profile") or {}
    if profile.get("symbol_class") and profile["symbol_class"] != "alpha":
        return {"skipped": True, "reason": "not_alpha_stream"}

    lane_map = {
        "stream_extension": "autokey_seed",
        "dynamic_perm": "gak_prng",
        "periodic_key": "periodic_key",
        "external_keystream": "running_key",
    }
    lane = lane_map[propagator]
    gak_min = int(hypothesis.get("prng_seed", 42)) - 50
    gak_max = int(hypothesis.get("prng_seed", 42)) + 50

    try:
        brute = run_brute_lane(
            ciphertext=ct,
            lane=lane,
            propagator=propagator,
            classification=classification,
            hypothesis=hypothesis,
            seed_length=seed_length,
            top_n=5,
            gak_mode=str(hypothesis.get("mode", "ctak_right")),
            gak_seed_min=max(0, gak_min),
            gak_seed_max=max(gak_min, gak_max),
            plaintext_trial=hypothesis.get("plaintext_trial"),
        )
    except ValueError as exc:
        return {"skipped": True, "reason": str(exc)}

    out: dict[str, Any] = {
        "lane": brute["lane"],
        "count": brute["count"],
        "notes": brute.get("notes"),
        "candidates": brute.get("candidates", [])[:5],
    }

    candidates = brute.get("candidates") or []
    if not candidates:
        return out

    top = candidates[0]
    if brute["lane"] == "autokey_seed" and top.get("score", 0) >= 0.35:
        seed = str(top.get("key", ""))
        out["hypothesis_patch"] = dict(top.get("hypothesis_patch") or {})
        out["plaintext_trial"] = top.get("plaintext")
        out["pins"] = [{"pos": i, "pt": ch} for i, ch in enumerate(clean_alpha(seed))]
        out["applied"] = f"seed={seed} score={top.get('score')}"
    elif brute["lane"] == "gak_prng" and candidates:
        seeds = [int(c["key"]) for c in candidates[:5]]
        out["seed_candidates"] = seeds
        out["hypothesis_patch"] = dict(candidates[0].get("hypothesis_patch") or {})
        out["applied"] = f"prng_seeds={seeds[:3]}"
    elif brute["lane"] == "periodic_key" and top.get("score", 0) >= 0.35:
        out["hypothesis_patch"] = dict(top.get("hypothesis_patch") or {})
        out["plaintext_trial"] = top.get("plaintext")
        out["applied"] = f"periodic {top.get('label')} score={top.get('score')}"
    elif brute["lane"] == "running_key" and top.get("score", 0) >= 0.35:
        out["hypothesis_patch"] = dict(top.get("hypothesis_patch") or {})
        out["plaintext_trial"] = top.get("plaintext")
        out["applied"] = f"running_key offset={top.get('key')} score={top.get('score')}"

    return out


def _step2_noita_depth(
    decks: list[list[int]],
    *,
    deck_size: int,
) -> dict[str, Any]:
    """Header check + depth diff preview for shared-keystream corpora."""
    n_msgs = len(decks)
    max_len = max(len(m) for m in decks) if decks else 0

    header_detected = bool(
        max_len > 2
        and all(len(m) > 2 and m[1] == NOITA_HEADER_CT[0][1] and m[2] == NOITA_HEADER_CT[1][1] for m in decks)
    )

    equal_columns: list[dict[str, Any]] = []
    diff_columns: list[dict[str, Any]] = []

    for t in range(max_len):
        cols = [(mi, decks[mi][t]) for mi in range(n_msgs) if t < len(decks[mi])]
        if not cols:
            continue
        vals = [c for _, c in cols]
        unique = set(vals)
        if len(unique) == 1:
            equal_columns.append({"depth": t, "ct": vals[0], "messages": len(cols)})
        else:
            diff_columns.append(
                {
                    "depth": t,
                    "ct_by_msg": {str(mi): v for mi, v in cols},
                    "n_distinct": len(unique),
                }
            )

    diff_columns.sort(key=lambda row: row["n_distinct"], reverse=True)
    top_depths = [row["depth"] for row in diff_columns[:12]]

    pins: list[dict[str, Any]] = []
    if header_detected:
        for pos, ct_val in NOITA_HEADER_CT:
            for mi in range(n_msgs):
                if pos < len(decks[mi]) and decks[mi][pos] == ct_val:
                    pins.append({"pos": pos, "msg": mi, "ct": ct_val})

    return {
        "num_messages": n_msgs,
        "max_depth": max_len,
        "deck_size": deck_size,
        "header_detected": header_detected,
        "equal_column_count": len(equal_columns),
        "diff_column_count": len(diff_columns),
        "top_crib_drag_depths": top_depths,
        "sample_equal": equal_columns[:5],
        "sample_diff": diff_columns[:8],
        "pins": pins,
        "notes": (
            "Universal header CT[1]=66, CT[2]=5 confirmed — use top diff depths for crib-drag."
            if header_detected
            else "Multi-message depth map — crib-drag at high-spread depths."
        ),
    }


def _step3_live_profile(
    *,
    ciphertext: str | None,
    decks: list[list[int]] | None,
    deck_size: int | None,
    hypothesis: dict[str, Any],
    propagator: str,
) -> dict[str, Any]:
    """Live property profile for routed family → seed_length / periodicity hints."""
    family = str(hypothesis.get("family") or _family_from_propagator(propagator))
    status = "unsolved" if propagator == "shared_keystream" else "solved"

    if decks:
        sample = decks[0]
        props = analyze_ciphertext(
            sample,
            cipher_family=family,
            status=status,
            params=dict(hypothesis),
            deck_size=deck_size,
        )
    elif ciphertext:
        props = analyze_ciphertext(
            ciphertext,
            cipher_family=family,
            status=status,
            params=dict(hypothesis),
            deck_size=deck_size,
        )
    else:
        return {"skipped": True, "reason": "no_ciphertext"}

    kasiski = props.get("kasiski") or {}
    coset = props.get("coset_ic") or {}
    guidance = props.get("analysis_guidance") or {}

    inferred_seed_length = int(hypothesis.get("seed_length") or 0)
    gcd = kasiski.get("gcd_of_spacings")
    if not inferred_seed_length and gcd and 1 < int(gcd) <= 4:
        inferred_seed_length = int(gcd)
    best_period = coset.get("best_period")
    if not inferred_seed_length and best_period and 1 < int(best_period) <= 4:
        inferred_seed_length = int(best_period)
    if not inferred_seed_length:
        inferred_seed_length = 3

    props["inferred_seed_length"] = inferred_seed_length
    props["periodicity"] = guidance.get("periodicity")
    return props


def _step4_dictionary_crib(
    *,
    ciphertext: str | None,
    propagator: str,
    hypothesis: dict[str, Any],
    seed_length: int,
) -> dict[str, Any]:
    """Slide common words — emit crib pin candidates for stream ciphers."""
    ct = clean_alpha(ciphertext or "")
    if not ct:
        return {"skipped": True, "reason": "no_alpha_ciphertext"}

    if propagator == "periodic_key":
        return _step4_periodic_crib(ciphertext=ct, hypothesis=hypothesis)
    if propagator == "external_keystream":
        return {"skipped": True, "reason": "use_preflight_running_key_offset"}
    if propagator != "stream_extension":
        return {"skipped": True, "reason": f"propagator={propagator}"}

    family = str(hypothesis.get("family", "autokey"))
    variant = str(hypothesis.get("variant", "standard"))
    extension = str(hypothesis.get("extension", "plaintext"))

    hits: list[dict[str, Any]] = []
    for word in COMMON_CRIBS:
        if len(word) < 3:
            continue
        max_offset = max(0, min(40, len(ct) - len(word) + 1))
        for offset in range(max_offset):
            pins = [{"pos": offset + i, "pt": ch} for i, ch in enumerate(word)]
            score = 0.05 * len(word)
            detail = f"{word}@{offset}"

            if offset == 0 and len(word) >= seed_length:
                seed = word[:seed_length]
                try:
                    if family == "gronsfeld_autokey":
                        plain = gronsfeld_autokey_decrypt(ct, seed, extension=extension)
                    else:
                        plain = stream_decrypt(
                            ct,
                            seed,
                            family=family,
                            variant=variant,
                            extension=extension,
                            mode=str(hypothesis.get("mode", "sum")),
                        )
                    score = _english_score(plain)
                    detail = f"seed={seed} english={score:.3f}"
                except ValueError:
                    score = 0.0

            if score >= 0.35:
                hits.append(
                    {
                        "word": word,
                        "offset": offset,
                        "score": round(score, 4),
                        "pins": pins,
                        "detail": detail,
                    }
                )

    hits.sort(key=lambda row: row["score"], reverse=True)
    top = hits[:8]
    out: dict[str, Any] = {"candidates": top, "count": len(top)}
    if top:
        out["pins"] = top[0]["pins"]
        out["applied"] = top[0]["detail"]
    return out


def _step4_periodic_crib(
    *,
    ciphertext: str,
    hypothesis: dict[str, Any],
) -> dict[str, Any]:
    """Try common cribs against periodic key decrypt at offset 0."""
    from cipherops.analysis.periodic_solver import _decrypt_periodic

    family = str(hypothesis.get("family", "vigenere"))
    key = str(hypothesis.get("key", "KEY"))
    hits: list[dict[str, Any]] = []
    for word in COMMON_CRIBS:
        if len(word) < 3:
            continue
        pins = [{"pos": i, "pt": ch} for i, ch in enumerate(word)]
        try:
            plain = _decrypt_periodic(ciphertext, key, family=family)
            score = _english_score(plain)
        except ValueError:
            score = 0.0
        if score >= 0.35:
            hits.append(
                {
                    "word": word,
                    "offset": 0,
                    "score": round(score, 4),
                    "pins": pins,
                    "detail": f"periodic key={key} english={score:.3f}",
                }
            )
    hits.sort(key=lambda row: row["score"], reverse=True)
    top = hits[:8]
    out: dict[str, Any] = {"candidates": top, "count": len(top)}
    if top:
        out["pins"] = top[0]["pins"]
        out["applied"] = top[0]["detail"]
    return out


def _step5_encoding_peel(
    raw: str,
    *,
    encoding_family: str,
) -> dict[str, Any]:
    """Decode outer encoding layer → inner payload for re-analysis."""
    stripped = re.sub(r"\s+", "", raw)
    if encoding_family == "hex":
        inner = encoding.hex_decode(raw)
    elif encoding_family == "base64":
        inner = encoding.base64_decode(stripped)
    elif encoding_family == "pam5":
        inner = encoding.pam5_decode(stripped)
    else:
        return {"skipped": True, "reason": f"unknown_encoding={encoding_family}"}

    return {
        "encoding": encoding_family,
        "inner": inner,
        "inner_preview": inner[:160],
        "inner_alpha": clean_alpha(inner) if inner else "",
    }


def _family_from_propagator(propagator: str) -> str:
    return {
        "shared_keystream": "noita-eye",
        "stream_extension": "autokey",
        "dynamic_perm": "gak",
        "periodic_key": "vigenere",
        "external_keystream": "running_key",
    }.get(propagator, "unknown")


def _merge_step_results(
    *,
    pins: list[dict[str, Any]],
    hypothesis_patch: dict[str, Any],
    seed_candidates: list[int],
    plaintext_trial: str | None,
    step_result: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[int], str | None]:
    if step_result.get("pins"):
        pins = merge_crib_pins(pins, step_result["pins"])
    if step_result.get("hypothesis_patch"):
        hypothesis_patch = {**hypothesis_patch, **step_result["hypothesis_patch"]}
    if step_result.get("seed_candidates"):
        seed_candidates = list(step_result["seed_candidates"])
    if step_result.get("plaintext_trial"):
        plaintext_trial = str(step_result["plaintext_trial"])
    return pins, hypothesis_patch, seed_candidates, plaintext_trial


def _run_steps_1_to_4(
    *,
    ciphertext: str | None,
    decks: list[list[int]] | None,
    deck_size: int | None,
    propagator: str,
    hypothesis: dict[str, Any],
    classification: dict[str, Any],
    pins: list[dict[str, Any]],
    hypothesis_patch: dict[str, Any],
    seed_candidates: list[int],
    plaintext_trial: str | None,
    property_profile: dict[str, Any] | None,
    depth_preview: dict[str, Any] | None,
    crib_candidates: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    context: str,
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    list[int],
    str | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]],
]:
    work_hypothesis = {**hypothesis, **hypothesis_patch}

    step1 = _step1_preflight_brute(
        ciphertext=ciphertext,
        propagator=propagator,
        hypothesis=work_hypothesis,
        classification=classification,
        property_profile=property_profile,
        seed_length=int(work_hypothesis.get("seed_length") or 3),
    )
    step1["context"] = context
    steps.append({"step": 1, "name": "preflight_brute", **step1})
    pins, hypothesis_patch, seed_candidates, plaintext_trial = _merge_step_results(
        pins=pins,
        hypothesis_patch=hypothesis_patch,
        seed_candidates=seed_candidates,
        plaintext_trial=plaintext_trial,
        step_result=step1,
    )

    if propagator == "shared_keystream" and decks:
        step2 = _step2_noita_depth(decks, deck_size=int(deck_size or max(max(r) for r in decks) + 1))
        step2["context"] = context
        steps.append({"step": 2, "name": "noita_depth", **step2})
        depth_preview = step2
        pins, hypothesis_patch, seed_candidates, plaintext_trial = _merge_step_results(
            pins=pins,
            hypothesis_patch=hypothesis_patch,
            seed_candidates=seed_candidates,
            plaintext_trial=plaintext_trial,
            step_result=step2,
        )
    else:
        steps.append({"step": 2, "name": "noita_depth", "skipped": True, "context": context})

    step3 = _step3_live_profile(
        ciphertext=ciphertext,
        decks=decks,
        deck_size=deck_size,
        hypothesis={**hypothesis, **hypothesis_patch},
        propagator=propagator,
    )
    step3_record: dict[str, Any] = {"step": 3, "name": "live_profile", "context": context}
    if step3.get("skipped"):
        step3_record.update(step3)
    else:
        property_profile = step3
        if step3.get("inferred_seed_length"):
            hypothesis_patch.setdefault("seed_length", step3["inferred_seed_length"])
        step3_record["profile"] = {
            key: step3[key]
            for key in (
                "stream",
                "fingerprint",
                "kasiski",
                "coset_ic",
                "analysis_guidance",
                "inferred_seed_length",
                "periodicity",
            )
            if key in step3
        }
    steps.append(step3_record)

    seed_len = int(hypothesis_patch.get("seed_length") or (property_profile or {}).get("inferred_seed_length") or 3)
    step4 = _step4_dictionary_crib(
        ciphertext=ciphertext,
        propagator=propagator,
        hypothesis={**hypothesis, **hypothesis_patch},
        seed_length=seed_len,
    )
    step4["context"] = context
    steps.append({"step": 4, "name": "dictionary_crib", **step4})
    if step4.get("candidates"):
        crib_candidates = step4["candidates"]
    pins, hypothesis_patch, seed_candidates, plaintext_trial = _merge_step_results(
        pins=pins,
        hypothesis_patch=hypothesis_patch,
        seed_candidates=seed_candidates,
        plaintext_trial=plaintext_trial,
        step_result=step4,
    )

    return pins, hypothesis_patch, seed_candidates, plaintext_trial, property_profile, depth_preview, crib_candidates


def prepare_run(
    classification: dict[str, Any],
    hypothesis_index: int = 0,
    *,
    ciphertext: str | None = None,
    ciphertexts: list[list[int]] | None = None,
    pins: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Run preflight steps 1–5 in sequence.

    Steps 1–4 enrich pins/seeds/profile; step 5 peels encoding and re-runs 1–4 on inner text.
    """
    hyps = classification.get("hypotheses") or []
    if not hyps or hypothesis_index >= len(hyps):
        raise ValueError("No hypothesis at index")

    h = hyps[hypothesis_index]
    propagator = str(h.get("dash_propagator") or h.get("propagator") or "none")
    hypothesis = dict(h.get("hypothesis") or {})

    work_ct = (ciphertext or "").strip() or None
    work_decks = ciphertexts
    deck_size = h.get("deck_size")

    if work_decks is not None:
        work_ct = None
    elif work_ct:
        parsed = parse_integer_decks(work_ct)
        if parsed:
            work_decks, inferred_size = parsed
            deck_size = deck_size or inferred_size
            work_ct = None

    merged_pins = list(pins or [])
    hypothesis_patch: dict[str, Any] = {}
    seed_candidates: list[int] = []
    plaintext_trial: str | None = None
    property_profile: dict[str, Any] | None = None
    depth_preview: dict[str, Any] | None = None
    crib_candidates: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []

    merged_pins, hypothesis_patch, seed_candidates, plaintext_trial, property_profile, depth_preview, crib_candidates = (
        _run_steps_1_to_4(
            ciphertext=work_ct,
            decks=work_decks,
            deck_size=int(deck_size) if deck_size else None,
            propagator=propagator,
            hypothesis=hypothesis,
            classification=classification,
            pins=merged_pins,
            hypothesis_patch=hypothesis_patch,
            seed_candidates=seed_candidates,
            plaintext_trial=plaintext_trial,
            property_profile=property_profile,
            depth_preview=depth_preview,
            crib_candidates=crib_candidates,
            steps=steps,
            context="initial",
        )
    )

    encoding_family: str | None = None
    if h.get("needs_conversion"):
        encoding_family = str(h.get("family"))
    elif classification.get("profile", {}).get("peel_first"):
        encoding_family = str(classification["profile"]["peel_first"])

    peeled = False
    if encoding_family in {"hex", "base64", "pam5"} and (work_ct or ciphertext):
        raw = work_ct or (ciphertext or "").strip()
        try:
            step5 = _step5_encoding_peel(raw, encoding_family=encoding_family)
            step5["context"] = "peel"
            steps.append({"step": 5, "name": "encoding_peel", **step5})
            inner = step5.get("inner") or ""
            peeled = True
            work_ct = inner
            work_decks = None
            parsed_inner = parse_integer_decks(inner)
            if parsed_inner:
                work_decks, deck_size = parsed_inner
                work_ct = None
            else:
                deck_size = deck_size or 26

            merged_pins, hypothesis_patch, seed_candidates, plaintext_trial, property_profile, depth_preview, crib_candidates = (
                _run_steps_1_to_4(
                    ciphertext=work_ct,
                    decks=work_decks,
                    deck_size=int(deck_size) if deck_size else None,
                    propagator=propagator,
                    hypothesis=hypothesis,
                    classification=classification,
                    pins=merged_pins,
                    hypothesis_patch=hypothesis_patch,
                    seed_candidates=seed_candidates,
                    plaintext_trial=plaintext_trial,
                    property_profile=property_profile,
                    depth_preview=depth_preview,
                    crib_candidates=crib_candidates,
                    steps=steps,
                    context="after_peel",
                )
            )
        except (ValueError, UnicodeDecodeError) as exc:
            steps.append({"step": 5, "name": "encoding_peel", "error": str(exc), "encoding": encoding_family})
    else:
        steps.append({"step": 5, "name": "encoding_peel", "skipped": True, "reason": "no_encoding_layer"})

    notes: list[str] = []
    for step in steps:
        if step.get("applied"):
            notes.append(f"{step.get('name')}: {step['applied']}")
        elif step.get("notes") and step.get("name") == "noita_depth":
            notes.append(str(step["notes"]))

    return {
        "steps": steps,
        "pins": merged_pins,
        "hypothesis_patch": hypothesis_patch,
        "seed_candidates": seed_candidates,
        "plaintext_trial": plaintext_trial,
        "ciphertext": work_ct,
        "ciphertexts": work_decks,
        "deck_size": deck_size,
        "property_profile": property_profile,
        "depth_preview": depth_preview,
        "crib_candidates": crib_candidates,
        "propagator": propagator,
        "peeled": peeled,
        "notes": notes,
    }


def merge_prepare_into_payload(payload: dict[str, Any], prepare: dict[str, Any]) -> dict[str, Any]:
    """Apply prepare_run output onto a dash analyze payload."""
    out = dict(payload)
    if prepare.get("ciphertext"):
        out["ciphertext"] = prepare["ciphertext"]
    if prepare.get("ciphertexts"):
        out["ciphertexts"] = prepare["ciphertexts"]
    if prepare.get("deck_size"):
        out["deck_size"] = prepare["deck_size"]
    if prepare.get("pins"):
        out["pins"] = merge_crib_pins(out.get("pins") or [], prepare["pins"])
    if prepare.get("hypothesis_patch"):
        base = dict(out.get("hypothesis") or {})
        base.update(prepare["hypothesis_patch"])
        out["hypothesis"] = base
    if prepare.get("seed_candidates") and out.get("propagator") == "dynamic_perm":
        out["seed_candidates"] = prepare["seed_candidates"]
    if prepare.get("plaintext_trial"):
        out["plaintext"] = prepare["plaintext_trial"]
    return out

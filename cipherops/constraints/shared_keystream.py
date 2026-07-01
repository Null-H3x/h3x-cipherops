"""Shared position-indexed keystream propagation (Noita depth model)."""

from __future__ import annotations

from cipherops.constraints.domain import (
    AlphabetDomain,
    ConstraintState,
    FindingKind,
    FindingsMap,
    Pin,
    coerce_symbol,
)


def _combiner_delta(pt: int, ct: int, combiner: str, mod: int) -> int:
    if combiner == "add":
        return (ct - pt) % mod
    if combiner in {"subtract", "beaufort"}:
        return (pt - ct) % mod
    raise ValueError(f"Unknown combiner: {combiner}")


def _pt_from_keystream(ct: int, k: int, combiner: str, mod: int) -> int:
    if combiner == "add":
        return (ct - k) % mod
    if combiner in {"subtract", "beaufort"}:
        return (ct + k) % mod
    raise ValueError(f"Unknown combiner: {combiner}")


def propagate_shared_keystream(state: ConstraintState) -> FindingsMap:
    """
    Propagate constraints for ``C_i[t] = combiner(P_i[t], K[t])`` with shared ``K[t]``.

    Emits:
    - ``equality`` when all messages share the same ciphertext at ``t``
    - ``pt_difference`` when ciphertext differs across messages at ``t``
    - ``keystream_pin`` when a plaintext pin fixes ``K[t]``
    - ``assignment`` for derived plaintext across messages from known ``K[t]``
    """
    if not state.ciphertexts:
        raise ValueError("shared_keystream propagator requires state.ciphertexts")

    mod = state.domain.size
    combiner = state.hypothesis.get("combiner", "add")
    out = FindingsMap(meta={"propagator": "shared_keystream", "combiner": combiner, "mod": mod})

    messages = state.ciphertexts
    n_msgs = len(messages)
    max_len = max(len(m) for m in messages)

    # Explicit pins (cribs)
    pinned_pt: dict[tuple[int | str | None, int], int] = {}
    pinned_ct: dict[tuple[int | str | None, int], int] = {}
    for pin in state.pins:
        msg_key = pin.msg
        if pin.ct is not None:
            pinned_ct[(msg_key, pin.pos)] = coerce_symbol(pin.ct, mod=mod)
        if pin.pt is not None:
            pinned_pt[(msg_key, pin.pos)] = coerce_symbol(pin.pt, mod=mod)

    keystream: dict[int, int] = {}

    for t in range(max_len):
        cols: list[tuple[int, int]] = []
        for mi, msg in enumerate(messages):
            if t >= len(msg):
                continue
            cols.append((mi, msg[t]))

        if not cols:
            continue

        ct_vals = [c for _, c in cols]
        if len(set(ct_vals)) == 1:
            out.add(
                FindingKind.EQUALITY,
                "depth",
                "hard",
                pos=t,
                field="pt",
                scope="all_messages_with_symbol",
                msg_indices=[mi for mi, _ in cols],
                ct=ct_vals[0],
                note="Identical ciphertext at t implies identical plaintext under shared K[t]",
            )

        # Pairwise plaintext differences where ciphertext differs
        for i in range(len(cols)):
            for j in range(i + 1, len(cols)):
                mi, ci = cols[i]
                mj, cj = cols[j]
                if ci == cj:
                    continue
                delta = (ci - cj) % mod
                out.add(
                    FindingKind.PT_DIFFERENCE,
                    "depth",
                    "propagated",
                    pos=t,
                    msg_a=mi,
                    msg_b=mj,
                    ct_a=ci,
                    ct_b=cj,
                    pt_delta_mod= delta if combiner == "add" else (-delta) % mod,
                )

        # Apply pins at this position
        for (msg_key, pos), pt_val in pinned_pt.items():
            if pos != t:
                continue
            targets = range(n_msgs) if msg_key is None else [msg_key]
            for mi in targets:
                if mi >= n_msgs or t >= len(messages[mi]):
                    continue
                ct_val = messages[mi][t]
                k_val = _combiner_delta(pt_val, ct_val, combiner, mod)
                if t in keystream and keystream[t] != k_val:
                    out.add(
                        FindingKind.CONFLICT,
                        "crib+depth",
                        "hard",
                        pos=t,
                        keystream_values=[keystream[t], k_val],
                    )
                else:
                    keystream[t] = k_val
                    out.add(
                        FindingKind.KEYSTREAM_PIN,
                        "crib",
                        "hard",
                        pos=t,
                        value=k_val,
                        derived_from={"msg": mi, "pt": pt_val, "ct": ct_val},
                    )

        for (msg_key, pos), ct_val in pinned_ct.items():
            if pos != t:
                continue
            if msg_key is None:
                if len(set(ct_vals)) == 1 and ct_vals[0] == ct_val:
                    out.add(
                        FindingKind.ASSIGNMENT,
                        "crib",
                        "hard",
                        pos=t,
                        field="ct",
                        msg="all",
                        value=ct_val,
                    )
            else:
                mi = msg_key if isinstance(msg_key, int) else None
                if mi is not None and mi < n_msgs and messages[mi][t] == ct_val:
                    out.add(
                        FindingKind.ASSIGNMENT,
                        "crib",
                        "hard",
                        pos=t,
                        field="ct",
                        msg=mi,
                        value=ct_val,
                    )

        if t in keystream:
            k_val = keystream[t]
            for mi, ct_val in cols:
                pt_val = _pt_from_keystream(ct_val, k_val, combiner, mod)
                out.add(
                    FindingKind.ASSIGNMENT,
                    "keystream_pin",
                    "propagated",
                    pos=t,
                    field="pt",
                    msg=mi,
                    value=pt_val,
                    keystream=k_val,
                )

    # Universal header pins (Noita: CT[1]=66, CT[2]=5 in 1-based journal notation → index 1,2)
    if state.hypothesis.get("detect_universal_header", True):
        for t, expected in ((1, 66), (2, 5)):
            if all(t < len(m) and m[t] == expected for m in messages):
                out.add(
                    FindingKind.ASSIGNMENT,
                    "universal_header",
                    "hard",
                    pos=t,
                    field="ct",
                    msg="all",
                    value=expected,
                )
                out.add(
                    FindingKind.EQUALITY,
                    "universal_header",
                    "hard",
                    pos=t,
                    field="pt",
                    scope="all_messages",
                    ct=expected,
                )

    out.meta["positions_with_keystream"] = sorted(keystream.keys())
    out.meta["keystream_partial"] = {str(k): v for k, v in sorted(keystream.items())}
    return out


def load_noita_state(
    corpus_path: str | None = None,
    *,
    pins: list[Pin] | None = None,
) -> ConstraintState:
    """Build ``ConstraintState`` from bundled Noita eye corpus JSON."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    path = Path(corpus_path) if corpus_path else root / "datasets/unsolved/noita-eye-messages/corpus.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    domain = AlphabetDomain(
        size=int(raw["deck_size"]),
        name="noita-eye",
    )
    return ConstraintState(
        domain=domain,
        hypothesis={"combiner": "add", "family": "shared_keystream"},
        pins=pins or [],
        ciphertexts=raw["ciphertexts"],
        message_labels=raw.get("message_labels"),
    )

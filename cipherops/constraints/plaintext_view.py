"""Assemble partial / full plaintext views from grounded pins and findings."""

from __future__ import annotations

from typing import Any

from cipherops.ciphers.classical import autokey_decrypt, gronsfeld_autokey_decrypt
from cipherops.ciphers.utils import clean_alpha, index_char


def _pt_key(msg: Any, pos: int) -> tuple[int | None, int]:
    if msg == "all":
        return (None, pos)
    if isinstance(msg, int):
        return (msg, pos)
    return (None, pos)


def collect_pt_cells(
    *,
    findings: list[dict[str, Any]],
    grounded_pins: list[dict[str, Any]],
    prefer_validated: bool = True,
) -> dict[tuple[int | None, int], dict[str, Any]]:
    """Merge pt assignments from grounded pins and finding rows."""
    cells: dict[tuple[int | None, int], dict[str, Any]] = {}

    def _set(key: tuple[int | None, int], pt: int, source: str, confidence: str) -> None:
        existing = cells.get(key)
        rank = {"hard": 3, "propagated": 2, "heuristic": 1}
        if existing and rank.get(existing["confidence"], 0) > rank.get(confidence, 0):
            return
        cells[key] = {"pt": pt, "source": source, "confidence": confidence}

    for pin in grounded_pins:
        if pin.get("pt") is None:
            continue
        msg = pin.get("msg")
        pos = int(pin["pos"])
        _set(_pt_key(msg, pos), int(pin["pt"]), "grounded_pin", "hard")

    for row in findings:
        if row.get("kind") != "assignment":
            continue
        data = row.get("data") or {}
        if data.get("field") != "pt":
            continue
        msg = data.get("msg")
        pos = int(data["pos"])
        conf = row.get("confidence", "propagated")
        if prefer_validated and conf == "heuristic":
            continue
        _set(_pt_key(msg, pos), int(data["value"]), row.get("source", "finding"), conf)

    return cells


def _format_symbol(pt: int, *, alphabetic: bool, mod: int) -> str:
    if alphabetic and mod == 26:
        return index_char(pt)
    return str(pt)


def assemble_plaintext_view(
    *,
    findings: list[dict[str, Any]],
    grounded_pins: list[dict[str, Any]],
    corpus_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build per-message plaintext strings with unknown positions marked.

    ``corpus_meta`` may include ciphertext, ciphertexts, message_labels, hypothesis,
    propagator, deck_size, plaintext_trial.
    """
    meta = corpus_meta or {}
    mod = int(meta.get("deck_size", 26))
    alphabetic = bool(meta.get("ciphertext")) and not meta.get("ciphertexts")
    propagator = meta.get("propagator")
    hypothesis = dict(meta.get("hypothesis") or {})

    cells = collect_pt_cells(findings=findings, grounded_pins=grounded_pins)

    # Expand msg=None (all-message) assignments to every message index present.
    msg_indices: set[int] = set()
    ciphertexts = meta.get("ciphertexts")
    if ciphertexts:
        msg_indices.update(range(len(ciphertexts)))
    for msg, _pos in cells:
        if isinstance(msg, int):
            msg_indices.add(msg)
    if not msg_indices:
        msg_indices.add(0)

    expanded: dict[tuple[int, int], dict[str, Any]] = {}
    for (msg, pos), cell in cells.items():
        if msg is None:
            for mi in msg_indices:
                expanded[(mi, pos)] = cell
        else:
            expanded[(int(msg), pos)] = cell

    # Message lengths from ciphertext structure.
    lengths: dict[int, int] = {}
    if ciphertexts:
        for mi, row in enumerate(ciphertexts):
            lengths[mi] = len(row)
    elif meta.get("ciphertext"):
        lengths[0] = len(clean_alpha(meta["ciphertext"]))

    if expanded:
        for mi in msg_indices:
            max_pos = max((p for m, p in expanded if m == mi), default=-1)
            lengths[mi] = max(lengths.get(mi, 0), max_pos + 1)

    labels = meta.get("message_labels") or []
    messages_out: list[dict[str, Any]] = []
    total_known = 0
    total_slots = 0

    for mi in sorted(msg_indices):
        length = lengths.get(mi, 0)
        symbols: list[str] = []
        details: list[dict[str, Any]] = []
        known = 0
        for pos in range(length):
            cell = expanded.get((mi, pos))
            if cell is None:
                symbols.append("·")
                details.append({"pos": pos, "known": False})
            else:
                sym = _format_symbol(cell["pt"], alphabetic=alphabetic, mod=mod)
                symbols.append(sym)
                known += 1
                details.append(
                    {
                        "pos": pos,
                        "known": True,
                        "pt": cell["pt"],
                        "symbol": sym,
                        "source": cell["source"],
                        "confidence": cell["confidence"],
                    }
                )
        total_known += known
        total_slots += length
        label = labels[mi] if mi < len(labels) else f"msg{mi}"
        messages_out.append(
            {
                "msg": mi,
                "label": label,
                "length": length,
                "known": known,
                "coverage": round(known / length, 4) if length else 0.0,
                "text": "".join(symbols),
                "cells": details,
            }
        )

    full_decrypt: dict[str, Any] | None = None
    ct = meta.get("ciphertext")
    if alphabetic and ct and propagator == "stream_extension":
        seed = hypothesis.get("seed")
        for row in findings:
            if row.get("kind") != "assignment":
                continue
            data = row.get("data") or {}
            if data.get("field") == "seed" and row.get("confidence") == "hard":
                seed = data.get("value", seed)
                break
        if seed:
            family = hypothesis.get("family", "autokey")
            extension = hypothesis.get("extension", "plaintext")
            variant = hypothesis.get("variant", "standard")
            try:
                if family == "gronsfeld_autokey":
                    plain = gronsfeld_autokey_decrypt(ct, str(seed), extension=extension)
                else:
                    plain = autokey_decrypt(ct, str(seed), variant=variant, extension=extension)
                full_decrypt = {
                    "msg": 0,
                    "label": "full_decrypt",
                    "seed": str(seed),
                    "text": plain,
                    "source": "verified_seed",
                }
            except ValueError:
                full_decrypt = None

    return {
        "alphabetic": alphabetic,
        "mod": mod,
        "propagator": propagator,
        "messages": messages_out,
        "full_decrypt": full_decrypt,
        "coverage": {
            "known": total_known,
            "total": total_slots,
            "ratio": round(total_known / total_slots, 4) if total_slots else 0.0,
        },
        "cell_count": len(expanded),
    }

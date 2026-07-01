"""Generate crib pin suggestions from constraint findings (for dashboard / API)."""

from __future__ import annotations

from typing import Any

ACTIONABLE_KINDS = frozenset(
    {
        "pt_difference",
        "equality",
        "keystream_pin",
        "assignment",
        "stream_pin",
    }
)


def crib_pins_from_finding(
    finding: dict[str, Any],
    *,
    deck_size: int = 83,
    anchor_pt: int = 10,
) -> dict[str, Any]:
    """
    Build suggested crib pins and a human hint from one finding record.

    Returns ``{"pins": [...], "hint": str, "actionable": bool}``.
    """
    kind = finding.get("kind")
    data = finding.get("data") or {}

    if kind == "pt_difference":
        pos = int(data["pos"])
        msg_a = int(data["msg_a"])
        msg_b = int(data["msg_b"])
        delta = int(data.get("pt_delta_mod", (int(data["ct_a"]) - int(data["ct_b"])) % deck_size))
        pt_b = (anchor_pt + delta) % deck_size
        return {
            "actionable": True,
            "kind": kind,
            "pins": [
                {"pos": pos, "msg": msg_a, "pt": anchor_pt},
                {"pos": pos, "msg": msg_b, "pt": pt_b},
            ],
            "hint": (
                f"pt_difference at pos {pos}: msg {msg_b} pt = (msg {msg_a} pt + {delta}) mod {deck_size}. "
                f"Anchored msg {msg_a} pt={anchor_pt} → msg {msg_b} pt={pt_b}. Edit anchor pt and re-apply."
            ),
            "formula": {
                "pos": pos,
                "msg_a": msg_a,
                "msg_b": msg_b,
                "pt_delta_mod": delta,
                "mod": deck_size,
                "anchor_pt": anchor_pt,
            },
        }

    if kind == "equality":
        pos = int(data["pos"])
        msg_indices = data.get("msg_indices")
        msg = int(msg_indices[0]) if msg_indices else 0
        return {
            "actionable": True,
            "kind": kind,
            "pins": [{"pos": pos, "msg": msg, "pt": anchor_pt}],
            "hint": (
                f"equality at pos {pos}: identical ciphertext → identical plaintext on all messages. "
                f"Pin pt on any one message (suggested msg {msg}, pt={anchor_pt})."
            ),
        }

    if kind == "keystream_pin":
        pos = int(data["pos"])
        derived = data.get("derived_from") or {}
        if derived:
            pin = {
                "pos": pos,
                "msg": int(derived["msg"]),
                "pt": int(derived["pt"]),
            }
            return {
                "actionable": True,
                "kind": kind,
                "pins": [pin],
                "hint": f"Re-apply crib that fixed K[{pos}]={data.get('value')} (from msg {pin['msg']} pt={pin['pt']}).",
            }
        return {
            "actionable": True,
            "kind": kind,
            "pins": [{"pos": pos, "msg": 0, "pt": anchor_pt}],
            "hint": f"Keystream K[{pos}]={data.get('value')}. Pin pt on one message (placeholder pt={anchor_pt}).",
        }

    if kind == "assignment" and data.get("field") == "pt":
        msg = data.get("msg")
        pin: dict[str, Any] = {"pos": int(data["pos"]), "pt": data["value"]}
        if isinstance(msg, int):
            pin["msg"] = msg
        return {
            "actionable": True,
            "kind": kind,
            "pins": [pin],
            "hint": "Grounded pt assignment — use as crib pin.",
        }

    if kind == "stream_pin" and data.get("role") == "seed":
        idx = int(data["stream_index"])
        return {
            "actionable": True,
            "kind": kind,
            "pins": [{"pos": idx, "pt": data.get("value", anchor_pt)}],
            "hint": f"Seed stream index {idx} — pin as plaintext crib at position {idx}.",
        }

    return {
        "actionable": False,
        "kind": kind,
        "pins": [],
        "hint": f"No crib template for finding kind {kind!r}.",
    }


def merge_crib_pins(existing: list[dict[str, Any]], new_pins: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge pin lists; later entries override same (msg, pos)."""
    keyed: dict[tuple[Any, ...], dict[str, Any]] = {}
    for pin in existing + new_pins:
        key = (pin.get("msg"), pin.get("pos"))
        keyed[key] = pin
    return list(keyed.values())

"""Heuristic cipher-family classification from ciphertext statistics."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from cipherops.analysis.fingerprint import ENGLISH_IC, RANDOM_IC_26, fingerprint_metrics
from cipherops.analysis.kasiski import kasiski_examination
from cipherops.analysis.profile import analyze_ciphertext
from cipherops.analysis.stream import normalize_stream

PropagatorName = Literal["shared_keystream", "stream_extension", "dynamic_perm", "none"]
DashMode = Literal["custom", "noita", "fingerprinted", "preset", "none"]


@dataclass
class ClassHypothesis:
    family: str
    label: str
    confidence: float
    propagator: PropagatorName
    dash_mode: DashMode
    reasoning: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    dataset_slug: str | None = None
    dash_propagator: str | None = None
    deck_size: int | None = None
    hypothesis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "propagator": self.propagator,
            "dash_mode": self.dash_mode,
            "reasoning": self.reasoning,
            "actions": self.actions,
            "dataset_slug": self.dataset_slug,
            "dash_propagator": self.dash_propagator,
            "deck_size": self.deck_size,
            "hypothesis": self.hypothesis,
        }


def _parse_decks(raw: str | list | None) -> list[list[int]] | None:
    if raw is None:
        return None
    if isinstance(raw, list):
        if raw and isinstance(raw[0], list):
            return [[int(x) for x in row] for row in raw]
        return [[int(x) for x in raw]]
    text = str(raw).strip()
    if not text:
        return None
    if text.startswith("["):
        parsed = json.loads(text)
        if parsed and isinstance(parsed[0], list):
            return [[int(x) for x in row] for row in parsed]
        return [[int(x) for x in parsed]]
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1 and all(re.match(r"^[\d\s,;]+$", ln) for ln in lines):
        return [_parse_int_line(ln) for ln in lines]
    if re.search(r"[\s,;]", text) and re.match(r"^[\d\s,;]+$", text):
        return [_parse_int_line(text)]
    return None


def _parse_int_line(text: str) -> list[int]:
    text = text.strip()
    if text.startswith("["):
        return [int(x) for x in json.loads(text)]
    parts = re.split(r"[\s,;]+", text)
    return [int(p) for p in parts if p]


def _ic_band(ic: float, *, alphabet_size: int = 26) -> str:
    random_ic = 1.0 / alphabet_size if alphabet_size > 1 else RANDOM_IC_26
    if ic >= ENGLISH_IC - 0.008:
        return "language_like"
    if ic <= random_ic + 0.012:
        return "flat_polyalphabetic"
    return "intermediate"


def _add(hypotheses: list[ClassHypothesis], h: ClassHypothesis) -> None:
    for i, existing in enumerate(hypotheses):
        if existing.family == h.family:
            if h.confidence > existing.confidence:
                hypotheses[i] = h
            return
    hypotheses.append(h)


def classify_ciphertext(
    ciphertext: str | list | list[list[int]] | None = None,
    *,
    ciphertexts: list[list[int]] | None = None,
    deck_size: int | None = None,
) -> dict[str, Any]:
    """
    Rank cipher-family hypotheses and suggest dash routing (propagator / mode).

    Accepts alphabetic text, integer deck JSON, or multi-line integer decks.
    """
    decks = ciphertexts
    if decks is None and ciphertext is not None:
        if isinstance(ciphertext, list) and ciphertext and isinstance(ciphertext[0], list):
            decks = [[int(x) for x in row] for row in ciphertext]
        elif isinstance(ciphertext, list):
            decks = [[int(x) for x in ciphertext]]
        elif isinstance(ciphertext, str):
            decks = _parse_decks(ciphertext)

    hypotheses: list[ClassHypothesis] = []
    profile_summary: dict[str, Any] = {}

    if decks:
        n_msgs = len(decks)
        max_val = max(max(row) for row in decks if row) if decks else 0
        inferred_size = deck_size or max_val + 1
        flat = [v for row in decks for v in row]
        stream = normalize_stream(flat, deck_size=inferred_size)
        fp = fingerprint_metrics(stream.text, symbol_class="integer")
        ic = fp.get("index_of_coincidence", 0.0)

        profile_summary = {
            "symbol_class": "integer",
            "num_messages": n_msgs,
            "deck_size": inferred_size,
            "total_symbols": len(flat),
            "index_of_coincidence": round(ic, 4),
            "shannon_entropy_bits": round(fp.get("shannon_entropy_bits", 0.0), 4),
        }

        conf = 0.75 if n_msgs >= 2 else 0.55
        reasoning = [
            f"{n_msgs} integer message(s), deck size ≈ {inferred_size}",
            f"IC={ic:.4f} on pooled symbols",
        ]
        actions = [
            "Use shared_keystream propagator with crib pins",
            "Exploit pt_difference rows for crib-drag",
        ]
        if inferred_size == 83 and n_msgs >= 2:
            _add(
                hypotheses,
                ClassHypothesis(
                    family="noita_shared_keystream",
                    label="Noita-style shared depth keystream (mod 83)",
                    confidence=min(0.92, conf + 0.15),
                    propagator="shared_keystream",
                    dash_mode="noita" if n_msgs == 9 else "custom",
                    reasoning=reasoning + ["Deck size 83 matches Noita eye corpus"],
                    actions=actions + ["Load Noita eyes preset or paste all nine decks"],
                    deck_size=83,
                    hypothesis={"combiner": "add", "family": "shared_keystream"},
                ),
            )
        else:
            _add(
                hypotheses,
                ClassHypothesis(
                    family="shared_keystream",
                    label=f"Multi-message shared keystream (mod {inferred_size})",
                    confidence=conf,
                    propagator="shared_keystream",
                    dash_mode="custom",
                    dash_propagator="shared_keystream",
                    reasoning=reasoning,
                    actions=actions,
                    deck_size=inferred_size,
                    hypothesis={"combiner": "add"},
                ),
            )

        return _package(hypotheses, profile_summary, decks=decks)

    if not ciphertext or not str(ciphertext).strip():
        return _package([], {"error": "empty input"}, decks=None)

    text = str(ciphertext).strip()
    stream = normalize_stream(text)
    analysis = analyze_ciphertext(text, cipher_family="unknown", status="unsolved")
    fp = analysis["fingerprint"]
    kas = analysis["kasiski"]
    ic = fp.get("index_of_coincidence", 0.0)
    symbol_class = stream.symbol_class

    profile_summary = {
        "symbol_class": symbol_class,
        "analysis_text_length": len(stream.text),
        "index_of_coincidence": round(ic, 4),
        "shannon_entropy_bits": round(fp.get("shannon_entropy_bits", 0.0), 4),
        "kasiski_periods": kas.get("candidate_key_lengths", [])[:5],
        "ic_band": _ic_band(ic) if symbol_class == "alpha" else symbol_class,
    }

    if symbol_class == "hex":
        _add(
            hypotheses,
            ClassHypothesis(
                family="hex",
                label="Hex encoding",
                confidence=0.9,
                propagator="none",
                dash_mode="none",
                reasoning=["Input is predominantly hexadecimal"],
                actions=["Decode hex → ASCII/UTF-8, then re-classify plaintext"],
            ),
        )
        return _package(hypotheses, profile_summary, decks=None)

    if symbol_class == "base64":
        _add(
            hypotheses,
            ClassHypothesis(
                family="base64",
                label="Base64 encoding",
                confidence=0.88,
                propagator="none",
                dash_mode="none",
                reasoning=["Input matches Base64 alphabet and decodes cleanly"],
                actions=["Base64-decode, then re-classify inner payload"],
            ),
        )
        return _package(hypotheses, profile_summary, decks=None)

    if symbol_class != "alpha":
        _add(
            hypotheses,
            ClassHypothesis(
                family="unknown",
                label="Unclassified printable / binary",
                confidence=0.4,
                propagator="none",
                dash_mode="none",
                reasoning=[f"Symbol class: {symbol_class}"],
                actions=["Normalize to alphabetic or integer deck if possible"],
            ),
        )
        return _package(hypotheses, profile_summary, decks=None)

    ic_band = _ic_band(ic)
    periods = kas.get("candidate_key_lengths") or []
    strongest_period = kas.get("strongest_period")
    top_period = strongest_period or (periods[0] if periods else None)

    if ic_band == "language_like":
        _add(
            hypotheses,
            ClassHypothesis(
                family="monoalphabetic",
                label="Monoalphabetic / transposition (language-like IC)",
                confidence=0.72,
                propagator="none",
                dash_mode="fingerprinted",
                dataset_slug="substitution-qwerty",
                reasoning=[
                    f"IC={ic:.4f} ≈ English ({ENGLISH_IC})",
                    "Consistent with substitution or transposition of plaintext",
                ],
                actions=["Try Caesar/Atbash/substitution decoders", "Check transposition (rail/columnar)"],
            ),
        )
        _add(
            hypotheses,
            ClassHypothesis(
                family="caesar",
                label="Caesar / ROT (quick check)",
                confidence=0.45,
                propagator="none",
                dash_mode="fingerprinted",
                dataset_slug="caesar-rot13",
                reasoning=["Language-like IC — low-cost ROT sweep worthwhile"],
                actions=["Brute all 26 shifts and score English"],
            ),
        )

    if ic_band == "flat_polyalphabetic":
        if top_period and kas.get("repeats_found", 0) >= 1:
            _add(
                hypotheses,
                ClassHypothesis(
                    family="vigenere",
                    label=f"Periodic polyalphabetic (Kasiski period ≈ {top_period})",
                    confidence=0.68,
                    propagator="none",
                    dash_mode="fingerprinted",
                    dataset_slug="vigenere-keyword",
                    reasoning=[
                        f"IC={ic:.4f} near random ({RANDOM_IC_26:.3f})",
                        f"Kasiski suggests period {top_period}",
                    ],
                    actions=["MIC / column IC on period", "Crib + periodic key recovery"],
                ),
            )
        _add(
            hypotheses,
            ClassHypothesis(
                family="autokey",
                label="Autokey / non-periodic polyalphabetic",
                confidence=0.62 if not top_period else 0.48,
                propagator="stream_extension",
                dash_mode="custom",
                dash_propagator="stream_extension",
                reasoning=[
                    f"IC={ic:.4f} flat — polyalphabetic or OTP-like",
                    "No strong Kasiski period" if not top_period else "Period weak vs autokey model",
                ],
                actions=[
                    "Set seed length + crib in stream_extension propagator",
                    "Try brute_top_n seed candidates (length ≤ 4)",
                ],
                hypothesis={"family": "autokey", "variant": "standard", "extension": "plaintext", "seed_length": 3},
            ),
        )
        _add(
            hypotheses,
            ClassHypothesis(
                family="gak",
                label="GAK / dynamic permutation (Eyes family)",
                confidence=0.38,
                propagator="dynamic_perm",
                dash_mode="custom",
                dash_propagator="dynamic_perm",
                reasoning=["Flat IC compatible with dynamic alphabet perm + stream"],
                actions=["Provide plaintext trial + seed_candidates", "Mode ctak_right default"],
                hypothesis={"mode": "ctak_right"},
            ),
        )
        _add(
            hypotheses,
            ClassHypothesis(
                family="running_key",
                label="Running-key / book cipher",
                confidence=0.35,
                propagator="none",
                dash_mode="fingerprinted",
                dataset_slug="running-key-book",
                reasoning=["Flat IC with book-length key mimics OTP statistics"],
                actions=["Book/word corpus search", "Crib on priming segment"],
            ),
        )

    if ic_band == "intermediate":
        _add(
            hypotheses,
            ClassHypothesis(
                family="polyalphabetic_mixed",
                label="Polyalphabetic (weak period signal)",
                confidence=0.5,
                propagator="stream_extension",
                dash_mode="custom",
                dash_propagator="stream_extension",
                reasoning=[f"IC={ic:.4f} between random and English — short text or mixed regime"],
                actions=["Try both periodic (Vigenère) and autokey propagator"],
                hypothesis={"family": "autokey", "seed_length": 3},
            ),
        )

    if not hypotheses:
        _add(
            hypotheses,
            ClassHypothesis(
                family="unknown",
                label="Insufficient signal",
                confidence=0.3,
                propagator="none",
                dash_mode="custom",
                reasoning=[f"IC={ic:.4f}, length={len(stream.text)}"],
                actions=["Add more ciphertext or a crib"],
            ),
        )

    hypotheses.sort(key=lambda h: h.confidence, reverse=True)
    return _package(hypotheses, profile_summary, decks=None)


def _package(
    hypotheses: list[ClassHypothesis],
    profile_summary: dict[str, Any],
    *,
    decks: list[list[int]] | None,
) -> dict[str, Any]:
    hypotheses.sort(key=lambda h: h.confidence, reverse=True)
    top = hypotheses[0] if hypotheses else None
    return {
        "profile": profile_summary,
        "hypotheses": [h.to_dict() for h in hypotheses[:6]],
        "top": top.to_dict() if top else None,
        "has_decks": decks is not None,
        "num_messages": len(decks) if decks else 0,
    }


def route_to_dash_payload(
    classification: dict[str, Any],
    hypothesis_index: int = 0,
    *,
    ciphertext: str | None = None,
    pins: list[dict[str, Any]] | None = None,
    max_rounds: int = 10,
) -> dict[str, Any]:
    """Build an analyze payload from a classification hypothesis + source ciphertext."""
    hyps = classification.get("hypotheses") or []
    if not hyps or hypothesis_index >= len(hyps):
        raise ValueError("No hypothesis at index")
    h = hyps[hypothesis_index]
    payload: dict[str, Any] = {"max_rounds": max_rounds}
    if pins:
        payload["pins"] = pins

    mode = h.get("dash_mode", "custom")
    if mode == "noita":
        payload["source"] = "noita"
        return payload
    if mode == "fingerprinted" and h.get("dataset_slug"):
        payload["source"] = "fingerprinted"
        payload["dataset_slug"] = h["dataset_slug"]
        return payload

    payload["source"] = "custom"
    prop = h.get("dash_propagator") or h.get("propagator")
    if prop and prop != "none":
        payload["propagator"] = prop
    if h.get("deck_size"):
        payload["deck_size"] = h["deck_size"]
    if h.get("hypothesis"):
        payload["hypothesis"] = dict(h["hypothesis"])

    ct = (ciphertext or "").strip()
    if ct:
        payload["ciphertext"] = ct
    elif classification.get("has_decks"):
        raise ValueError("Integer deck ciphertext required for this route")

    if prop and prop != "none" and not ct and mode == "custom":
        raise ValueError("Ciphertext required to route this hypothesis")

    return payload

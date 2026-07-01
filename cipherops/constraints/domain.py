"""Alphabet domain, constraint state, and findings map for cryptanalysis propagation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

Confidence = Literal["hard", "propagated", "heuristic"]


class FindingKind(str, Enum):
    ASSIGNMENT = "assignment"
    EQUALITY = "equality"
    STREAM_PIN = "stream_pin"
    KEYSTREAM_PIN = "keystream_pin"
    PT_DIFFERENCE = "pt_difference"
    FORBIDDEN = "forbidden"
    SEED_ELIMINATION = "seed_elimination"
    SEED_CANDIDATE = "seed_candidate"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class Pin:
    """Hard pin at a stream position (0-based unless ``pos_1based=True`` in state meta)."""

    pos: int
    msg: int | str | None = None
    pt: int | str | None = None
    ct: int | str | None = None


@dataclass(frozen=True)
class Pair:
    """Involution pair A ↔ B on key or alphabet (Enigma plugboard style)."""

    a: int | str
    b: int | str


@dataclass
class AlphabetDomain:
    """Symbol carrier for constraint propagation (size + optional labels)."""

    size: int
    labels: list[int | str] | None = None
    name: str = "default"

    def __post_init__(self) -> None:
        if self.size < 1:
            raise ValueError("AlphabetDomain.size must be >= 1")
        if self.labels is not None and len(self.labels) != self.size:
            raise ValueError("labels length must match domain size")


@dataclass
class ConstraintState:
    """
    Input to a propagator: domain, hypothesis, pins, and corpus material.

    ``ciphertexts``: multi-message integer decks (Noita / shared keystream).
    ``ciphertext``: single alphabetic ciphertext string (autokey / GAK mod 26).
    ``plaintext_trial``: optional partial or full plaintext (ints or A–Z string).
    """

    domain: AlphabetDomain
    hypothesis: dict[str, Any] = field(default_factory=dict)
    pins: list[Pin] = field(default_factory=list)
    pairs: list[Pair] = field(default_factory=list)
    ciphertexts: list[list[int]] | None = None
    ciphertext: str | None = None
    message_labels: list[str] | None = None
    plaintext_trial: list[int] | str | None = None
    seed_candidates: list[int] | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    kind: FindingKind | str
    source: str
    confidence: Confidence
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        kind = self.kind.value if isinstance(self.kind, FindingKind) else self.kind
        return {
            "kind": kind,
            "source": self.source,
            "confidence": self.confidence,
            "data": self.data,
        }


@dataclass
class FindingsMap:
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        kind: FindingKind | str,
        source: str,
        confidence: Confidence,
        **data: Any,
    ) -> None:
        self.findings.append(Finding(kind=kind, source=source, confidence=confidence, data=data))

    def extend(self, other: FindingsMap) -> None:
        self.findings.extend(other.findings)
        self.meta.update(other.meta)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FindingsMap:
        findings = [
            Finding(
                kind=f["kind"],
                source=f["source"],
                confidence=f["confidence"],
                data=f.get("data", {}),
            )
            for f in payload.get("findings", [])
        ]
        return cls(findings=findings, meta=payload.get("meta", {}))


def _assignment_key(data: dict[str, Any]) -> tuple[Any, ...]:
    return (
        data.get("msg"),
        data.get("pos"),
        data.get("field", "pt"),
    )


def merge_findings(*maps: FindingsMap) -> FindingsMap:
    """Merge finding lists; emit ``conflict`` on contradictory hard assignments."""
    merged = FindingsMap(meta={})
    hard_values: dict[tuple[Any, ...], Any] = {}

    for fm in maps:
        merged.meta.update(fm.meta)
        for finding in fm.findings:
            if finding.kind in (FindingKind.CONFLICT, "conflict"):
                merged.findings.append(finding)
                continue
            if finding.confidence == "hard" and finding.kind in (
                FindingKind.ASSIGNMENT,
                FindingKind.KEYSTREAM_PIN,
                "assignment",
                "keystream_pin",
            ):
                key = _assignment_key(finding.data)
                val = finding.data.get("value")
                if key in hard_values and hard_values[key] != val:
                    merged.add(
                        FindingKind.CONFLICT,
                        "merge_findings",
                        "hard",
                        key=key,
                        values=[hard_values[key], val],
                    )
                else:
                    hard_values[key] = val
            merged.findings.append(finding)

    merged.meta["finding_count"] = len(merged.findings)
    merged.meta["conflict_count"] = sum(
        1 for f in merged.findings if f.kind in (FindingKind.CONFLICT, "conflict")
    )
    return merged


def coerce_symbol(value: int | str, *, mod: int | None = None) -> int:
    if isinstance(value, int):
        if mod is not None:
            return value % mod
        return value
    if isinstance(value, str) and len(value) == 1 and value.isalpha():
        from cipherops.ciphers.utils import char_index

        return char_index(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise TypeError(f"Cannot coerce symbol: {value!r}")


def plaintext_as_ints(value: list[int] | str | None, *, mod: int | None = None) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [x % mod if mod else x for x in value]
    from cipherops.ciphers.utils import char_index, clean_alpha

    return [char_index(ch) for ch in clean_alpha(value)]

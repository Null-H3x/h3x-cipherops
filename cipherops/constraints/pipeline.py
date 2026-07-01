"""Findings generation, validation, and recursive re-propagation loop."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from cipherops.ciphers.classical import autokey_decrypt, gronsfeld_autokey_decrypt
from cipherops.ciphers.utils import char_index, clean_alpha, index_char
from cipherops.constraints.domain import (
    AlphabetDomain,
    ConstraintState,
    Finding,
    FindingKind,
    FindingsMap,
    Pin,
    merge_findings,
    plaintext_as_ints,
)
from cipherops.constraints.shared_keystream import (
    _combiner_delta,
    _pt_from_keystream,
    load_noita_state,
    propagate_shared_keystream,
)
from cipherops.constraints.stream_extension import propagate_stream_extension
from cipherops.constraints.dynamic_perm import propagate_dynamic_perm, _simulate_encrypt_path
from cipherops.ciphers import gak as gak_cipher

PropagatorName = Literal["shared_keystream", "stream_extension", "dynamic_perm"]

StopStatus = Literal[
    "complete",
    "needs_information",
    "conflict",
    "validation_failed",
    "max_rounds",
]

REQUIRED_FINDING_KEYS = {"kind", "source", "confidence", "data"}


@dataclass
class CorpusConfig:
    slug: str
    propagator: PropagatorName
    state: ConstraintState
    description: str = ""


@dataclass
class ValidatedFinding:
    finding: Finding
    status: Literal["validated", "rejected", "heuristic_ok"]
    reason: str = ""
    fingerprint: str = ""


@dataclass
class RoundReport:
    round: int
    findings_count: int
    validated_count: int
    rejected_count: int
    heuristic_count: int
    conflicts: int
    new_pins: int
    converged: bool
    findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StopSuggestion:
    priority: Literal["high", "medium", "low"]
    category: str
    action: str
    detail: str = ""
    example: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "priority": self.priority,
            "category": self.category,
            "action": self.action,
        }
        if self.detail:
            out["detail"] = self.detail
        if self.example:
            out["example"] = self.example
        return out


@dataclass
class StopReport:
    """Graceful stop: why the loop ended and what would unlock the next step."""

    status: StopStatus
    headline: str
    detail: str
    suggestions: list[StopSuggestion] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headline": self.headline,
            "detail": self.detail,
            "suggestions": [s.to_dict() for s in self.suggestions],
        }


@dataclass
class PipelineResult:
    corpus: str
    propagator: str
    rounds: list[RoundReport]
    grounded_pins: list[dict[str, Any]]
    final_validated: list[dict[str, Any]]
    remaining_conflicts: int
    converged: bool
    stop: StopReport | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "corpus": self.corpus,
            "propagator": self.propagator,
            "rounds": [
                {
                    "round": r.round,
                    "findings_count": r.findings_count,
                    "validated_count": r.validated_count,
                    "rejected_count": r.rejected_count,
                    "heuristic_count": r.heuristic_count,
                    "conflicts": r.conflicts,
                    "new_pins": r.new_pins,
                    "converged": r.converged,
                }
                for r in self.rounds
            ],
            "grounded_pins": self.grounded_pins,
            "final_validated_count": len(self.final_validated),
            "remaining_conflicts": self.remaining_conflicts,
            "converged": self.converged,
        }
        if self.stop is not None:
            out["stop"] = self.stop.to_dict()
        return out


def finding_fingerprint(finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, Finding):
        payload = finding.to_dict()
    else:
        payload = {k: finding[k] for k in ("kind", "source", "confidence", "data") if k in finding}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def run_propagator(state: ConstraintState, propagator: PropagatorName) -> FindingsMap:
    if propagator == "shared_keystream":
        return propagate_shared_keystream(state)
    if propagator == "stream_extension":
        return propagate_stream_extension(state)
    if propagator == "dynamic_perm":
        return propagate_dynamic_perm(state)
    raise ValueError(f"Unknown propagator: {propagator}")


def _pin_key(pin: Pin) -> tuple[Any, ...]:
    return (pin.msg, pin.pos, pin.pt, pin.ct)


def _dedupe_pins(pins: list[Pin]) -> list[Pin]:
    seen: set[tuple[Any, ...]] = set()
    out: list[Pin] = []
    for pin in pins:
        key = _pin_key(pin)
        if key in seen:
            continue
        seen.add(key)
        out.append(pin)
    return out


def _keystream_pins_from_finding(state: ConstraintState, finding: Finding) -> list[Pin]:
    if not state.ciphertexts:
        return []
    pos = int(finding.data["pos"])
    k_val = int(finding.data["value"])
    combiner = state.hypothesis.get("combiner", "add")
    mod = state.domain.size
    pins: list[Pin] = []
    for mi, msg in enumerate(state.ciphertexts):
        if pos >= len(msg):
            continue
        pt_val = _pt_from_keystream(msg[pos], k_val, combiner, mod)
        pins.append(Pin(pos=pos, msg=mi, pt=pt_val))
    return pins


def apply_validated_findings(
    state: ConstraintState,
    validated: list[ValidatedFinding],
) -> tuple[ConstraintState, list[Pin]]:
    """Promote validated hard findings into ``ConstraintState.pins`` / hypothesis."""
    new_pins = list(state.pins)
    hypothesis = dict(state.hypothesis)
    added: list[Pin] = []

    for vf in validated:
        if vf.status != "validated":
            continue
        f = vf.finding
        if f.confidence != "hard":
            continue
        if f.kind in (FindingKind.CONFLICT, "conflict"):
            continue

        if f.kind in (FindingKind.KEYSTREAM_PIN, "keystream_pin"):
            for pin in _keystream_pins_from_finding(state, f):
                new_pins.append(pin)
                added.append(pin)
            continue

        if f.kind in (FindingKind.ASSIGNMENT, "assignment"):
            field_name = f.data.get("field")
            if field_name == "pt":
                msg = f.data.get("msg")
                pos = int(f.data["pos"])
                val = f.data["value"]
                if msg == "all" and state.ciphertexts:
                    for mi in range(len(state.ciphertexts)):
                        pin = Pin(pos=pos, msg=mi, pt=val)
                        new_pins.append(pin)
                        added.append(pin)
                elif isinstance(msg, int):
                    pin = Pin(pos=pos, msg=msg, pt=val)
                    new_pins.append(pin)
                    added.append(pin)
            elif field_name == "seed":
                val = f.data["value"]
                if isinstance(val, int):
                    hypothesis["prng_seed"] = val
                else:
                    hypothesis["seed"] = str(val)

    new_pins = _dedupe_pins(new_pins)
    new_state = ConstraintState(
        domain=state.domain,
        hypothesis=hypothesis,
        pins=new_pins,
        pairs=list(state.pairs),
        ciphertexts=state.ciphertexts,
        ciphertext=state.ciphertext,
        message_labels=state.message_labels,
        plaintext_trial=state.plaintext_trial,
        seed_candidates=state.seed_candidates,
        meta={**state.meta, "grounded_round": state.meta.get("grounded_round", 0) + 1},
    )
    return new_state, added


def validate_finding(finding: Finding, state: ConstraintState, propagator: PropagatorName) -> ValidatedFinding:
    fp = finding_fingerprint(finding)
    if finding.confidence == "heuristic":
        return ValidatedFinding(finding=finding, status="heuristic_ok", reason="heuristic", fingerprint=fp)

    if finding.kind in (FindingKind.CONFLICT, "conflict"):
        return ValidatedFinding(finding=finding, status="validated", reason="conflict_record", fingerprint=fp)

    try:
        if propagator == "shared_keystream":
            ok, reason = _validate_shared_keystream(finding, state)
        elif propagator == "stream_extension":
            ok, reason = _validate_stream_extension(finding, state)
        elif propagator == "dynamic_perm":
            ok, reason = _validate_dynamic_perm(finding, state)
        else:
            ok, reason = False, f"unknown propagator {propagator}"
    except Exception as exc:  # noqa: BLE001 — validation diagnostic
        ok, reason = False, str(exc)

    status: Literal["validated", "rejected", "heuristic_ok"] = "validated" if ok else "rejected"
    return ValidatedFinding(finding=finding, status=status, reason=reason, fingerprint=fp)


def _validate_shared_keystream(finding: Finding, state: ConstraintState) -> tuple[bool, str]:
    if not state.ciphertexts:
        return False, "missing ciphertexts"

    mod = state.domain.size
    combiner = state.hypothesis.get("combiner", "add")
    messages = state.ciphertexts
    data = finding.data
    kind = finding.kind if isinstance(finding.kind, str) else finding.kind.value

    if kind == FindingKind.EQUALITY.value:
        pos = int(data["pos"])
        cols = [(mi, msg[pos]) for mi, msg in enumerate(messages) if pos < len(msg)]
        if len(cols) < 2:
            return True, "single message column"
        ct_vals = [c for _, c in cols]
        if len(set(ct_vals)) == 1:
            return True, "equal ciphertext at depth"
        return False, f"ciphertext differs at pos {pos}: {ct_vals}"

    if kind == FindingKind.KEYSTREAM_PIN.value:
        pos = int(data["pos"])
        k_val = int(data["value"])
        derived = data.get("derived_from") or {}
        if not derived:
            return True, "keystream pin accepted without derived_from"
        mi = int(derived["msg"])
        pt_val = int(derived["pt"])
        ct_val = int(derived["ct"])
        expected = _combiner_delta(pt_val, ct_val, combiner, mod)
        if expected != k_val:
            return False, f"keystream mismatch: expected {expected}, got {k_val}"
        return True, "keystream recomputed from crib"

    if kind == FindingKind.ASSIGNMENT.value:
        pos = int(data["pos"])
        field_name = data.get("field")
        if field_name == "ct" and data.get("msg") == "all":
            expected = int(data["value"])
            if all(pos < len(m) and m[pos] == expected for m in messages):
                return True, "universal ct assignment"
            return False, f"ct mismatch at pos {pos}"
        if field_name == "pt" and "keystream" in data:
            mi = int(data["msg"])
            pt_val = int(data["value"])
            k_val = int(data["keystream"])
            if mi >= len(messages) or pos >= len(messages[mi]):
                return False, "position out of range"
            ct_val = messages[mi][pos]
            expected = _pt_from_keystream(ct_val, k_val, combiner, mod)
            if expected != pt_val:
                return False, f"pt assignment mismatch: {expected} != {pt_val}"
            return True, "pt from keystream verified"

    if kind == FindingKind.PT_DIFFERENCE.value:
        mi_a = int(data["msg_a"])
        mi_b = int(data["msg_b"])
        pos = int(data["pos"])
        ci = int(data["ct_a"])
        cj = int(data["ct_b"])
        delta = (ci - cj) % mod
        expected_delta = int(data.get("pt_delta_mod", delta))
        if combiner == "add" and delta != expected_delta:
            return False, "pt_delta_mod mismatch"
        return True, "ciphertext difference consistent"

    if finding.confidence == "propagated":
        return True, "propagated finding accepted when parent constraints hold"

    return True, "accepted"


def _validate_stream_extension(finding: Finding, state: ConstraintState) -> tuple[bool, str]:
    if not state.ciphertext:
        return False, "missing ciphertext"

    family = state.hypothesis.get("family", "autokey")
    variant = state.hypothesis.get("variant", "standard")
    extension = state.hypothesis.get("extension", "plaintext")
    seed_len = int(state.hypothesis.get("seed_length", 3))
    kind = finding.kind if isinstance(finding.kind, str) else finding.kind.value
    data = finding.data

    if kind == FindingKind.ASSIGNMENT.value and data.get("field") == "seed":
        seed = str(data["value"])
        pt_ints = plaintext_as_ints(state.plaintext_trial)
        if pt_ints is None:
            return False, "no plaintext to verify seed"
        plain_str = "".join(index_char(p) for p in pt_ints)
        if family == "gronsfeld_autokey":
            dec = gronsfeld_autokey_decrypt(state.ciphertext, seed, extension=extension)
        else:
            dec = autokey_decrypt(state.ciphertext, seed, variant=variant, extension=extension)
        if clean_alpha(dec) == plain_str:
            return True, "seed decrypt verified"
        return False, "seed decrypt mismatch"

    if kind == FindingKind.STREAM_PIN.value:
        stream_index = int(data["stream_index"])
        value = int(data["value"])
        pt_ints = plaintext_as_ints(state.plaintext_trial)
        if pt_ints is None:
            return finding.confidence != "hard", "no plaintext for stream pin"
        if data.get("role") == "seed" and stream_index < seed_len:
            if pt_ints[stream_index] == value:
                return True, "seed stream pin matches plaintext"
            return False, "seed stream pin mismatch"
        if data.get("source_pt_pos") is not None:
            src = int(data["source_pt_pos"])
            if pt_ints[src] == value:
                return True, "pt extension stream pin verified"
            return False, "pt extension mismatch"

    if kind == FindingKind.SEED_CANDIDATE.value:
        return True, "heuristic seed candidate"

    if finding.confidence == "propagated":
        return True, "propagated stream finding"

    return True, "accepted"


def _validate_dynamic_perm(finding: Finding, state: ConstraintState) -> tuple[bool, str]:
    mode_name = state.hypothesis.get("mode", "ctak_right")
    mode_code = gak_cipher.MODE_BY_NAME[mode_name]
    n = state.domain.size
    kind = finding.kind if isinstance(finding.kind, str) else finding.kind.value
    data = finding.data
    seed = int(data.get("prng_seed", state.hypothesis.get("prng_seed", -1)))

    if state.ciphertext:
        ct_ints = [char_index(ch) for ch in clean_alpha(state.ciphertext)]
    elif state.ciphertexts:
        ct_ints = list(state.ciphertexts[0])
    else:
        return False, "missing ciphertext"

    pt_ints = plaintext_as_ints(state.plaintext_trial)
    sigma = gak_cipher.generate_sigma_tables(seed, n)

    if kind == FindingKind.SEED_ELIMINATION.value:
        if pt_ints is None:
            return True, "elimination without plaintext trial"
        trial_pt = pt_ints[: len(ct_ints)]
        enc_ct, _ = _simulate_encrypt_path(trial_pt, sigma, n, mode_code)
        if enc_ct != ct_ints[: len(trial_pt)]:
            return True, "seed correctly eliminated"
        return False, "seed should not be eliminated"

    if kind == FindingKind.STREAM_PIN.value and finding.source == "gak_transition":
        if pt_ints is None:
            return finding.confidence != "hard", "no plaintext for transition"
        pos = int(data["pos"])
        trial_pt = pt_ints[: len(ct_ints)]
        enc_ct, steps = _simulate_encrypt_path(trial_pt, sigma, n, mode_code)
        if pos >= len(steps):
            return False, "transition pos out of range"
        step = steps[pos]
        for key in ("p", "c", "k"):
            if int(data[key]) != step[key]:
                return False, f"transition {key} mismatch at {pos}"
        return True, "gak transition verified"

    if kind == FindingKind.ASSIGNMENT.value and data.get("field") == "seed":
        if pt_ints is None:
            return False, "no plaintext for seed assignment"
        trial_pt = pt_ints[: len(ct_ints)]
        enc_ct, _ = _simulate_encrypt_path(trial_pt, sigma, n, mode_code)
        if enc_ct == ct_ints[: len(trial_pt)]:
            return True, "surviving seed verified"
        return False, "seed assignment encrypt mismatch"

    if finding.confidence == "propagated":
        return True, "propagated gak finding"

    return True, "accepted"


def validate_findings_map(
    findings: FindingsMap,
    state: ConstraintState,
    propagator: PropagatorName,
) -> list[ValidatedFinding]:
    return [validate_finding(f, state, propagator) for f in findings.findings]


def _findings_by_kind(validated: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [f for f in validated if f.get("kind") == kind]


def _has_seed_assignment(validated: list[dict[str, Any]]) -> bool:
    return any(
        f.get("kind") == "assignment"
        and f.get("data", {}).get("field") == "seed"
        and f.get("confidence") == "hard"
        for f in validated
    )


def _surviving_gak_seeds(validated: list[dict[str, Any]]) -> list[int]:
    eliminated = {
        int(f["data"]["prng_seed"])
        for f in validated
        if f.get("kind") == "seed_elimination" and "prng_seed" in f.get("data", {})
    }
    assigned = {
        int(f["data"].get("value", f["data"].get("prng_seed")))
        for f in validated
        if f.get("kind") == "assignment"
        and f.get("data", {}).get("field") == "seed"
        and f.get("source") == "encrypt_verify"
    }
    return sorted(assigned - eliminated)


def diagnose_stop(
    config: CorpusConfig,
    state: ConstraintState,
    validated: list[dict[str, Any]],
    *,
    converged: bool,
    remaining_conflicts: int,
    total_rejected: int,
    max_rounds: int,
    rounds_run: int,
    grounded_pins: list[dict[str, Any]],
) -> StopReport:
    """Classify loop exit and emit actionable next-step suggestions."""
    suggestions: list[StopSuggestion] = []
    prop = config.propagator

    if remaining_conflicts > 0:
        suggestions.append(
            StopSuggestion(
                priority="high",
                category="conflict",
                action="Resolve contradictory pins or hypothesis",
                detail="Two hard assignments disagree at the same position or keystream slot.",
                example='[{"pos":1,"msg":0,"pt":5},{"pos":1,"msg":1,"pt":20}] on identical ciphertext',
            )
        )
        return StopReport(
            status="conflict",
            headline="Hit a wall — contradictory constraints",
            detail=f"{remaining_conflicts} conflict finding(s) remain after validation.",
            suggestions=suggestions,
        )

    if total_rejected > 0:
        suggestions.append(
            StopSuggestion(
                priority="high",
                category="validation",
                action="Fix or remove inputs that failed mathematical re-check",
                detail="A stored finding could not be re-derived from the corpus and current hypothesis.",
            )
        )
        return StopReport(
            status="validation_failed",
            headline="Stopped — validation rejected hard findings",
            detail=f"{total_rejected} finding(s) failed live re-validation.",
            suggestions=suggestions,
        )

    if not converged and rounds_run >= max_rounds:
        suggestions.append(
            StopSuggestion(
                priority="medium",
                category="loop",
                action="Increase max rounds or add crib pins to accelerate grounding",
                detail=f"Loop ran {rounds_run} rounds without reaching a fixpoint.",
            )
        )
        return StopReport(
            status="max_rounds",
            headline="Round limit reached — not yet at fixpoint",
            detail="Propagation may still be unfolding; add information or raise max_rounds.",
            suggestions=suggestions,
        )

    # --- Fixpoint reached: complete vs needs more information ---
    keystream_pins = _findings_by_kind(validated, "keystream_pin")
    pt_pin_count = sum(1 for p in grounded_pins if p.get("pt") is not None)

    if prop == "stream_extension":
        has_seed = _has_seed_assignment(validated)
        pt_ints = plaintext_as_ints(state.plaintext_trial)
        pt_known = pt_ints is not None and len(pt_ints) > 0
        pt_full = pt_ints is not None and all(x is not None for x in pt_ints) if pt_ints else False
        seed_candidates = _findings_by_kind(validated, "seed_candidate")
        seed_len = int(state.hypothesis.get("seed_length", 3))

        if has_seed:
            return StopReport(
                status="complete",
                headline="Grounded — seed verified",
                detail="Hard seed assignment survived decrypt verification.",
                suggestions=[],
            )

        if not pt_known:
            suggestions.extend(
                [
                    StopSuggestion(
                        priority="high",
                        category="crib",
                        action="Add a plaintext crib (prefix or full trial)",
                        detail="Stream extension needs known plaintext symbols to pin the autokey seed or extend the stream.",
                        example='plaintext: "ATTACK" or crib pin {"pos":0,"pt":"A"}',
                    ),
                    StopSuggestion(
                        priority="medium",
                        category="hypothesis",
                        action="Set seed / key and seed_length in hypothesis",
                        detail="If you know the key, declare it so full-decrypt can verify.",
                        example='hypothesis.seed="KEY", seed_length=3',
                    ),
                ]
            )
            if seed_len <= 4:
                suggestions.append(
                    StopSuggestion(
                        priority="low",
                        category="brute",
                        action="Enable seed brute hints",
                        detail="Set hypothesis.brute_top_n to emit ranked seed_candidate findings.",
                        example="brute_top_n: 5",
                    )
                )
        elif not pt_full:
            suggestions.append(
                StopSuggestion(
                    priority="high",
                    category="crib",
                    action="Extend known plaintext toward full message length",
                    detail="Partial plaintext pins seed symbols but cannot verify full decrypt yet.",
                )
            )
        else:
            suggestions.append(
                StopSuggestion(
                    priority="high",
                    category="hypothesis",
                    action="Check seed, variant, and extension match the cipher",
                    detail="Full plaintext present but seed assignment failed — wrong key or autokey mode.",
                    example='variant: standard|beaufort, extension: plaintext|ciphertext',
                )
            )

        if seed_candidates and not has_seed:
            suggestions.append(
                StopSuggestion(
                    priority="medium",
                    category="brute",
                    action="Use top seed_candidate hits as declared seed and re-run",
                    detail=f"{len(seed_candidates)} heuristic candidate(s) available — promote the best to hypothesis.seed.",
                )
            )

        return StopReport(
            status="needs_information",
            headline="Hit a wall — needs more plaintext or key information",
            detail="Fixpoint reached without a verified seed assignment.",
            suggestions=suggestions,
        )

    if prop == "dynamic_perm":
        survivors = _surviving_gak_seeds(validated)
        eliminations = _findings_by_kind(validated, "seed_elimination")
        pt_ints = plaintext_as_ints(state.plaintext_trial)

        if len(survivors) == 1:
            return StopReport(
                status="complete",
                headline="Grounded — single PRNG seed survives",
                detail=f"Seed {survivors[0]} verified against plaintext/ciphertext stream.",
                suggestions=[],
            )

        if len(survivors) > 1:
            suggestions.extend(
                [
                    StopSuggestion(
                        priority="high",
                        category="plaintext",
                        action="Lengthen plaintext trial to eliminate extra seeds",
                        detail=f"{len(survivors)} seeds still satisfy the visible prefix: {survivors[:5]}{'…' if len(survivors) > 5 else ''}.",
                    ),
                    StopSuggestion(
                        priority="medium",
                        category="pins",
                        action="Add pt pins at mismatch positions",
                        detail="Pin additional plaintext letters to kill false seed candidates faster.",
                    ),
                ]
            )
        elif eliminations and not survivors:
            suggestions.extend(
                [
                    StopSuggestion(
                        priority="high",
                        category="seeds",
                        action="Widen seed_candidates or fix GAK mode",
                        detail="Every tested PRNG seed was eliminated by encrypt verification.",
                    ),
                    StopSuggestion(
                        priority="medium",
                        category="hypothesis",
                        action="Confirm mode matches encryption",
                        detail=f"Current mode: {state.hypothesis.get('mode', 'ctak_right')}.",
                        example="ctak_right, ctak_left, ptak_right, xgak_sum_right, …",
                    ),
                ]
            )
        else:
            suggestions.append(
                StopSuggestion(
                    priority="high",
                    category="plaintext",
                    action="Provide plaintext_trial for encrypt-verify filtering",
                    detail="Without plaintext, only roundtrip checks run — seed may stay ambiguous.",
                )
            )

        if not pt_ints:
            suggestions.append(
                StopSuggestion(
                    priority="high",
                    category="plaintext",
                    action="Paste partial or full plaintext",
                    detail="GAK seed elimination requires comparing simulated encryption to observed ciphertext.",
                )
            )

        return StopReport(
            status="needs_information",
            headline="Hit a wall — seed or plaintext still ambiguous",
            detail="Fixpoint reached without a unique surviving PRNG seed.",
            suggestions=suggestions,
        )

    # shared_keystream
    if keystream_pins:
        positions = sorted({int(f["data"]["pos"]) for f in keystream_pins if "pos" in f.get("data", {})})
        if pt_pin_count > 0 and converged:
            return StopReport(
                status="complete",
                headline="Grounded — shared keystream pinned from cribs",
                detail=f"Keystream fixed at {len(positions)} position(s); pt assignments propagated across messages.",
                suggestions=[],
            )

    equality_count = len(_findings_by_kind(validated, "equality"))
    diff_count = len(_findings_by_kind(validated, "pt_difference"))

    if pt_pin_count == 0:
        suggestions.extend(
            [
                StopSuggestion(
                    priority="high",
                    category="crib",
                    action="Pin plaintext at a known position on one message",
                    detail="A single pt crib fixes shared K[t] and propagates to all messages at that depth.",
                    example='[{"pos":1,"msg":0,"pt":10}]',
                ),
                StopSuggestion(
                    priority="medium",
                    category="structure",
                    action="Use pt_difference rows to plan crib drag across messages",
                    detail=f"{diff_count} pairwise difference(s) at differing ciphertext columns — drag candidate plaintext offsets.",
                ),
            ]
        )
    else:
        suggestions.append(
            StopSuggestion(
                priority="medium",
                category="crib",
                action="Add cribs at uncovered keystream positions",
                detail=f"{pt_pin_count} pt pin(s) grounded; extend to positions without keystream_pin yet.",
            )
        )

    if equality_count:
        suggestions.append(
            StopSuggestion(
                priority="low",
                category="structure",
                action="Exploit depth equalities where all messages share ciphertext",
                detail=f"{equality_count} positions force identical plaintext under shared K[t].",
            )
        )

    return StopReport(
        status="needs_information",
        headline="Hit a wall — structural depth only, no keystream cribs yet",
        detail="Identical/differing ciphertext columns mapped; shared K[t] not fixed without plaintext pins.",
        suggestions=suggestions,
    )


def run_findings_loop(
    config: CorpusConfig,
    *,
    max_rounds: int = 10,
) -> PipelineResult:
    """Generate findings, validate, promote grounded truth, re-propagate until fixpoint."""
    state = config.state
    rounds: list[RoundReport] = []
    validated_by_fp: dict[str, ValidatedFinding] = {}
    seen_fingerprints: set[str] = set()
    converged = False
    total_rejected = 0

    for round_idx in range(max_rounds):
        findings = run_propagator(state, config.propagator)
        validated = validate_findings_map(findings, state, config.propagator)

        new_fps = {vf.fingerprint for vf in validated if vf.status == "validated"}
        round_converged = round_idx > 0 and new_fps.issubset(seen_fingerprints)

        conflicts = sum(
            1
            for vf in validated
            if vf.finding.kind in (FindingKind.CONFLICT, "conflict") and vf.status == "validated"
        )
        rejected = sum(1 for vf in validated if vf.status == "rejected")
        total_rejected += rejected
        heuristic = sum(1 for vf in validated if vf.status == "heuristic_ok")
        validated_hard = [vf for vf in validated if vf.status == "validated"]

        state, added_pins = apply_validated_findings(state, validated_hard)
        seen_fingerprints.update(new_fps)
        for vf in validated_hard:
            validated_by_fp.setdefault(vf.fingerprint, vf)

        rounds.append(
            RoundReport(
                round=round_idx,
                findings_count=len(findings.findings),
                validated_count=len(validated_hard),
                rejected_count=rejected,
                heuristic_count=heuristic,
                conflicts=conflicts,
                new_pins=len(added_pins),
                converged=round_converged,
                findings=[f.to_dict() for f in findings.findings],
            )
        )

        if round_converged or rejected > 0:
            converged = round_converged and rejected == 0
            break
        # max rounds without fixpoint: converged stays False

    all_validated = list(validated_by_fp.values())
    final_validated = [vf.finding.to_dict() for vf in all_validated if vf.status == "validated"]
    grounded_pins = [
        {"msg": p.msg, "pos": p.pos, "pt": p.pt, "ct": p.ct}
        for p in state.pins
    ]
    remaining_conflicts = sum(
        1
        for vf in all_validated
        if vf.finding.kind in (FindingKind.CONFLICT, "conflict")
    )

    stop = diagnose_stop(
        config,
        state,
        final_validated,
        converged=converged,
        remaining_conflicts=remaining_conflicts,
        total_rejected=total_rejected,
        max_rounds=max_rounds,
        rounds_run=len(rounds),
        grounded_pins=grounded_pins,
    )

    return PipelineResult(
        corpus=config.slug,
        propagator=config.propagator,
        rounds=rounds,
        grounded_pins=grounded_pins,
        final_validated=final_validated,
        remaining_conflicts=remaining_conflicts,
        converged=converged,
        stop=stop,
    )


def _load_jsonl(path) -> list[dict]:
    import json
    from pathlib import Path

    p = Path(path)
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_corpus_configs(root) -> list[CorpusConfig]:
    """Default corpora: Noita shared keystream, autokey demo, GAK demo."""
    from pathlib import Path

    root = Path(root)
    configs: list[CorpusConfig] = []

    configs.append(
        CorpusConfig(
            slug="noita-eye-messages",
            propagator="shared_keystream",
            state=load_noita_state(str(root / "datasets/unsolved/noita-eye-messages/corpus.json")),
            description="Nine-message shared keystream depth model",
        )
    )

    configs.append(
        CorpusConfig(
            slug="noita-eye-crib-demo",
            propagator="shared_keystream",
            state=load_noita_state(
                str(root / "datasets/unsolved/noita-eye-messages/corpus.json"),
                pins=[Pin(pos=1, msg=0, pt=10)],
            ),
            description="Noita with crib pt=10 at msg0 pos1 → keystream propagation",
        )
    )

    autokey_path = root / "datasets/fingerprinted/autokey-standard/data.jsonl"
    autokey_rows = _load_jsonl(autokey_path)
    if autokey_rows:
        row = autokey_rows[0]
        params = row.get("params", {})
        seed = str(params.get("key", "KEY"))
        configs.append(
            CorpusConfig(
                slug="autokey-demo",
                propagator="stream_extension",
                state=ConstraintState(
                    domain=AlphabetDomain(size=26, name="latin"),
                    hypothesis={
                        "family": "autokey",
                        "variant": params.get("variant", "standard"),
                        "extension": params.get("extension", "plaintext"),
                        "seed_length": len(clean_alpha(seed)),
                        "seed": seed,
                    },
                    ciphertext=row["ciphertext"],
                    plaintext_trial=row["plaintext"],
                ),
                description=f"Autokey roundtrip validation ({row['id']})",
            )
        )

    gak_path = root / "datasets/fingerprinted/gak-ctak-right-s42/data.jsonl"
    gak_rows = _load_jsonl(gak_path)
    if gak_rows:
        row = gak_rows[0]
        params = row.get("params", {})
        prng_seed = int(params.get("prng_seed", 42))
        wrong = [prng_seed - 1, prng_seed + 1]
        configs.append(
            CorpusConfig(
                slug="gak-ctak-right-demo",
                propagator="dynamic_perm",
                state=ConstraintState(
                    domain=AlphabetDomain(size=26, name="gak"),
                    hypothesis={"mode": params.get("mode", "ctak_right")},
                    ciphertext=row["ciphertext"],
                    plaintext_trial=row["plaintext"],
                    seed_candidates=[prng_seed] + wrong,
                ),
                description=f"GAK ctak_right seed filter ({row['id']})",
            )
        )

    return configs


def serialize_pipeline_outputs(result: PipelineResult) -> tuple[list[str], dict[str, Any]]:
    """JSONL lines for findings + history dict."""
    lines: list[str] = []
    for round_report in result.rounds:
        for finding in round_report.findings:
            fp = finding_fingerprint(finding)
            record = {
                **finding,
                "corpus": result.corpus,
                "round": round_report.round,
                "fingerprint": fp,
            }
            lines.append(json.dumps(record, ensure_ascii=False))

    history = result.to_dict()
    return lines, history

"""Build constraint propagation state from ad-hoc / pasted / selected cipher input."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cipherops.ciphers.utils import clean_alpha
from cipherops.constraints.domain import AlphabetDomain, ConstraintState, Pin
from cipherops.constraints.pipeline import CorpusConfig, PropagatorName, build_corpus_configs
from cipherops.constraints.shared_keystream import load_noita_state

STREAM_SLUG_PREFIXES = (
    "autokey-",
    "gronsfeld-autokey-",
    "porta-autokey-",
    "nihilist-autokey-",
    "xautokey-",
)
GAK_SLUG_PREFIXES = ("gak-", "xgak-")


def propagator_for_slug(slug: str) -> PropagatorName | None:
    if slug in {"noita-eye-messages", "noita-eye-crib-demo"} or slug.startswith("noita-"):
        return "shared_keystream"
    if any(slug.startswith(p) for p in STREAM_SLUG_PREFIXES):
        return "stream_extension"
    if any(slug.startswith(p) for p in GAK_SLUG_PREFIXES):
        return "dynamic_perm"
    return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_pins(raw: list[dict[str, Any]] | None) -> list[Pin]:
    pins: list[Pin] = []
    if not raw:
        return pins
    for item in raw:
        pins.append(
            Pin(
                pos=int(item["pos"]),
                msg=item.get("msg"),
                pt=item.get("pt"),
                ct=item.get("ct"),
            )
        )
    return pins


def _parse_int_list(text: str) -> list[int]:
    text = text.strip()
    if text.startswith("["):
        values = json.loads(text)
        return [int(x) for x in values]
    parts = re.split(r"[\s,;]+", text)
    return [int(p) for p in parts if p]


def _parse_ciphertexts(raw: str | list | None) -> list[list[int]] | None:
    if raw is None:
        return None
    if isinstance(raw, list):
        return [[int(x) for x in row] for row in raw]
    text = raw.strip()
    if not text:
        return None
    if text.startswith("["):
        parsed = json.loads(text)
        if parsed and isinstance(parsed[0], list):
            return [[int(x) for x in row] for row in parsed]
        return [parsed]
    if re.search(r"[\s,;]", text):
        return [_parse_int_list(text)]
    return None


def _stream_hypothesis_from_params(params: dict[str, Any]) -> dict[str, Any]:
    key = str(params.get("key", params.get("numeric_key", params.get("seed", "KEY"))))
    family = params.get("family", "autokey")
    return {
        "family": family,
        "variant": params.get("variant", "standard"),
        "extension": params.get("extension", "plaintext"),
        "seed_length": len(clean_alpha(key)),
        "seed": key,
    }


def build_from_preset(root: Path, slug: str) -> CorpusConfig:
    configs = {c.slug: c for c in build_corpus_configs(root)}
    if slug not in configs:
        raise ValueError(f"Unknown preset corpus: {slug}")
    return configs[slug]


def build_from_fingerprinted(
    root: Path,
    slug: str,
    *,
    record_id: str | None = None,
    pins: list[Pin] | None = None,
) -> CorpusConfig:
    propagator = propagator_for_slug(slug)
    if propagator is None:
        raise ValueError(f"Slug {slug!r} is not supported by constraint propagators")

    path = root / "datasets" / "fingerprinted" / slug / "data.jsonl"
    rows = _load_jsonl(path)
    if not rows:
        raise ValueError(f"No fingerprinted records for {slug}")

    row = rows[0]
    if record_id:
        matches = [r for r in rows if r.get("id") == record_id]
        if not matches:
            raise ValueError(f"Record {record_id!r} not found in {slug}")
        row = matches[0]

    if propagator == "stream_extension":
        params = row.get("params", {})
        family_raw = row.get("cipher_family", "autokey")
        if "gronsfeld" in family_raw or "gronsfeld" in slug:
            family = "gronsfeld_autokey"
        else:
            family = family_raw.replace("-", "_")
        hypothesis = _stream_hypothesis_from_params({**params, "family": family})
        return CorpusConfig(
            slug=f"fingerprinted/{slug}/{row['id']}",
            propagator=propagator,
            state=ConstraintState(
                domain=AlphabetDomain(size=26, name="latin"),
                hypothesis=hypothesis,
                ciphertext=row["ciphertext"],
                plaintext_trial=row.get("plaintext"),
                pins=pins or [],
            ),
            description=f"Fingerprinted {row['id']}",
        )

    params = row.get("params", {})
    prng_seed = int(params.get("prng_seed", 42))
    return CorpusConfig(
        slug=f"fingerprinted/{slug}/{row['id']}",
        propagator=propagator,
        state=ConstraintState(
            domain=AlphabetDomain(size=26, name="gak"),
            hypothesis={"mode": params.get("mode", "ctak_right")},
            ciphertext=row["ciphertext"],
            plaintext_trial=row.get("plaintext"),
            seed_candidates=[prng_seed - 1, prng_seed, prng_seed + 1],
            pins=pins or [],
        ),
        description=f"Fingerprinted {row['id']}",
    )


def build_from_noita(
    root: Path,
    *,
    pins: list[Pin] | None = None,
) -> CorpusConfig:
    return CorpusConfig(
        slug="noita-eye-messages/custom",
        propagator="shared_keystream",
        state=load_noita_state(
            str(root / "datasets/unsolved/noita-eye-messages/corpus.json"),
            pins=pins or [],
        ),
        description="Noita eye messages (unsolved corpus)",
    )


def build_custom_config(payload: dict[str, Any], root: Path | None = None) -> CorpusConfig:
    """Build a corpus config from dashboard/API payload."""
    root = root or Path(__file__).resolve().parents[2]
    source = payload.get("source", "custom")

    pins = _parse_pins(payload.get("pins"))

    if source == "preset":
        slug = payload.get("preset_slug") or payload.get("slug")
        if not slug:
            raise ValueError("preset_slug required for preset source")
        return build_from_preset(root, slug)

    if source == "fingerprinted":
        slug = payload.get("dataset_slug") or payload.get("slug")
        if not slug:
            raise ValueError("dataset_slug required for fingerprinted source")
        return build_from_fingerprinted(
            root,
            slug,
            record_id=payload.get("record_id"),
            pins=pins,
        )

    if source == "noita":
        return build_from_noita(root, pins=pins)

    propagator: PropagatorName = payload.get("propagator", "stream_extension")
    hypothesis = dict(payload.get("hypothesis") or {})

    if propagator == "shared_keystream":
        ciphertexts = _parse_ciphertexts(payload.get("ciphertexts"))
        if ciphertexts is None and payload.get("ciphertext"):
            ciphertexts = _parse_ciphertexts(payload["ciphertext"])
        if not ciphertexts:
            return build_from_noita(root, pins=pins)
        deck_size = int(payload.get("deck_size") or hypothesis.get("deck_size") or max(max(r) for r in ciphertexts) + 1)
        return CorpusConfig(
            slug=payload.get("slug", "custom/shared-keystream"),
            propagator=propagator,
            state=ConstraintState(
                domain=AlphabetDomain(size=deck_size, name="custom"),
                hypothesis={"combiner": hypothesis.get("combiner", "add"), **hypothesis},
                ciphertexts=ciphertexts,
                message_labels=payload.get("message_labels"),
                pins=pins,
            ),
            description=payload.get("description", "Custom shared keystream"),
        )

    if propagator == "stream_extension":
        ciphertext = payload.get("ciphertext")
        if not ciphertext:
            raise ValueError("ciphertext required for stream_extension")
        seed = hypothesis.get("seed")
        if seed and "seed_length" not in hypothesis:
            hypothesis["seed_length"] = len(clean_alpha(str(seed)))
        return CorpusConfig(
            slug=payload.get("slug", "custom/stream-extension"),
            propagator=propagator,
            state=ConstraintState(
                domain=AlphabetDomain(size=26, name="latin"),
                hypothesis={"family": "autokey", "variant": "standard", "extension": "plaintext", **hypothesis},
                ciphertext=str(ciphertext),
                plaintext_trial=payload.get("plaintext") or payload.get("plaintext_trial"),
                pins=pins,
            ),
            description=payload.get("description", "Custom autokey stream"),
        )

    if propagator == "dynamic_perm":
        ciphertext = payload.get("ciphertext")
        if not ciphertext:
            raise ValueError("ciphertext required for dynamic_perm")
        seeds = payload.get("seed_candidates")
        if seeds is None:
            center = int(hypothesis.get("prng_seed", 42))
            seeds = [center - 1, center, center + 1]
        return CorpusConfig(
            slug=payload.get("slug", "custom/dynamic-perm"),
            propagator=propagator,
            state=ConstraintState(
                domain=AlphabetDomain(size=int(hypothesis.get("alphabet_size", 26)), name="gak"),
                hypothesis={"mode": hypothesis.get("mode", "ctak_right"), **hypothesis},
                ciphertext=str(ciphertext),
                plaintext_trial=payload.get("plaintext") or payload.get("plaintext_trial"),
                seed_candidates=[int(s) for s in seeds],
                pins=pins,
            ),
            description=payload.get("description", "Custom GAK dynamic perm"),
        )

    raise ValueError(f"Unsupported propagator: {propagator}")


def list_dashboard_sources(root: Path | None = None) -> dict[str, Any]:
    """Metadata for dashboard corpus / cipher pickers."""
    root = root or Path(__file__).resolve().parents[2]

    presets: list[dict[str, Any]] = []
    manifest_path = root / "datasets" / "constraint-findings" / "manifest.json"
    if manifest_path.is_file():
        presets = json.loads(manifest_path.read_text(encoding="utf-8"))

    fingerprinted: list[dict[str, Any]] = []
    fp_manifest = root / "datasets" / "fingerprinted" / "manifest.json"
    if fp_manifest.is_file():
        for entry in json.loads(fp_manifest.read_text(encoding="utf-8")):
            slug = entry["slug"]
            propagator = propagator_for_slug(slug)
            if propagator is None:
                continue
            path = root / "datasets" / "fingerprinted" / slug / "data.jsonl"
            rows = _load_jsonl(path)
            fingerprinted.append(
                {
                    "slug": slug,
                    "propagator": propagator,
                    "count": len(rows),
                    "sample_id": rows[0]["id"] if rows else None,
                    "cipher_family": rows[0].get("cipher_family") if rows else None,
                }
            )

    return {
        "presets": presets,
        "fingerprinted": sorted(fingerprinted, key=lambda x: x["slug"]),
        "propagators": [
            {
                "id": "shared_keystream",
                "label": "Shared Keystream",
                "hint": "Multi-message integer decks (Noita depth model)",
            },
            {
                "id": "stream_extension",
                "label": "Stream Extension",
                "hint": "Autokey / Gronsfeld autokey with crib + seed",
            },
            {
                "id": "dynamic_perm",
                "label": "Dynamic Permutation",
                "hint": "GAK / XGAK seed filter + transition pins",
            },
        ],
    }

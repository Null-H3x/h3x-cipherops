"""Full ciphertext property profiling."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cipherops.analysis.attacks import ATTACK_VECTORS, attack_surface
from cipherops.analysis.fingerprint import fingerprint_metrics
from cipherops.analysis.frequency import frequency_profile
from cipherops.analysis.kasiski import kasiski_examination
from cipherops.analysis.ngrams import ngram_profile
from cipherops.analysis.patterns import word_pattern_profile
from cipherops.analysis.stream import normalize_stream

ANALYZER_VERSION = "1.0.0"


def analyze_ciphertext(
    ciphertext: str | list[int],
    *,
    cipher_family: str = "unknown",
    era: str = "classical",
    status: str = "solved",
    params: dict | None = None,
    deck_size: int | None = None,
) -> dict[str, Any]:
    stream = normalize_stream(ciphertext, deck_size=deck_size)
    fingerprint = fingerprint_metrics(stream.text, symbol_class=stream.symbol_class)
    fingerprint["symbol_class"] = stream.symbol_class

    kasiski = kasiski_examination(stream.text)
    patterns = word_pattern_profile(stream.raw, stream.text, symbol_class=stream.symbol_class)
    attacks = attack_surface(
        cipher_family=cipher_family,
        era=era,
        status=status,
        fingerprint=fingerprint,
        kasiski=kasiski,
        patterns=patterns,
        params=params,
    )

    return {
        "stream": {
            "raw_length": len(stream.raw),
            "analysis_text_length": len(stream.text),
            "symbol_class": stream.symbol_class,
            "alphabet_size": stream.alphabet_size,
        },
        "fingerprint": fingerprint,
        "frequency": frequency_profile(stream.text),
        "kasiski": kasiski,
        "ngrams": ngram_profile(stream.text),
        "patterns": patterns,
        "attacks": {name: attacks[name] for name in ATTACK_VECTORS},
    }


def _properties_digest(properties: dict) -> str:
    payload = json.dumps(properties, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def profile_record(
    *,
    record_id: str,
    ciphertext: str | list[int],
    cipher_family: str,
    variant_slug: str,
    era: str = "classical",
    status: str = "solved",
    params: dict | None = None,
    source_path: str,
    ciphertext_sha256: str | None = None,
    deck_size: int | None = None,
) -> dict[str, Any]:
    properties = analyze_ciphertext(
        ciphertext,
        cipher_family=cipher_family,
        era=era,
        status=status,
        params=params,
        deck_size=deck_size,
    )
    return {
        "id": record_id,
        "source": {
            "fingerprinted_path": source_path,
            "cipher_family": cipher_family,
            "variant_slug": variant_slug,
            "ciphertext_sha256": ciphertext_sha256,
            "status": status,
        },
        **properties,
        "validation": {
            "properties_sha256": _properties_digest(properties),
            "analyzer_version": ANALYZER_VERSION,
        },
    }

"""Kasiski examination and periodicity hints."""

from __future__ import annotations

import math
from collections import Counter, defaultdict


def _gcd_list(values: list[int]) -> int:
    result = values[0]
    for value in values[1:]:
        result = math.gcd(result, value)
    return result


def kasiski_examination(text: str, *, min_len: int = 3, max_len: int = 5, max_period: int = 30) -> dict:
    if len(text) < min_len * 2:
        return {
            "repeats_found": 0,
            "repeat_spacings": [],
            "spacing_gcd": None,
            "candidate_key_lengths": [],
            "strongest_period": None,
        }

    spacing_counter: Counter[int] = Counter()
    repeats_found = 0

    for n in range(min_len, max_len + 1):
        positions: dict[str, list[int]] = defaultdict(list)
        for i in range(len(text) - n + 1):
            gram = text[i : i + n]
            positions[gram].append(i)

        for positions_list in positions.values():
            if len(positions_list) < 2:
                continue
            repeats_found += len(positions_list) - 1
            for i in range(len(positions_list) - 1):
                spacing = positions_list[i + 1] - positions_list[i]
                if 1 < spacing <= max_period * 3:
                    spacing_counter[spacing] += 1

    candidate_lengths: Counter[int] = Counter()
    for spacing, count in spacing_counter.items():
        for divisor in range(2, min(max_period, spacing) + 1):
            if spacing % divisor == 0:
                candidate_lengths[divisor] += count

    spacing_gcd = _gcd_list(list(spacing_counter)) if spacing_counter else None
    candidates = [length for length, _ in candidate_lengths.most_common(8)]
    strongest = candidate_lengths.most_common(1)[0][0] if candidate_lengths else None

    return {
        "repeats_found": repeats_found,
        "repeat_spacings": [spacing for spacing, _ in spacing_counter.most_common(12)],
        "spacing_gcd": spacing_gcd,
        "candidate_key_lengths": candidates,
        "strongest_period": strongest,
    }

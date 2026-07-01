"""Coset (column-wise) index of coincidence for period confirmation."""

from __future__ import annotations

from cipherops.analysis.fingerprint import ENGLISH_IC, index_of_coincidence


def coset_ic_profile(text: str, *, max_period: int = 20) -> dict:
    """Compute mean IC for each coset at periods 2..max_period."""
    alpha = "".join(ch.upper() for ch in text if ch.isalpha())
    n = len(alpha)
    if n < 20:
        return {
            "periods_tested": 0,
            "best_period": None,
            "best_mean_ic": None,
            "english_ic_reference": ENGLISH_IC,
            "by_period": {},
        }

    by_period: dict[int, float] = {}
    for period in range(2, min(max_period, n // 2) + 1):
        coset_ics: list[float] = []
        for offset in range(period):
            coset = alpha[offset::period]
            if len(coset) >= 2:
                coset_ics.append(index_of_coincidence(coset))
        if coset_ics:
            by_period[period] = round(sum(coset_ics) / len(coset_ics), 6)

    best_period = max(by_period, key=by_period.get) if by_period else None
    best_ic = by_period.get(best_period) if best_period else None

    return {
        "periods_tested": len(by_period),
        "best_period": best_period,
        "best_mean_ic": best_ic,
        "english_ic_reference": ENGLISH_IC,
        "by_period": {str(k): v for k, v in sorted(by_period.items())},
    }

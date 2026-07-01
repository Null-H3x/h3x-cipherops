"""
fingerprint.py — Entropy, Index of Coincidence, Kasiski examination.

Backward-compatible re-exports. Prefer cipherops.analysis for full profiling.
"""

from cipherops.analysis.fingerprint import (
    ENGLISH_FREQ,
    ENGLISH_IC,
    chi_squared_english,
    fingerprint_metrics,
    friedman_key_length_estimate,
    index_of_coincidence,
    normalized_ic_ratio,
    shannon_entropy,
)
from cipherops.analysis.kasiski import kasiski_examination

__all__ = [
    "ENGLISH_FREQ",
    "ENGLISH_IC",
    "chi_squared_english",
    "fingerprint_metrics",
    "friedman_key_length_estimate",
    "index_of_coincidence",
    "kasiski_examination",
    "normalized_ic_ratio",
    "shannon_entropy",
]

"""
cipherops — Validated cipher engine for H3X CipherOps.

Features:
- Fingerprinting: entropy, IC, Kasiski exam
- Classification: heuristic cipher detection
- Decoding: ROT, Base*, XOR decoders
- Conversion: hex ↔ base64 ↔ bin ↔ ASCII
- Brute-force: parallel key search with hints from fine-tuned LLMs
"""

__version__ = "0.1.0"
__author__ = "Null-H3x"

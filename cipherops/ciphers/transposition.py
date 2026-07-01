"""Transposition cipher implementations."""

from __future__ import annotations

from cipherops.ciphers.utils import clean_alpha, columnar_read, columnar_write


def rail_fence(text: str, rails: int) -> str:
    """Write text in a zigzag across `rails` rows, read row by row."""
    if rails < 2:
        raise ValueError("Rail count must be >= 2")
    if rails == 1:
        return text

    fence: list[list[str]] = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    return "".join("".join(row) for row in fence)


def rail_fence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text

    n = len(text)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    counts = [0] * rails
    for i in range(n):
        counts[pattern[i % len(pattern)]] += 1

    rows: list[list[str]] = []
    idx = 0
    for count in counts:
        rows.append(list(text[idx : idx + count]))
        idx += count

    result = []
    row_idx = [0] * rails
    for i in range(n):
        r = pattern[i % len(pattern)]
        result.append(rows[r][row_idx[r]])
        row_idx[r] += 1
    return "".join(result)


def columnar_transposition(text: str, key: str) -> str:
    """Columnar transposition: write rows, read columns sorted by key."""
    return columnar_read(text, key)


def columnar_transposition_decrypt(text: str, key: str) -> str:
    return columnar_write(text, key)


def scytale(text: str, diameter: int) -> str:
    """
    Scytale (skytale) cylinder transposition.

    Write plaintext in rows of width `diameter`, read down columns (around the staff).
    """
    if diameter < 2:
        raise ValueError("Scytale diameter must be >= 2")
    alpha = clean_alpha(text)
    if not alpha:
        return ""
    cols = (len(alpha) + diameter - 1) // diameter
    padded = alpha + "X" * (cols * diameter - len(alpha))
    matrix = [padded[r * cols : (r + 1) * cols] for r in range(diameter)]
    return "".join(matrix[r][c] for c in range(cols) for r in range(diameter))


def scytale_decrypt(text: str, diameter: int) -> str:
    """Reverse scytale: write column-wise, read row-wise."""
    if diameter < 2:
        return text
    alpha = clean_alpha(text)
    if not alpha:
        return ""
    cols = len(alpha) // diameter
    if cols * diameter != len(alpha):
        raise ValueError("Ciphertext length must be divisible by diameter")
    matrix = [[""] * cols for _ in range(diameter)]
    idx = 0
    for c in range(cols):
        for r in range(diameter):
            matrix[r][c] = alpha[idx]
            idx += 1
    rows = "".join("".join(row) for row in matrix)
    return rows.rstrip("X")

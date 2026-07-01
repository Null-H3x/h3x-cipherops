#!/usr/bin/env python3
"""CLI entrypoint for cipherops toolkit."""

import json

import click

from cipherops import fingerprint
from cipherops.analysis.profile import analyze_ciphertext


@click.group()
def cli():
    """CipherOps: Crypto analysis toolkit for LLM Cryptography."""
    pass


@cli.command(name="fingerprint")
@click.argument("text", type=click.STRING)
@click.option("--method", "-m", default="all", help="Entropy method: 'shannon' or 'ic'")
def fingerprint_cmd(text, method):
    """Calculate entropy/IC of ciphertext."""
    if method == "shannon" or method == "all":
        click.echo(f"Shannon Entropy: {fingerprint.shannon_entropy(text):.4f} bits/symbol")
    if method == "ic" or method == "all":
        click.echo(f"Index of Coincidence: {fingerprint.index_of_coincidence(text):.4f}")


@cli.command(name="analyze")
@click.argument("text", type=click.STRING)
@click.option("--family", default="unknown", help="Cipher family hint for attack metadata")
@click.option("--json-out", is_flag=True, help="Emit full property profile as JSON")
def analyze_cmd(text, family, json_out):
    """Full ciphertext property profile (fingerprint, frequency, Kasiski, n-grams, attacks)."""
    profile = analyze_ciphertext(text, cipher_family=family)
    if json_out:
        click.echo(json.dumps(profile, indent=2))
        return
    fp = profile["fingerprint"]
    click.echo(f"Symbol class: {profile['stream']['symbol_class']}")
    click.echo(f"Shannon entropy: {fp['shannon_entropy_bits']:.4f} bits/symbol")
    click.echo(f"Index of coincidence: {fp['index_of_coincidence']:.4f}")
    kas = profile["kasiski"]
    if kas["candidate_key_lengths"]:
        click.echo(f"Kasiski key length candidates: {kas['candidate_key_lengths']}")
    click.echo("Attack surface:")
    for name, entry in profile["attacks"].items():
        click.echo(f"  {name}: {entry['viable']} (confidence={entry['confidence']})")


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
"""CLI entrypoint for cipherops toolkit."""

import click

from cipherops import fingerprint


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


if __name__ == "__main__":
    cli()

"""Constraint propagation for alphabet / key ordering."""

from cipherops.constraints.domain import (
    AlphabetDomain,
    ConstraintState,
    Finding,
    FindingKind,
    FindingsMap,
    Pin,
    Pair,
    merge_findings,
    coerce_symbol,
    plaintext_as_ints,
)
from cipherops.constraints.shared_keystream import load_noita_state, propagate_shared_keystream
from cipherops.constraints.stream_extension import propagate_from_crib_prefix, propagate_stream_extension
from cipherops.constraints.dynamic_perm import propagate_dynamic_perm
from cipherops.constraints.pipeline import (
    CorpusConfig,
    PipelineResult,
    StopReport,
    StopSuggestion,
    build_corpus_configs,
    diagnose_stop,
    run_findings_loop,
    validate_finding,
    validate_findings_map,
    finding_fingerprint,
)
from cipherops.constraints.adhoc import build_custom_config, list_dashboard_sources, propagator_for_slug
from cipherops.constraints.crib_hints import crib_pins_from_finding, merge_crib_pins, ACTIONABLE_KINDS

__all__ = [
    "AlphabetDomain",
    "ConstraintState",
    "Finding",
    "FindingKind",
    "FindingsMap",
    "Pin",
    "Pair",
    "coerce_symbol",
    "merge_findings",
    "plaintext_as_ints",
    "load_noita_state",
    "propagate_shared_keystream",
    "propagate_stream_extension",
    "propagate_from_crib_prefix",
    "propagate_dynamic_perm",
    "CorpusConfig",
    "PipelineResult",
    "StopReport",
    "StopSuggestion",
    "build_corpus_configs",
    "diagnose_stop",
    "run_findings_loop",
    "validate_finding",
    "validate_findings_map",
    "finding_fingerprint",
    "build_custom_config",
    "list_dashboard_sources",
    "propagator_for_slug",
    "crib_pins_from_finding",
    "merge_crib_pins",
    "ACTIONABLE_KINDS",
]

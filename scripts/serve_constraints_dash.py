#!/usr/bin/env python3
"""Serve the H3X-style constraint findings dashboard (static UI + JSON API)."""

from __future__ import annotations

import argparse
import json
import mimetypes
import socket
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web" / "constraints-dash"
sys.path.insert(0, str(ROOT))

from cipherops.analysis.brute_lane import run_brute_lane
from cipherops.analysis.classifier import classify_ciphertext, route_to_dash_payload
from cipherops.constraints.adhoc import build_custom_config, list_dashboard_sources
from cipherops.constraints.crib_hints import ACTIONABLE_KINDS, crib_pins_from_finding, merge_crib_pins
from cipherops.constraints.pipeline import finding_fingerprint, run_findings_loop
from cipherops.constraints.plaintext_view import assemble_plaintext_view
from cipherops.constraints.prepare_run import merge_prepare_into_payload, prepare_run

# In-memory cache of last analysis per client session (uuid).
_SESSION_CACHE: dict[str, dict[str, Any]] = {}


class DashHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _port_available(host: str, port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _pick_port(host: str, start: int, *, attempts: int = 20) -> int | None:
    for offset in range(attempts):
        port = start + offset
        if _port_available(host, port):
            return port
    return None


def _bind_error_message(host: str, port: int, exc: OSError) -> str:
    err = exc.errno
    if err in {98, 48, 10048}:  # EADDRINUSE (Linux, BSD, Windows)
        return (
            f"Port {port} on {host} is already in use.\n"
            f"  • Stop the other dash: pkill -f serve_constraints_dash.py\n"
            f"  • Or use another port: ./run.sh --port {port + 1}\n"
            f"  • Or: PYTHONPATH=. python3 scripts/serve_constraints_dash.py --port {port + 1}"
        )
    if err in {13, 10013}:
        return f"Permission denied binding to {host}:{port} (try port >= 1024 or run without sudo)."
    if err in {99, 10049}:
        return f"Cannot assign address {host}:{port} — check --host (use 127.0.0.1 or 0.0.0.0)."
    return f"Could not bind {host}:{port}: {exc}"


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8") or "{}")


def _filter_findings(
    findings: list[dict[str, Any]],
    *,
    kind: str | None,
    confidence: str | None,
    round_no: int | None,
    q: str | None,
    offset: int,
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    rows = findings
    if kind:
        rows = [r for r in rows if r.get("kind") == kind]
    if confidence:
        rows = [r for r in rows if r.get("confidence") == confidence]
    if round_no is not None:
        rows = [r for r in rows if r.get("round") == round_no]
    if q:
        needle = q.lower()
        rows = [
            r
            for r in rows
            if needle in json.dumps(r, ensure_ascii=False).lower()
        ]
    total = len(rows)
    return rows[offset : offset + limit], total


def _flatten_findings(result, corpus: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for round_report in result.rounds:
        for finding in round_report.findings:
            fp = finding_fingerprint(finding)
            rows.append(
                {
                    **finding,
                    "corpus": corpus,
                    "round": round_report.round,
                    "fingerprint": fp,
                }
            )
    return rows


def _corpus_meta_from_config(config, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    state = config.state
    payload = payload or {}
    return {
        "propagator": config.propagator,
        "deck_size": state.domain.size,
        "ciphertext": state.ciphertext or payload.get("ciphertext"),
        "ciphertexts": state.ciphertexts,
        "message_labels": state.message_labels,
        "hypothesis": dict(state.hypothesis),
        "plaintext_trial": state.plaintext_trial or payload.get("plaintext") or payload.get("plaintext_trial"),
    }


def _run_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    max_rounds = int(payload.get("max_rounds", 10))
    config = build_custom_config(payload, ROOT)
    result = run_findings_loop(config, max_rounds=max_rounds)
    findings = _flatten_findings(result, config.slug)
    corpus_meta = _corpus_meta_from_config(config, payload)
    plaintext_view = assemble_plaintext_view(
        findings=findings,
        grounded_pins=result.to_dict().get("grounded_pins", []),
        corpus_meta=corpus_meta,
    )
    return {
        "config": {
            "slug": config.slug,
            "propagator": config.propagator,
            "description": config.description,
            "deck_size": config.state.domain.size,
        },
        "corpus_meta": corpus_meta,
        "summary": result.to_dict(),
        "validated": result.final_validated,
        "findings": findings,
        "findings_count": len(findings),
        "plaintext_view": plaintext_view,
    }


def _best_routable_hypothesis_index(classification: dict[str, Any]) -> int:
    for i, h in enumerate(classification.get("hypotheses") or []):
        if h.get("needs_conversion"):
            continue
        prop = h.get("dash_propagator") or h.get("propagator")
        if prop and prop != "none":
            return i
        if h.get("dash_mode") == "noita":
            return i
        if h.get("dash_mode") == "fingerprinted" and h.get("dataset_slug"):
            return i
    return 0


def _resolve_route_context(
    payload: dict[str, Any],
    classification: dict[str, Any],
    hypothesis_index: int,
) -> tuple[dict[str, Any], int, dict[str, Any] | None, str | None, list[list[int]] | None]:
    """Prepare first, re-classify after encoding peel, return routing context."""
    prepared = None
    if not payload.get("skip_prepare"):
        prepared = prepare_run(
            classification,
            hypothesis_index,
            ciphertext=payload.get("ciphertext"),
            ciphertexts=payload.get("ciphertexts"),
            pins=payload.get("pins"),
        )

    work_classification = classification
    work_index = hypothesis_index
    work_ct: str | None = payload.get("ciphertext")
    work_decks: list[list[int]] | None = payload.get("ciphertexts")

    if prepared:
        if prepared.get("ciphertext"):
            work_ct = prepared["ciphertext"]
            work_decks = None
        if prepared.get("ciphertexts"):
            work_decks = prepared["ciphertexts"]
            work_ct = None

        if prepared.get("peeled"):
            if work_decks:
                work_classification = classify_ciphertext(
                    work_decks,
                    deck_size=int(prepared["deck_size"]) if prepared.get("deck_size") else None,
                )
            elif work_ct:
                work_classification = classify_ciphertext(work_ct)
            work_index = _best_routable_hypothesis_index(work_classification)

    return work_classification, work_index, prepared, work_ct, work_decks


class DashHandler(BaseHTTPRequestHandler):
    server_version = "ConstraintsDash/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/health":
            _json_response(self, 200, {"ok": True, "service": "constraints-dash"})
            return

        if path == "/api/sources":
            _json_response(self, 200, list_dashboard_sources(ROOT))
            return

        if path == "/api/findings":
            session_id = (qs.get("session") or [""])[0]
            if not session_id or session_id not in _SESSION_CACHE:
                _json_response(self, 404, {"error": "Unknown or missing session"})
                return
            cache = _SESSION_CACHE[session_id]
            findings = cache.get("findings", [])
            offset = int((qs.get("offset") or ["0"])[0])
            limit = min(int((qs.get("limit") or ["200"])[0]), 2000)
            kind = (qs.get("kind") or [None])[0]
            confidence = (qs.get("confidence") or [None])[0]
            round_raw = (qs.get("round") or [None])[0]
            round_no = int(round_raw) if round_raw is not None and round_raw != "" else None
            q = (qs.get("q") or [None])[0]
            page, total = _filter_findings(
                findings,
                kind=kind,
                confidence=confidence,
                round_no=round_no,
                q=q,
                offset=offset,
                limit=limit,
            )
            _json_response(
                self,
                200,
                {
                    "session": session_id,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "rows": page,
                    "summary": cache.get("summary"),
                    "config": cache.get("config"),
                },
            )
            return

        if path == "/api/plaintext-view":
            session_id = (qs.get("session") or [""])[0]
            if not session_id or session_id not in _SESSION_CACHE:
                _json_response(self, 404, {"error": "Unknown or missing session"})
                return
            cache = _SESSION_CACHE[session_id]
            view = cache.get("plaintext_view")
            if view is None:
                view = assemble_plaintext_view(
                    findings=cache.get("findings", []),
                    grounded_pins=(cache.get("summary") or {}).get("grounded_pins", []),
                    corpus_meta=cache.get("corpus_meta"),
                )
            _json_response(self, 200, {"session": session_id, "plaintext_view": view})
            return

        if path in {"/", "/index.html"}:
            self._serve_file(WEB_ROOT / "index.html")
            return

        if path.startswith("/assets/"):
            rel = path[len("/assets/") :]
            if not rel or ".." in rel.split("/"):
                self.send_error(404)
                return
            assets_root = (WEB_ROOT / "assets").resolve()
            target = (assets_root / rel).resolve()
            if not str(target).startswith(str(assets_root)):
                self.send_error(404)
                return
            if target.is_file():
                self._serve_file(target)
                return

        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/crib-from-finding":
            try:
                payload = _read_json_body(self)
                finding = payload.get("finding")
                if not finding:
                    _json_response(self, 400, {"error": "finding required"})
                    return
                deck_size = int(payload.get("deck_size", 83))
                anchor_pt = int(payload.get("anchor_pt", 10))
                existing = payload.get("existing_pins") or []
                hint = crib_pins_from_finding(finding, deck_size=deck_size, anchor_pt=anchor_pt)
                if hint.get("pins"):
                    hint["merged_pins"] = merge_crib_pins(existing, hint["pins"])
                _json_response(self, 200, hint)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/classify":
            try:
                payload = _read_json_body(self)
                if payload.get("source") == "noita":
                    import json as _json

                    corpus = _json.loads(
                        (ROOT / "datasets/unsolved/noita-eye-messages/corpus.json").read_text(encoding="utf-8")
                    )
                    result = classify_ciphertext(corpus["ciphertexts"], deck_size=int(corpus["deck_size"]))
                    _json_response(self, 200, result)
                    return
                ct = payload.get("ciphertext")
                decks = payload.get("ciphertexts")
                deck_size = payload.get("deck_size")
                if ct is None and decks is None:
                    _json_response(self, 400, {"error": "ciphertext or ciphertexts required"})
                    return
                result = classify_ciphertext(
                    ct,
                    ciphertexts=decks,
                    deck_size=int(deck_size) if deck_size is not None else None,
                )
                _json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/prepare-run":
            try:
                payload = _read_json_body(self)
                classification = payload.get("classification")
                if not classification:
                    _json_response(self, 400, {"error": "classification required"})
                    return
                idx = int(payload.get("hypothesis_index", 0))
                prepared = prepare_run(
                    classification,
                    idx,
                    ciphertext=payload.get("ciphertext"),
                    ciphertexts=payload.get("ciphertexts"),
                    pins=payload.get("pins"),
                )
                _json_response(self, 200, prepared)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/route-run":
            try:
                payload = _read_json_body(self)
                classification = payload.get("classification")
                if not classification:
                    _json_response(self, 400, {"error": "classification required"})
                    return
                idx = int(payload.get("hypothesis_index", 0))
                work_classification, work_index, prepared, work_ct, work_decks = _resolve_route_context(
                    payload, classification, idx
                )
                merged_pins = payload.get("pins")
                if prepared and prepared.get("pins"):
                    merged_pins = merge_crib_pins(payload.get("pins") or [], prepared["pins"])

                analyze_payload = route_to_dash_payload(
                    work_classification,
                    work_index,
                    ciphertext=work_ct,
                    pins=merged_pins,
                    max_rounds=int(payload.get("max_rounds", 10)),
                )
                if work_decks is not None:
                    analyze_payload["ciphertexts"] = work_decks
                if prepared:
                    analyze_payload = merge_prepare_into_payload(analyze_payload, prepared)
                hyp_override = payload.get("hypothesis_override")
                if hyp_override:
                    base = dict(analyze_payload.get("hypothesis") or {})
                    base.update(hyp_override)
                    analyze_payload["hypothesis"] = base
                    if "prng_seed" in hyp_override and analyze_payload.get("propagator") == "dynamic_perm":
                        center = int(hyp_override["prng_seed"])
                        analyze_payload["seed_candidates"] = [center - 1, center, center + 1]
                if payload.get("plaintext_trial"):
                    analyze_payload["plaintext"] = payload["plaintext_trial"]
                elif prepared and prepared.get("plaintext_trial"):
                    analyze_payload["plaintext"] = prepared["plaintext_trial"]
                session_id = payload.get("session") or str(uuid.uuid4())
                result = _run_analysis(analyze_payload)
                result["classification"] = work_classification
                result["last_payload"] = analyze_payload
                if prepared:
                    result["prepare"] = prepared
                _SESSION_CACHE[session_id] = result
                hyp = (work_classification.get("hypotheses") or [{}])[work_index]
                response: dict[str, Any] = {
                    "session": session_id,
                    "config": result["config"],
                    "summary": result["summary"],
                    "validated_count": len(result["validated"]),
                    "findings_count": result["findings_count"],
                    "preview": result["findings"][:100],
                    "plaintext_view": result["plaintext_view"],
                    "actionable_kinds": sorted(ACTIONABLE_KINDS),
                    "route": {
                        "hypothesis_index": work_index,
                        "label": hyp.get("label"),
                        "propagator": hyp.get("dash_propagator") or hyp.get("propagator"),
                        "deck_size": hyp.get("deck_size") or result["config"].get("deck_size"),
                    },
                }
                if prepared:
                    response["prepare"] = prepared
                if work_index != idx or (prepared and prepared.get("peeled")):
                    response["route"]["original_hypothesis_index"] = idx
                    response["reclassified"] = bool(prepared and prepared.get("peeled"))
                if prepared and prepared.get("peeled"):
                    response["classification"] = work_classification
                _json_response(self, 200, response)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/brute-force":
            try:
                payload = _read_json_body(self)
                session_id = payload.get("session")
                cache = _SESSION_CACHE.get(session_id or "") if session_id else {}
                ciphertext = payload.get("ciphertext") or (cache.get("corpus_meta") or {}).get("ciphertext")
                if not ciphertext:
                    _json_response(self, 400, {"error": "ciphertext required"})
                    return
                corpus_meta = cache.get("corpus_meta") or {}
                result = run_brute_lane(
                    ciphertext=str(ciphertext),
                    lane=payload.get("lane", "auto"),
                    propagator=corpus_meta.get("propagator") or (cache.get("config") or {}).get("propagator"),
                    classification=payload.get("classification") or cache.get("classification"),
                    hypothesis=payload.get("hypothesis") or corpus_meta.get("hypothesis"),
                    seed_length=int(payload.get("seed_length", 3)),
                    top_n=min(int(payload.get("top_n", 10)), 50),
                    gak_mode=str(payload.get("gak_mode", corpus_meta.get("hypothesis", {}).get("mode", "ctak_right"))),
                    gak_seed_min=int(payload.get("gak_seed_min", 0)),
                    gak_seed_max=int(payload.get("gak_seed_max", 500)),
                    plaintext_trial=payload.get("plaintext_trial") or corpus_meta.get("plaintext_trial"),
                )
                if session_id and session_id in _SESSION_CACHE:
                    _SESSION_CACHE[session_id]["last_brute"] = result
                _json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 400, {"error": str(exc)})
            return

        if path != "/api/analyze":
            self.send_error(404)
            return

        try:
            payload = _read_json_body(self)
            session_id = payload.get("session") or str(uuid.uuid4())
            result = _run_analysis(payload)
            _SESSION_CACHE[session_id] = result
            _json_response(
                self,
                200,
                {
                    "session": session_id,
                    "config": result["config"],
                    "summary": result["summary"],
                    "validated_count": len(result["validated"]),
                    "findings_count": result["findings_count"],
                    "preview": result["findings"][:100],
                    "plaintext_view": result["plaintext_view"],
                    "actionable_kinds": sorted(ACTIONABLE_KINDS),
                },
            )
        except Exception as exc:  # noqa: BLE001 — return API error to browser
            _json_response(self, 400, {"error": str(exc)})

    def _serve_file(self, path: Path) -> None:
        content = path.read_bytes()
        mime, _ = mimetypes.guess_type(str(path))
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--auto-port",
        action="store_true",
        help="If --port is busy, try the next free port (up to +19)",
    )
    args = parser.parse_args()

    if not WEB_ROOT.is_dir():
        print(f"Missing web root: {WEB_ROOT}", file=sys.stderr)
        return 1

    host = args.host
    port = args.port
    if not _port_available(host, port):
        if args.auto_port:
            picked = _pick_port(host, port)
            if picked is None:
                print(_bind_error_message(host, port, OSError(98, "Address in use")), file=sys.stderr)
                return 1
            if picked != port:
                print(f"Port {port} busy — using {picked} instead.", file=sys.stderr)
            port = picked
        else:
            print(_bind_error_message(host, port, OSError(98, "Address in use")), file=sys.stderr)
            return 1

    try:
        server = DashHTTPServer((host, port), DashHandler)
    except OSError as exc:
        print(_bind_error_message(host, port, exc), file=sys.stderr)
        return 1

    display_host = "127.0.0.1" if host in {"0.0.0.0", ""} else host
    url = f"http://{display_host}:{port}/"
    print(f"H3X Constraints Dash → {url}")
    if host == "0.0.0.0":
        print(f"  LAN: bind 0.0.0.0:{port} — open http://<machine-ip>:{port}/ from other devices")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

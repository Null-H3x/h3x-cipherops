#!/usr/bin/env python3
"""Serve the H3X-style constraint findings dashboard (static UI + JSON API)."""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web" / "constraints-dash"
sys.path.insert(0, str(ROOT))

from cipherops.constraints.adhoc import build_custom_config, list_dashboard_sources
from cipherops.constraints.pipeline import finding_fingerprint, run_findings_loop

# In-memory cache of last analysis per client session (uuid).
_SESSION_CACHE: dict[str, dict[str, Any]] = {}


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


def _run_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    max_rounds = int(payload.get("max_rounds", 10))
    config = build_custom_config(payload, ROOT)
    result = run_findings_loop(config, max_rounds=max_rounds)
    findings = _flatten_findings(result, config.slug)
    return {
        "config": {
            "slug": config.slug,
            "propagator": config.propagator,
            "description": config.description,
        },
        "summary": result.to_dict(),
        "validated": result.final_validated,
        "findings": findings,
        "findings_count": len(findings),
    }


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

        if path in {"/", "/index.html"}:
            self._serve_file(WEB_ROOT / "index.html")
            return

        if path.startswith("/assets/"):
            rel = path[len("/assets/") :]
            target = WEB_ROOT / rel
            if target.is_file():
                self._serve_file(target)
                return

        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/analyze":
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
    args = parser.parse_args()

    if not WEB_ROOT.is_dir():
        print(f"Missing web root: {WEB_ROOT}", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer((args.host, args.port), DashHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"H3X Constraints Dash → {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

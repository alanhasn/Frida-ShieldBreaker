"""Session report generation for Frida-ShieldBreaker.

Turns the structured `event`/`log`/`ready` messages every agent module
already emits over IPC (see `core.ipc.IPCBus`) into a JSON, HTML, and/or
DOCX report, without requiring any changes to the modules themselves.

Usage (see `main.py`'s `cmd_run` for the real integration):

    from core.report import ReportCollector, write_reports

    collector = ReportCollector()
    collector.attach(loader.ipc)
    ...
    report = collector.build_report(meta)
    write_reports(report, Path("reports/session"), formats=["json", "html", "docx"])
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from core.report.collector import ReportCollector
from core.report.model import Finding, InterpretedFinding, SessionMeta, SessionReport

__all__ = [
    "ReportCollector",
    "Finding",
    "InterpretedFinding",
    "SessionMeta",
    "SessionReport",
    "write_reports",
    "SUPPORTED_FORMATS",
]

SUPPORTED_FORMATS = ("json", "html", "docx")


def write_reports(report: SessionReport, base_path: Path, formats: Iterable[str] = SUPPORTED_FORMATS) -> list[Path]:
    """Renders `report` in each requested format and writes it to `base_path` with that format's extension.

    `base_path` should have no extension (or any existing one is
    replaced) -- e.g. `Path("reports/session")` produces
    `reports/session.json`, `reports/session.html`, `reports/session.docx`.
    Returns the list of paths actually written, in the order given.
    """
    written: list[Path] = []
    base_path.parent.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        fmt = fmt.strip().lower()
        out_path = base_path.with_suffix(f".{fmt}")

        if fmt == "json":
            from core.report.json_renderer import render_json

            out_path.write_text(render_json(report), encoding="utf-8")
        elif fmt == "html":
            from core.report.html_renderer import render_html

            out_path.write_text(render_html(report), encoding="utf-8")
        elif fmt == "docx":
            from core.report.docx_renderer import render_docx

            out_path.write_bytes(render_docx(report))
        else:
            raise ValueError(f"Unsupported report format: {fmt!r} (supported: {', '.join(SUPPORTED_FORMATS)})")

        written.append(out_path)

    return written

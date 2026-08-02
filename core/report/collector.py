"""Collects a session's IPC traffic into a `SessionReport`.

`ReportCollector` registers itself as additional handlers on an
`IPCBus` (`IPCBus.on()` supports multiple handlers per message type
already, so this needs no changes to `core/ipc.py`) and accumulates
every `event`/`ready` message it sees, plus a per-level count of `log`
messages for the session-statistics section of a report. It never
replaces the bus's existing console-logging handlers -- attaching a
collector is purely additive.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from core.ipc import IPCBus
from core.report.interpreters import interpret
from core.report.model import Finding, SessionMeta, SessionReport


class ReportCollector:
    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._log_level_counts: dict[str, int] = defaultdict(int)
        self._ready_payload: dict[str, Any] = {}

    def attach(self, ipc: IPCBus) -> None:
        """Registers this collector's handlers on `ipc`. Safe to call once per session."""
        ipc.on("event", self._handle_event)
        ipc.on("ready", self._handle_ready)
        ipc.on("log", self._handle_log)

    def _handle_event(self, module: str, payload: dict[str, Any]) -> None:
        name = payload.get("name", "event")
        seq = payload.get("seq", 0)
        ts = payload.get("ts", 0)
        details = {k: v for k, v in payload.items() if k not in ("name", "seq", "ts")}
        self._findings.append(Finding(seq=seq, ts=ts, module=module, name=name, payload=details))

    def _handle_ready(self, module: str, payload: dict[str, Any]) -> None:
        # Authoritative for which modules actually initialized -- important
        # for --auto sessions, where main.py doesn't know the module list
        # in advance (see agents/loader.js's bootstrap()).
        self._ready_payload = payload

    def _handle_log(self, module: str, payload: dict[str, Any]) -> None:
        level = str(payload.get("level", "info")).lower()
        self._log_level_counts[level] += 1

    def build_report(self, meta: SessionMeta) -> SessionReport:
        """Finalizes `meta` with what was learned from the `ready` message, and assembles the full report."""
        if self._ready_payload:
            meta.modules_enabled = list(self._ready_payload.get("enabled_modules", meta.modules_enabled))
            if meta.platform is None:
                meta.platform = self._ready_payload.get("platform")
            if meta.arch is None:
                meta.arch = self._ready_payload.get("arch")

        findings_sorted = sorted(self._findings, key=lambda f: f.seq)
        interpreted = [interpret(f) for f in findings_sorted]

        return SessionReport(
            meta=meta,
            findings=interpreted,
            log_level_counts=dict(self._log_level_counts),
            modules_ready_payload=dict(self._ready_payload),
        )

"""Data model for Frida-ShieldBreaker session reports.

Populated at runtime by `core.report.collector.ReportCollector` from the
same IPC event stream every agent module already emits, then rendered
into JSON/HTML/DOCX by the sibling `*_renderer` modules. This module
owns the data shape only -- it has no opinion about how a report is
collected or rendered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Ordered worst-to-best is not the point here -- this is the fixed
# severity vocabulary every interpreter (core.report.interpreters) must
# use, and the order renderers sort/display them in.
SEVERITY_ORDER = ("high", "medium", "low", "info")

# Canonical category slug -> display title. Interpreters assign findings
# to these slugs; renderers only ever need to know the title for display.
# "other" is the catch-all for any event type without a registered
# interpreter, so an unrecognized (e.g. future) event still renders
# sensibly instead of being dropped.
CATEGORY_TITLES: dict[str, str] = {
    "root_jailbreak": "Root / Jailbreak Detection",
    "developer_mode": "Developer Mode Detection",
    "process_execution": "Process Execution",
    "device_fingerprint": "Device Fingerprinting",
    "tls_pinning": "TLS Certificate Validation & Pinning",
    "anti_debugging": "Anti-Debugging",
    "reconnaissance": "Runtime Reconnaissance",
    "flutter_tls": "Flutter TLS Instrumentation",
    "framework_detection": "Framework Detection",
    "other": "Other",
}


@dataclass
class Finding:
    """One raw `event` message received from the agent, in arrival order."""

    seq: int
    ts: int  # epoch milliseconds, as reported by the agent's Date.now()
    module: str
    name: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> datetime:
        if not self.ts:
            return datetime.now(timezone.utc)
        return datetime.fromtimestamp(self.ts / 1000, tz=timezone.utc)


@dataclass
class InterpretedFinding:
    """A `Finding` plus the human-readable interpretation applied to it (see `core.report.interpreters`)."""

    finding: Finding
    title: str
    description: str
    category: str
    severity: str  # one of SEVERITY_ORDER

    @property
    def bypassed(self) -> bool:
        return bool(self.finding.payload.get("bypassed"))

    @property
    def category_title(self) -> str:
        return CATEGORY_TITLES.get(self.category, self.category)


@dataclass
class SessionMeta:
    """Everything known about the session itself, independent of any one finding."""

    target: str
    device_name: str
    platform: Optional[str] = None
    arch: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None
    modules_requested: list[str] = field(default_factory=list)
    modules_enabled: list[str] = field(default_factory=list)
    auto_detect: bool = False
    bypass_requested: bool = False
    agent_path: str = ""
    tool_version: str = "unknown"

    @property
    def duration_seconds(self) -> float:
        if self.ended_at is None:
            return 0.0
        return max(0.0, (self.ended_at - self.started_at).total_seconds())


@dataclass
class CategorySummary:
    category: str
    title: str
    total: int
    bypassed: int


@dataclass
class SessionReport:
    """Top-level, fully-assembled report -- what every renderer consumes."""

    meta: SessionMeta
    findings: list[InterpretedFinding] = field(default_factory=list)
    log_level_counts: dict[str, int] = field(default_factory=dict)
    modules_ready_payload: dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_bypassed(self) -> int:
        return sum(1 for f in self.findings if f.bypassed)

    def severity_counts(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def by_category(self) -> list[CategorySummary]:
        """Category summaries, in encounter order, each listing its own findings in original sequence."""
        order: list[str] = []
        totals: dict[str, int] = {}
        bypassed: dict[str, int] = {}
        for f in self.findings:
            if f.category not in totals:
                order.append(f.category)
                totals[f.category] = 0
                bypassed[f.category] = 0
            totals[f.category] += 1
            if f.bypassed:
                bypassed[f.category] += 1
        return [
            CategorySummary(category=cat, title=CATEGORY_TITLES.get(cat, cat), total=totals[cat], bypassed=bypassed[cat])
            for cat in order
        ]

    def findings_in_category(self, category: str) -> list[InterpretedFinding]:
        return [f for f in self.findings if f.category == category]

"""JSON report renderer -- the machine-readable format the other two derive their content from."""

from __future__ import annotations

import json
from typing import Any

from core.report.model import InterpretedFinding, SessionReport


def _finding_to_dict(f: InterpretedFinding) -> dict[str, Any]:
    return {
        "seq": f.finding.seq,
        "ts": f.finding.ts,
        "timestamp": f.finding.timestamp.isoformat(),
        "module": f.finding.module,
        "name": f.finding.name,
        "category": f.category,
        "category_title": f.category_title,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "bypassed": f.bypassed,
        "payload": f.finding.payload,
    }


def render_json(report: SessionReport) -> str:
    """Renders `report` as an indented, deterministic JSON document."""
    meta = report.meta
    data = {
        "tool": "Frida-ShieldBreaker",
        "tool_version": meta.tool_version,
        "session": {
            "target": meta.target,
            "device": meta.device_name,
            "platform": meta.platform,
            "arch": meta.arch,
            "started_at": meta.started_at.isoformat(),
            "ended_at": meta.ended_at.isoformat() if meta.ended_at else None,
            "duration_seconds": round(meta.duration_seconds, 3),
            "modules_requested": meta.modules_requested,
            "modules_enabled": meta.modules_enabled,
            "auto_detect": meta.auto_detect,
            "bypass_requested": meta.bypass_requested,
            "agent_path": meta.agent_path,
        },
        "summary": {
            "total_findings": report.total_findings,
            "total_bypassed": report.total_bypassed,
            "severity_counts": report.severity_counts(),
            "log_level_counts": report.log_level_counts,
            "categories": [
                {"category": c.category, "title": c.title, "total": c.total, "bypassed": c.bypassed}
                for c in report.by_category()
            ],
        },
        "findings": [_finding_to_dict(f) for f in report.findings],
    }
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)

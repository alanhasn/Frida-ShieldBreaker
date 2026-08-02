"""HTML report renderer.

Produces a single, self-contained HTML document (inline CSS, no external
requests) suitable for opening directly in a browser or attaching to an
engagement writeup. Follows a fixed, restrained color scheme: the status
palette (critical/warning/neutral) for finding severity, a single
sequential hue for the category-magnitude bars, and plain text/surface
tokens everywhere else -- no per-category rainbow, since a report can
have far more categories than a palette can keep pairwise distinct.
"""

from __future__ import annotations

from html import escape

from core.report.model import CategorySummary, InterpretedFinding, SessionReport

_SEVERITY_LABELS = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _severity_badge(severity: str) -> str:
    label = escape(_SEVERITY_LABELS.get(severity, severity.title()))
    return f'<span class="badge badge-{escape(severity)}">{label}</span>'


def _stat_tile(label: str, value: str, accent: str = "") -> str:
    accent_class = f" stat-{accent}" if accent else ""
    return (
        f'<div class="stat-tile{accent_class}">'
        f'<div class="stat-value">{escape(value)}</div>'
        f'<div class="stat-label">{escape(label)}</div>'
        f"</div>"
    )


def _category_bar_row(cat: CategorySummary, max_total: int) -> str:
    width_pct = round((cat.total / max_total) * 100) if max_total else 0
    tooltip = f"{cat.title}: {cat.total} finding(s), {cat.bypassed} bypassed"
    return f"""
    <div class="cat-bar-row" title="{escape(tooltip)}">
      <div class="cat-bar-label">{escape(cat.title)}</div>
      <div class="cat-bar-track">
        <div class="cat-bar-fill" style="width:{width_pct}%"></div>
      </div>
      <div class="cat-bar-value">{cat.total}</div>
    </div>"""


def _finding_row(f: InterpretedFinding) -> str:
    ts = escape(f.finding.timestamp.strftime("%H:%M:%S.%f")[:-3])
    return f"""
        <tr>
          <td class="col-severity">{_severity_badge(f.severity)}</td>
          <td class="col-title">
            <div class="finding-title">{escape(f.title)}</div>
            <div class="finding-desc">{escape(f.description)}</div>
          </td>
          <td class="col-module">{escape(f.finding.module)}</td>
          <td class="col-time">{ts}</td>
        </tr>"""


def _category_section(report: SessionReport, cat: CategorySummary) -> str:
    findings = report.findings_in_category(cat.category)
    rows = "\n".join(_finding_row(f) for f in findings)
    return f"""
    <section class="category-section">
      <h3>{escape(cat.title)} <span class="count-pill">{cat.total}</span></h3>
      <table class="findings-table">
        <thead>
          <tr><th>Severity</th><th>Finding</th><th>Module</th><th>Time</th></tr>
        </thead>
        <tbody>{rows}
        </tbody>
      </table>
    </section>"""


def render_html(report: SessionReport) -> str:
    meta = report.meta
    severity_counts = report.severity_counts()
    categories = sorted(report.by_category(), key=lambda c: c.total, reverse=True)
    max_total = max((c.total for c in categories), default=0)

    stat_tiles = "".join(
        [
            _stat_tile("Total findings", str(report.total_findings)),
            _stat_tile(
                "Bypassed",
                str(report.total_bypassed),
                accent="critical" if report.total_bypassed else "neutral",
            ),
            _stat_tile("Modules run", str(len(meta.modules_enabled))),
            _stat_tile("Duration", _fmt_duration(meta.duration_seconds)),
        ]
    )

    category_bars = "".join(_category_bar_row(c, max_total) for c in categories) or (
        '<p class="empty-note">No findings were recorded during this session.</p>'
    )
    category_sections = "".join(_category_section(report, c) for c in categories)

    modules_enabled_str = ", ".join(meta.modules_enabled) or "none"
    modules_requested_str = ", ".join(meta.modules_requested) or ("auto-detected" if meta.auto_detect else "none")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Frida-ShieldBreaker Report — {escape(meta.target)}</title>
<style>
  :root {{
    color-scheme: light;
    --page: #f9f9f7;
    --surface: #fcfcfb;
    --ink: #0b0b0b;
    --ink-secondary: #52514e;
    --ink-muted: #898781;
    --gridline: #e1e0d9;
    --border: rgba(11,11,11,0.10);
    --seq-blue: #2a78d6;
    --status-critical: #d03b3b;
    --status-warning: #fab219;
    --status-neutral: #898781;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      color-scheme: dark;
      --page: #0d0d0d;
      --surface: #1a1a19;
      --ink: #ffffff;
      --ink-secondary: #c3c2b7;
      --ink-muted: #898781;
      --gridline: #2c2c2a;
      --border: rgba(255,255,255,0.10);
      --seq-blue: #3987e5;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--page);
    color: var(--ink);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  header.report-header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 28px;
  }}
  header.report-header h1 {{ font-size: 1.5rem; margin: 0 0 4px; }}
  header.report-header .subtitle {{ color: var(--ink-secondary); font-size: 0.95rem; }}
  .disclaimer {{
    margin-top: 12px;
    font-size: 0.8rem;
    color: var(--ink-muted);
  }}
  section {{ margin-bottom: 36px; }}
  h2 {{ font-size: 1.1rem; margin: 0 0 14px; }}
  h3 {{ font-size: 1rem; margin: 0 0 10px; display: flex; align-items: center; gap: 8px; }}
  .count-pill {{
    display: inline-block;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--ink-secondary);
    background: var(--gridline);
    border-radius: 999px;
    padding: 1px 9px;
  }}
  .stat-row {{ display: flex; flex-wrap: wrap; gap: 12px; }}
  .stat-tile {{
    flex: 1 1 140px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }}
  .stat-tile .stat-value {{ font-size: 1.8rem; font-weight: 600; }}
  .stat-tile .stat-label {{ font-size: 0.8rem; color: var(--ink-secondary); margin-top: 2px; }}
  .stat-tile.stat-critical .stat-value {{ color: var(--status-critical); }}
  .stat-tile.stat-neutral .stat-value {{ color: var(--ink); }}
  table.meta-table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
  table.meta-table td {{ padding: 6px 0; border-bottom: 1px solid var(--gridline); }}
  table.meta-table td.k {{ color: var(--ink-secondary); width: 220px; }}
  .cat-bar-row {{
    display: grid;
    grid-template-columns: 220px 1fr 40px;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
    font-size: 0.85rem;
  }}
  .cat-bar-label {{ color: var(--ink-secondary); }}
  .cat-bar-track {{ background: var(--gridline); border-radius: 4px; height: 16px; overflow: hidden; }}
  .cat-bar-fill {{ background: var(--seq-blue); height: 100%; border-radius: 4px; }}
  .cat-bar-value {{ text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-secondary); }}
  .findings-table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
  .findings-table th {{
    text-align: left;
    font-weight: 600;
    color: var(--ink-secondary);
    border-bottom: 1px solid var(--gridline);
    padding: 8px 10px;
  }}
  .findings-table td {{ padding: 8px 10px; border-bottom: 1px solid var(--gridline); vertical-align: top; }}
  .findings-table tr:last-child td {{ border-bottom: none; }}
  .col-severity {{ width: 90px; }}
  .col-module {{ width: 110px; color: var(--ink-secondary); }}
  .col-time {{ width: 110px; color: var(--ink-muted); font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .finding-title {{ font-weight: 600; }}
  .finding-desc {{ color: var(--ink-secondary); margin-top: 2px; }}
  .badge {{
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    border-radius: 5px;
    padding: 2px 7px;
    border: 1px solid transparent;
  }}
  .badge-high {{ color: var(--status-critical); border-color: var(--status-critical); }}
  .badge-medium {{ color: var(--status-warning); border-color: var(--status-warning); }}
  .badge-low, .badge-info {{ color: var(--ink-muted); border-color: var(--gridline); }}
  .empty-note {{ color: var(--ink-muted); font-style: italic; }}
  footer {{
    border-top: 1px solid var(--border);
    padding-top: 16px;
    margin-top: 40px;
    font-size: 0.78rem;
    color: var(--ink-muted);
  }}
</style>
</head>
<body>
<div class="wrap">

<header class="report-header">
  <h1>Frida-ShieldBreaker Session Report</h1>
  <div class="subtitle">Target: {escape(meta.target)} · Device: {escape(meta.device_name)} · Generated {escape(meta.started_at.strftime("%Y-%m-%d %H:%M UTC"))}</div>
  <div class="disclaimer">For use only on targets you own or are explicitly authorized to test.</div>
</header>

<section class="summary">
  <h2>Executive summary</h2>
  <div class="stat-row">{stat_tiles}</div>
</section>

<section class="session-details">
  <h2>Session details</h2>
  <table class="meta-table">
    <tr><td class="k">Target</td><td>{escape(meta.target)}</td></tr>
    <tr><td class="k">Device</td><td>{escape(meta.device_name)}</td></tr>
    <tr><td class="k">Platform / architecture</td><td>{escape(meta.platform or "unknown")} / {escape(meta.arch or "unknown")}</td></tr>
    <tr><td class="k">Started</td><td>{escape(meta.started_at.isoformat())}</td></tr>
    <tr><td class="k">Duration</td><td>{_fmt_duration(meta.duration_seconds)}</td></tr>
    <tr><td class="k">Modules requested</td><td>{escape(modules_requested_str)}</td></tr>
    <tr><td class="k">Modules enabled</td><td>{escape(modules_enabled_str)}</td></tr>
    <tr><td class="k">Automatic framework detection</td><td>{"enabled" if meta.auto_detect else "disabled"}</td></tr>
    <tr><td class="k">Active bypass requested</td><td>{"yes" if meta.bypass_requested else "no"}</td></tr>
    <tr><td class="k">Frida-ShieldBreaker version</td><td>{escape(meta.tool_version)}</td></tr>
  </table>
</section>

<section class="category-breakdown">
  <h2>Findings by category</h2>
  {category_bars}
</section>

<section class="findings">
  <h2>Detailed findings</h2>
  {category_sections or '<p class="empty-note">No findings were recorded during this session.</p>'}
</section>

<footer>
  Generated by Frida-ShieldBreaker {escape(meta.tool_version)} · Severity: high = bypassed/high-impact,
  medium = observed or automatic action, low/info = diagnostic only ({severity_counts.get("high", 0)} high,
  {severity_counts.get("medium", 0)} medium, {severity_counts.get("low", 0)} low, {severity_counts.get("info", 0)} info)
</footer>

</div>
</body>
</html>
"""

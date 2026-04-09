"""
HTML report generator.

Produces a fully self-contained, single-file HTML report with:
  - Summary scorecard (pass / fail / manual / skipped / error counts)
  - Severity breakdown bar
  - Findings grouped by CIS section, each section collapsible
  - Filter buttons (status) + search input that hide empty sections
  - Expandable detail panel per finding (description, rationale, evidence,
    remediation, CIS controls, references)
  - AccuKnox branding

No external dependencies — all CSS and JS are inlined.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict
from datetime import datetime, timezone

from sspm.core.models import AssessmentStatus, FindingStatus, ScanResult, Severity

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_STATUS_COLOURS = {
    FindingStatus.PASS:    ("#22c55e", "#dcfce7", "#166534"),
    FindingStatus.FAIL:    ("#ef4444", "#fee2e2", "#991b1b"),
    FindingStatus.MANUAL:  ("#f59e0b", "#fef3c7", "#92400e"),
    FindingStatus.ERROR:   ("#a855f7", "#f3e8ff", "#6b21a8"),
    FindingStatus.SKIPPED: ("#94a3b8", "#f1f5f9", "#475569"),
}

_SEVERITY_COLOURS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#ca8a04",
    Severity.LOW:      "#2563eb",
    Severity.INFO:     "#64748b",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _status_badge(status: FindingStatus) -> str:
    accent, bg, text = _STATUS_COLOURS.get(status, ("#94a3b8", "#f1f5f9", "#475569"))
    return (
        f'<span class="badge" style="background:{bg};color:{text};'
        f'border:1px solid {accent}">{status.value.upper()}</span>'
    )


def _severity_badge(severity: Severity) -> str:
    colour = _SEVERITY_COLOURS.get(severity, "#64748b")
    return (
        f'<span class="badge sev-badge" style="background:{colour}1a;'
        f'color:{colour};border:1px solid {colour}">'
        f'{_e(severity.value.upper())}</span>'
    )


def _assessment_badge(status: AssessmentStatus) -> str:
    if status == AssessmentStatus.AUTOMATED:
        return '<span class="badge" style="background:#eff6ff;color:#1d4ed8;border:1px solid #93c5fd">AUTO</span>'
    return '<span class="badge" style="background:#fff7ed;color:#c2410c;border:1px solid #fdba74">MANUAL</span>'


def _section_sort_key(section_name: str):
    """Sort CIS sections numerically: '1.1 Users' → [1, 1]."""
    prefix = section_name.split(" ")[0]
    try:
        return [int(p) for p in prefix.split(".")]
    except ValueError:
        return [999]


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --border: #e2e8f0;
  --text: #1e293b;
  --muted: #64748b;
  --accent: #1d4ed8;
  --radius: 8px;
  --shadow: 0 1px 3px rgba(0,0,0,.1), 0 1px 2px rgba(0,0,0,.06);
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}

/* ---- Header ---- */
.header {
  background: linear-gradient(135deg, #1e3a5f 0%, #1d4ed8 100%);
  color: #fff;
  padding: 24px 32px;
}
.header-inner { max-width: 1280px; margin: 0 auto; }
.header h1 { font-size: 22px; font-weight: 700; letter-spacing: -.3px; }
.header-sub { font-size: 13px; opacity: .75; margin-top: 4px; }
.header-meta { display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }
.header-meta span { font-size: 12px; opacity: .8; }
.header-meta strong { opacity: 1; }

/* ---- Main layout ---- */
.main { max-width: 1280px; margin: 0 auto; padding: 24px 32px 48px; }

/* ---- Score cards ---- */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  text-align: center;
  box-shadow: var(--shadow);
}
.card-num { font-size: 32px; font-weight: 700; line-height: 1; }
.card-label { font-size: 12px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }

/* ---- Severity bar ---- */
.sev-section { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; margin-bottom: 24px; box-shadow: var(--shadow); }
.sev-section h3 { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; margin-bottom: 12px; }
.sev-bar { display: flex; border-radius: 6px; overflow: hidden; height: 10px; background: var(--border); }
.sev-seg { height: 100%; transition: width .4s; }
.sev-legend { display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; }
.sev-legend-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); }
.sev-dot { width: 10px; height: 10px; border-radius: 50%; }

/* ---- Filters ---- */
.filters {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  margin-bottom: 16px;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
  box-shadow: var(--shadow);
}
.filters input[type=search] {
  flex: 1;
  min-width: 200px;
  padding: 7px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 13px;
  outline: none;
  background: var(--bg);
}
.filters input[type=search]:focus { border-color: var(--accent); }
.filter-btn {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg);
  font-size: 12px;
  cursor: pointer;
  color: var(--muted);
  transition: all .15s;
}
.filter-btn:hover, .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.filter-sep { width: 1px; background: var(--border); height: 24px; }
.collapse-btn {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg);
  font-size: 12px;
  cursor: pointer;
  color: var(--muted);
  transition: all .15s;
  margin-left: auto;
}
.collapse-btn:hover { background: #f1f5f9; color: var(--text); }

/* ---- Section groups ---- */
.table-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
  margin-bottom: 12px;
}
table { width: 100%; border-collapse: collapse; }
thead tr { background: #f8fafc; border-bottom: 2px solid var(--border); }
th {
  padding: 10px 14px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .5px;
  color: var(--muted);
  white-space: nowrap;
}

/* ---- Section header row ---- */
tr.section-hdr td {
  padding: 10px 16px;
  background: #f1f5f9;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
}
tr.section-hdr:hover td { background: #e9eef5; }
.section-hdr-inner { display: flex; align-items: center; gap: 10px; }
.section-hdr-title { font-weight: 600; font-size: 13px; flex: 1; }
.section-hdr-num { font-size: 11px; font-weight: 700; color: var(--muted); font-family: ui-monospace, monospace; }
.section-stats { display: flex; gap: 6px; flex-wrap: wrap; }
.section-stat { font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 10px; }
.stat-fail    { background: #fee2e2; color: #991b1b; }
.stat-pass    { background: #dcfce7; color: #166534; }
.stat-manual  { background: #fef3c7; color: #92400e; }
.stat-skipped { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
.stat-error   { background: #f3e8ff; color: #6b21a8; }
.toggle-icon { font-size: 13px; transition: transform .2s; color: var(--muted); }
.section-hdr.collapsed .toggle-icon { transform: rotate(-90deg); }

/* ---- Finding rows ---- */
td { padding: 11px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr.finding-row:hover { background: #f8fafc; cursor: pointer; }
tr.finding-row.hidden { display: none; }
tr.detail-row.hidden { display: none; }

/* ---- Detail panel ---- */
tr.detail-row td { padding: 0; }
.detail-panel {
  padding: 20px 24px;
  background: #f8fafc;
  border-top: 1px solid var(--border);
  display: none;
}
.detail-panel.open { display: block; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media (max-width: 768px) { .detail-grid { grid-template-columns: 1fr; } }
.detail-section h4 { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin-bottom: 8px; }
.detail-section p, .detail-section pre { font-size: 13px; line-height: 1.6; color: var(--text); }
.detail-section pre {
  background: #1e293b;
  color: #e2e8f0;
  padding: 12px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
.detail-full { margin-top: 16px; }
.refs { display: flex; flex-direction: column; gap: 4px; }
.refs a { font-size: 12px; color: var(--accent); text-decoration: none; word-break: break-all; }
.refs a:hover { text-decoration: underline; }
.cis-controls { display: flex; flex-direction: column; gap: 6px; }
.cis-control { font-size: 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; }
.cis-control strong { color: var(--text); }
.ig-pills { display: inline-flex; gap: 4px; margin-left: 6px; }
.ig-pill { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: #dbeafe; color: #1d4ed8; }
.expand-icon { float: right; font-size: 16px; opacity: .5; transition: transform .2s; }
.finding-row.expanded .expand-icon { transform: rotate(180deg); opacity: 1; }

/* ---- Badges ---- */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; white-space: nowrap; }

/* ---- Rule ID ---- */
.rule-id { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); }
.rule-title { font-weight: 500; }

/* ---- Section hidden by filter ---- */
.table-wrap.section-hidden { display: none; }

/* ---- No results ---- */
.no-results-global { text-align: center; color: var(--muted); padding: 40px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); display: none; }

/* ---- Footer ---- */
.footer { text-align: center; color: var(--muted); font-size: 12px; padding: 16px; border-top: 1px solid var(--border); margin-top: 32px; }
"""

# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

_JS = """
(function () {
  'use strict';

  // ---- Toggle detail panel ----
  document.querySelectorAll('tr.finding-row').forEach(function (row) {
    row.addEventListener('click', function () {
      var detailRow = row.nextElementSibling;
      var panel = detailRow ? detailRow.querySelector('.detail-panel') : null;
      if (!panel) return;
      var isOpen = panel.classList.contains('open');

      // Close all others
      document.querySelectorAll('.detail-panel.open').forEach(function (p) {
        p.classList.remove('open');
        var prev = p.closest('tr').previousElementSibling;
        if (prev) prev.classList.remove('expanded');
      });

      if (!isOpen) {
        panel.classList.add('open');
        row.classList.add('expanded');
        row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  });

  // ---- Section collapse/expand ----
  document.querySelectorAll('tr.section-hdr').forEach(function (hdr) {
    hdr.addEventListener('click', function () {
      toggleSection(hdr);
    });
  });

  function toggleSection(hdr) {
    var wrap = hdr.closest('.table-wrap');
    var isCollapsed = hdr.classList.contains('collapsed');
    hdr.classList.toggle('collapsed', !isCollapsed);
    wrap.querySelectorAll('tr.finding-row, tr.detail-row').forEach(function (r) {
      if (!r.classList.contains('filter-hidden')) {
        r.style.display = isCollapsed ? '' : 'none';
      }
    });
  }

  // ---- Expand all / Collapse all ----
  document.getElementById('btn-expand-all') && document.getElementById('btn-expand-all').addEventListener('click', function () {
    document.querySelectorAll('tr.section-hdr.collapsed').forEach(function (hdr) {
      hdr.classList.remove('collapsed');
      var wrap = hdr.closest('.table-wrap');
      wrap.querySelectorAll('tr.finding-row, tr.detail-row').forEach(function (r) {
        if (!r.classList.contains('filter-hidden')) r.style.display = '';
      });
    });
  });
  document.getElementById('btn-collapse-all') && document.getElementById('btn-collapse-all').addEventListener('click', function () {
    document.querySelectorAll('tr.section-hdr').forEach(function (hdr) {
      hdr.classList.add('collapsed');
      var wrap = hdr.closest('.table-wrap');
      wrap.querySelectorAll('tr.finding-row, tr.detail-row').forEach(function (r) {
        r.style.display = 'none';
      });
    });
  });

  // ---- Filter by status ----
  document.querySelectorAll('.filter-btn[data-status]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var active = btn.classList.contains('active');
      document.querySelectorAll('.filter-btn[data-status]').forEach(function (b) {
        b.classList.remove('active');
      });
      if (!active) btn.classList.add('active');
      applyFilters();
    });
  });

  // ---- Search ----
  var searchInput = document.getElementById('search-input');
  if (searchInput) searchInput.addEventListener('input', applyFilters);

  function applyFilters() {
    var activeBtn = document.querySelector('.filter-btn[data-status].active');
    var statusFilter = activeBtn ? activeBtn.dataset.status : '';
    var searchTerm = searchInput ? searchInput.value.toLowerCase() : '';

    var totalVisible = 0;

    document.querySelectorAll('.table-wrap[data-section]').forEach(function (wrap) {
      var rows = wrap.querySelectorAll('tr.finding-row');
      var sectionVisible = 0;

      rows.forEach(function (row) {
        var detailRow = row.nextElementSibling;
        var matchStatus = !statusFilter || row.dataset.status === statusFilter;
        var matchSearch = !searchTerm || row.textContent.toLowerCase().includes(searchTerm);
        var show = matchStatus && matchSearch;

        row.classList.toggle('filter-hidden', !show);
        row.classList.toggle('hidden', !show);
        if (detailRow) {
          detailRow.classList.toggle('filter-hidden', !show);
          detailRow.classList.toggle('hidden', !show);
          if (!show && detailRow.querySelector('.detail-panel.open')) {
            detailRow.querySelector('.detail-panel').classList.remove('open');
            row.classList.remove('expanded');
          }
        }

        if (show) {
          sectionVisible++;
          totalVisible++;
          // Respect section collapse state
          var hdr = wrap.querySelector('tr.section-hdr');
          if (hdr && hdr.classList.contains('collapsed')) {
            row.style.display = 'none';
            if (detailRow) detailRow.style.display = 'none';
          } else {
            row.style.display = '';
            if (detailRow) detailRow.style.display = '';
          }
        }
      });

      // Hide entire section if no rows match
      wrap.classList.toggle('section-hidden', sectionVisible === 0);
      // Update section stat count display
      var countEl = wrap.querySelector('.section-filter-count');
      if (countEl) {
        countEl.textContent = statusFilter || searchTerm
          ? '(' + sectionVisible + ' shown)'
          : '';
      }
    });

    var noResults = document.getElementById('no-results-global');
    if (noResults) noResults.style.display = totalVisible === 0 ? 'block' : 'none';
  }
})();
"""


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------

def _severity_bar(findings) -> str:
    failed = [f for f in findings if f.status == FindingStatus.FAIL]
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in failed:
        counts[f.rule.severity] = counts.get(f.rule.severity, 0) + 1
    total = sum(counts.values()) or 1

    segments = ""
    for sev in _SEVERITY_ORDER:
        pct = counts[sev] / total * 100
        if pct > 0:
            colour = _SEVERITY_COLOURS[sev]
            segments += (
                f'<div class="sev-seg" style="width:{pct:.1f}%;background:{colour}" '
                f'title="{counts[sev]} {sev.value}"></div>'
            )

    legend = ""
    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            colour = _SEVERITY_COLOURS[sev]
            legend += (
                f'<div class="sev-legend-item">'
                f'<div class="sev-dot" style="background:{colour}"></div>'
                f'{counts[sev]} {_e(sev.value.capitalize())}</div>'
            )
    if not legend:
        legend = '<span style="color:var(--muted);font-size:12px">No failed controls</span>'

    return f"""
<div class="sev-section">
  <h3>Failed Controls by Severity</h3>
  <div class="sev-bar">{segments}</div>
  <div class="sev-legend">{legend}</div>
</div>"""


def _score_cards(result: ScanResult) -> str:
    s = result.summary()
    total = s["total"] or 1
    pass_pct = int(s["passed"] / total * 100)

    def card(num, label, colour):
        return (
            f'<div class="card">'
            f'<div class="card-num" style="color:{colour}">{num}</div>'
            f'<div class="card-label">{label}</div>'
            f'</div>'
        )

    return f"""
<div class="cards">
  {card(s['total'], 'Total', 'var(--text)')}
  {card(s['passed'], 'Passed', '#16a34a')}
  {card(s['failed'], 'Failed', '#dc2626')}
  {card(s['manual'], 'Manual', '#d97706')}
  {card(s['skipped'], 'Skipped', '#94a3b8')}
  {card(s['errors'], 'Errors', '#9333ea')}
  {card(f'{pass_pct}%', 'Pass Rate', '#16a34a' if pass_pct >= 80 else '#dc2626')}
</div>"""


def _detail_panel(finding) -> str:
    m = finding.rule

    def section(title, content):
        if not content:
            return ""
        return f'<div class="detail-section"><h4>{_e(title)}</h4>{content}</div>'

    # Evidence
    ev_html = ""
    if finding.evidence:
        ev_parts = []
        for ev in finding.evidence:
            data_str = json.dumps(ev.data, indent=2, default=str)
            ev_parts.append(
                f'<p style="font-size:12px;color:var(--muted);margin-bottom:4px">'
                f'<strong>{_e(ev.source)}</strong>'
                + (f' — {_e(ev.description)}' if ev.description else '')
                + f'</p><pre>{_e(data_str)}</pre>'
            )
        ev_html = "".join(ev_parts)

    # CIS controls
    cis_html = ""
    if m.cis_controls:
        parts = []
        for c in m.cis_controls:
            igs = ""
            for i, flag in enumerate([c.ig1, c.ig2, c.ig3], 1):
                if flag:
                    igs += f'<span class="ig-pill">IG{i}</span>'
            parts.append(
                f'<div class="cis-control">'
                f'<strong>{_e(c.version)} {_e(c.control_id)}</strong> — {_e(c.title)}'
                + (f'<span class="ig-pills">{igs}</span>' if igs else "")
                + '</div>'
            )
        cis_html = f'<div class="cis-controls">{"".join(parts)}</div>'

    # References
    refs_html = ""
    if m.references:
        links = "".join(
            f'<a href="{_e(r)}" target="_blank" rel="noopener">{_e(r)}</a>'
            for r in m.references
        )
        refs_html = f'<div class="refs">{links}</div>'

    remediation = finding.remediation_guidance or m.remediation

    top_grid = f"""
<div class="detail-grid">
  {section("Description", f'<p>{_e(m.description)}</p>')}
  {section("Rationale", f'<p>{_e(m.rationale)}</p>')}
  {section("Impact", f'<p>{_e(m.impact)}</p>')}
  {section("Remediation", f'<p>{_e(remediation)}</p>')}
</div>"""

    bottom_row = ""
    cols = []
    if m.audit_procedure:
        cols.append(section("Audit Procedure", f'<p style="white-space:pre-wrap">{_e(m.audit_procedure)}</p>'))
    if ev_html:
        cols.append(section("Evidence", ev_html))
    if cis_html:
        cols.append(section("CIS Controls", cis_html))
    if refs_html:
        cols.append(section("References", refs_html))
    if cols:
        bottom_row = f'<div class="detail-full detail-grid">{"".join(cols)}</div>'

    return f'<div class="detail-panel">{top_grid}{bottom_row}</div>'


def _section_stats_html(section_findings) -> str:
    counts = defaultdict(int)
    for f in section_findings:
        counts[f.status] += 1

    parts = []
    order = [
        (FindingStatus.FAIL,    "stat-fail",    "Fail"),
        (FindingStatus.PASS,    "stat-pass",    "Pass"),
        (FindingStatus.MANUAL,  "stat-manual",  "Manual"),
        (FindingStatus.SKIPPED, "stat-skipped", "Skipped"),
        (FindingStatus.ERROR,   "stat-error",   "Error"),
    ]
    for status, css_class, label in order:
        n = counts.get(status, 0)
        if n:
            parts.append(
                f'<span class="section-stat {css_class}">{n} {label}</span>'
            )
    return "".join(parts)


def _section_accent_colour(section_findings) -> str:
    """Left border colour reflecting overall section health."""
    statuses = {f.status for f in section_findings}
    if FindingStatus.FAIL in statuses:
        return "#ef4444"
    if FindingStatus.MANUAL in statuses:
        return "#f59e0b"
    return "#22c55e"


def _findings_table_grouped(findings) -> str:
    _SEV_SORT = {
        Severity.CRITICAL: "0", Severity.HIGH: "1",
        Severity.MEDIUM: "2",   Severity.LOW:  "3", Severity.INFO: "4",
    }
    _STATUS_SORT = {
        FindingStatus.FAIL: "0",    FindingStatus.MANUAL:  "1",
        FindingStatus.ERROR: "2",   FindingStatus.SKIPPED: "3",
        FindingStatus.PASS: "4",
    }

    # Group by section
    by_section: dict[str, list] = defaultdict(list)
    for f in findings:
        by_section[f.rule.section].append(f)

    sorted_sections = sorted(by_section.keys(), key=_section_sort_key)

    html_parts = []

    for section_name in sorted_sections:
        section_findings = by_section[section_name]
        accent = _section_accent_colour(section_findings)
        stats_html = _section_stats_html(section_findings)
        n = len(section_findings)

        # Section header number (e.g. "1.1" from "1.1 Users")
        section_num = section_name.split(" ")[0]
        section_title = section_name[len(section_num):].strip()

        # Finding rows for this section
        rows = ""
        for finding in section_findings:
            m = finding.rule
            status_badge = _status_badge(finding.status)
            sev_badge = _severity_badge(m.severity)
            assess_badge = _assessment_badge(m.assessment_status)
            message = _e(finding.message[:120] + ("…" if len(finding.message) > 120 else ""))

            rows += f"""
<tr class="finding-row" data-status="{_e(finding.status.value)}">
  <td data-sort="{_e(_STATUS_SORT.get(finding.status, '9'))}">{status_badge}</td>
  <td data-sort="{_e(_SEV_SORT.get(m.severity, '9'))}">{sev_badge}</td>
  <td><span class="rule-id">{_e(m.id)}</span></td>
  <td><span class="rule-title">{_e(m.title)}</span></td>
  <td>{assess_badge}</td>
  <td style="max-width:340px;color:var(--muted)">{message}</td>
  <td><span class="expand-icon">▾</span></td>
</tr>
<tr class="detail-row">
  <td colspan="7">{_detail_panel(finding)}</td>
</tr>"""

        html_parts.append(f"""
<div class="table-wrap" data-section="{_e(section_name)}" style="border-left:4px solid {accent}">
  <table>
    <tbody>
      <tr class="section-hdr">
        <td colspan="7">
          <div class="section-hdr-inner">
            <span class="toggle-icon">▾</span>
            <span class="section-hdr-num">{_e(section_num)}</span>
            <span class="section-hdr-title">{_e(section_title)}</span>
            <span class="section-stats">{stats_html}</span>
            <span class="section-stat" style="color:var(--muted);font-size:11px">{n} control{'s' if n != 1 else ''}</span>
            <span class="section-filter-count" style="font-size:11px;color:var(--muted)"></span>
          </div>
        </td>
      </tr>
    </tbody>
    <thead>
      <tr>
        <th>Status</th>
        <th>Severity</th>
        <th>Rule ID</th>
        <th>Title</th>
        <th>Type</th>
        <th>Message</th>
        <th></th>
      </tr>
    </thead>
    <tbody class="section-findings">
      {rows}
    </tbody>
  </table>
</div>""")

    return "\n".join(html_parts)


def _filter_bar() -> str:
    statuses = [
        ("fail",    "Failed",  "#dc2626"),
        ("manual",  "Manual",  "#d97706"),
        ("pass",    "Passed",  "#16a34a"),
        ("skipped", "Skipped", "#94a3b8"),
        ("error",   "Errors",  "#9333ea"),
    ]
    btns = "".join(
        f'<button class="filter-btn" data-status="{s}">{label}</button>'
        for s, label, _ in statuses
    )
    return f"""
<div class="filters">
  <input type="search" id="search-input" placeholder="Search rules, IDs, messages…">
  <button class="filter-btn active" data-status="">All</button>
  {btns}
  <div class="filter-sep"></div>
  <button class="collapse-btn" id="btn-expand-all">Expand all</button>
  <button class="collapse-btn" id="btn-collapse-all">Collapse all</button>
</div>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_html(result: ScanResult) -> str:
    """Convert a ``ScanResult`` to a self-contained HTML string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = result.summary()

    header = f"""
<div class="header">
  <div class="header-inner">
    <h1>AccuKnox SSPM — Security Posture Report</h1>
    <div class="header-sub">{_e(result.benchmark)}</div>
    <div class="header-meta">
      <span><strong>Target:</strong> {_e(result.target)}</span>
      <span><strong>Scan ID:</strong> {_e(result.scan_id)}</span>
      <span><strong>Started:</strong> {_e(result.started_at)}</span>
      <span><strong>Completed:</strong> {_e(result.completed_at)}</span>
      <span><strong>Generated:</strong> {_e(now)}</span>
    </div>
  </div>
</div>"""

    body = (
        _score_cards(result)
        + _severity_bar(result.findings)
        + _filter_bar()
        + _findings_table_grouped(result.findings)
        + '\n<div id="no-results-global" class="no-results-global">No findings match the current filter.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AccuKnox SSPM Report – {_e(result.target)}</title>
  <style>{_CSS}</style>
</head>
<body>
  {header}
  <div class="main">{body}</div>
  <footer class="footer">
    AccuKnox SSPM &nbsp;·&nbsp; {_e(result.benchmark)} &nbsp;·&nbsp;
    {summary['total']} controls evaluated &nbsp;·&nbsp; {_e(now)}
  </footer>
  <script>{_JS}</script>
</body>
</html>"""


def write_html(result: ScanResult, path: str) -> None:
    """Write the HTML report to *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_html(result))

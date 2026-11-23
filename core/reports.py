"""Report data and rendering. A report is built on demand from stored findings; nothing is written to disk.

The same ``build_report`` result feeds the HTML view, the JSON download and the PDF. Evidence in findings has already
been redacted at capture time (secret values masked, sensitive headers never stored); the report only trims it.
"""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from core.compare import compare_scans, comparable_problem
from core.constants import utcnow
from core.risk import SEV_ORDER, assess, location

TOOL_LIMITS = (
    "SYSX sends only GET and HEAD requests. It does not submit forms, so state-changing endpoints and POST-only "
    "functionality are reviewed passively or not at all.",
    "A finding marked Potential or Unverified has not been confirmed by an active check; static source-code findings are "
    "patterns and are never confirmed.",
    "XXE and other body-based injection classes are not tested.",
    "Absence of a finding is not proof of absence of a vulnerability: coverage depends on what the crawler reached, the "
    "enabled modules, the scan intensity and the credentials supplied.",
)
MAX_EVIDENCE_ITEMS = 2


def _trim(items: list, include_evidence: bool) -> list:
    if not include_evidence:
        return []
    out = []
    for item in (items or [])[:MAX_EVIDENCE_ITEMS]:
        resp = item.get("response") or {}
        out.append(dict(label=item.get("label", ""), method=(item.get("request") or {}).get("method"),
                        url=(item.get("request") or {}).get("url"), status=resp.get("status"),
                        snippet=(resp.get("snippet") or item.get("code") or "")[:400], note=item.get("note", "")))
    return out


def build_report(storage, target, include_closed: bool = False, include_evidence: bool = True) -> dict:
    findings = storage.list_findings(target_id=target.id)
    risk = assess(findings)
    shown = [f for f in findings if include_closed or f.status not in ("False Positive", "Fixed")]
    shown.sort(key=lambda f: (SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9, -(f.confidence or 0), f.id))
    scans = [s for s in storage.list_scans(200, target.id) if s.status == "completed"]
    previous = None
    for kind in ("discovery", "source"):
        pair = [s for s in scans if (getattr(s, "kind", None) or "discovery") == kind and "fingerprints" in (s.summary or {})][:2]
        if len(pair) == 2 and comparable_problem(pair[1], pair[0]) is None:
            diff = compare_scans(storage, pair[1], pair[0])
            previous = (previous or []) + [dict(kind=kind, older=pair[1].id, newer=pair[0].id, new=len(diff["new"]),
                                                  not_seen=len(diff["not_seen"]), persistent=len(diff["persistent"]))]
    top = risk["ranked"][:5]
    return dict(
        generated_at=utcnow().isoformat(timespec="seconds") + "Z",
        target=dict(id=target.id, name=target.name, base_url=target.base_url, authorization_type=target.authorization_type,
                    attested_by=target.attested_by, attested_at=target.attested_at.isoformat() + "Z" if target.attested_at else None,
                    scan_intensity=target.scan_intensity, allowed_domains=list(target.allowed_domains or []),
                    excluded_paths=list(target.excluded_paths or [])),
        scans=[dict(id=s.id, kind=getattr(s, "kind", None) or "discovery", finished_at=s.finished_at.isoformat() + "Z" if s.finished_at else None,
                    findings=(s.summary or {}).get("findings")) for s in scans[:10]],
        risk=dict(score=risk["score"], rating=risk["rating"], counts=risk["counts"], open=risk["open"], closed=risk["closed"],
                  verified=risk["verified"], unverified=risk["unverified"], hotspots=risk["hotspots"][:5], top=top),
        changes=previous or [], limitations=list(TOOL_LIMITS), include_closed=include_closed, include_evidence=include_evidence,
        findings=[dict(id=f.id, title=f.title, severity=f.severity, status=f.status, confidence=f.confidence,
                       cvss_score=f.cvss_score, cvss_vector=f.cvss_vector, vuln_type=f.vuln_type, technique=f.technique,
                       origin=getattr(f, "origin", None) or "dynamic", where=location(f), parameter=f.parameter,
                       description=f.description, impact=f.impact, remediation=f.remediation,
                       evidence=_trim(f.evidence, include_evidence)) for f in shown])


def executive_summary(report: dict) -> list[str]:
    r = report["risk"]
    c = r["counts"]
    lines = [f"Overall risk rating: {r['rating']} ({r['score']}/100). {r['open']} open finding(s): "
             + ", ".join(f"{c[s]} {s}" for s in SEV_ORDER if c[s]) + "." if r["open"] else "No open findings were recorded for this target."]
    if r["open"]:
        lines.append(f"{r['verified']} finding(s) were verified by an active check; {r['unverified']} are potential or unverified "
                     "and need manual review before they are treated as vulnerabilities.")
    if r["top"]:
        lines.append("Highest-priority items: " + "; ".join(f"{t['title']} ({t['where']})" for t in r["top"][:3]) + ".")
    for ch in report["changes"]:
        lines.append(f"Since the previous {ch['kind']} scan: {ch['new']} new, {ch['persistent']} still present, "
                     f"{ch['not_seen']} not seen again (not proof they are fixed).")
    return lines


def render_pdf(report: dict) -> bytes:
    """Raises ImportError when reportlab is not installed."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#444444"))
    code = ParagraphStyle("code", parent=small, fontName="Courier", fontSize=7.5, leading=9.5, backColor=colors.HexColor("#F2F2F2"))
    h1, h2, h3 = styles["Title"], styles["Heading2"], styles["Heading3"]
    sev_color = {"critical": "#A80000", "high": "#C2410C", "medium": "#B7791F", "low": "#2F6F4F", "informational": "#555555"}

    def p(text, style=body):
        clean = "".join(ch for ch in str(text if text is not None else "") if ch in "\n\t" or ord(ch) >= 32)
        return Paragraph(escape(clean).replace("\n", "<br/>"), style)

    t = report["target"]
    story = [p("SYSX Security Assessment Report", h1), p(f"{t['name']} · {t['base_url']}", body),
             p(f"Generated {report['generated_at']} · Authorization: {t['authorization_type']}"
               + (f" · attested by {t['attested_by']}" if t.get("attested_by") else ""), small), Spacer(1, 6 * mm),
             p("Executive summary", h2)]
    for line in executive_summary(report):
        story += [p(line), Spacer(1, 2 * mm)]
    c = report["risk"]["counts"]
    table = Table([["Critical", "High", "Medium", "Low", "Info"], [c["critical"], c["high"], c["medium"], c["low"], c["informational"]]],
                  colWidths=[30 * mm] * 5)
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEE8")),
                               ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
    story += [table, Spacer(1, 6 * mm), p("Scope and limitations", h2)]
    story += [p("• " + text, small) for text in report["limitations"]]
    story += [Spacer(1, 6 * mm), p(f"Findings ({len(report['findings'])})", h2)]
    for f in report["findings"]:
        color = sev_color.get(f["severity"], "#555555")
        head = Paragraph(f'<font color="{color}"><b>{escape(f["severity"].upper())}</b></font> · {escape(f["title"])}', h3)
        meta = f"{f['status']} · confidence {round((f['confidence'] or 0) * 100)}%" + (f" · CVSS {f['cvss_score']}" if f["cvss_score"] is not None else "")
        block = [head, p(meta, small), p(f"Where: {f['where']}" + (f" (parameter {f['parameter']})" if f["parameter"] else ""), small)]
        for label, key in (("Description", "description"), ("Impact", "impact"), ("Remediation", "remediation")):
            if f.get(key):
                block.append(p(f"{label}: {f[key]}", body))
        for ev in f["evidence"]:
            block.append(p(f"Evidence: {ev['label']} {ev['method'] or ''} {ev['url'] or ''} {('-> ' + str(ev['status'])) if ev['status'] else ''}", small))
            if ev["snippet"]:
                block.append(p(ev["snippet"], code))
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block[:4]))
        story += block[4:]
    if not report["findings"]:
        story.append(p("No findings to report.", body))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"SYSX report: {t['name']}", author="SYSX")
    doc.build(story)
    return buf.getvalue()

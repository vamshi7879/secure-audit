from __future__ import annotations

import os
import re
import struct
from datetime import datetime
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from scanner.analyzer import CHECKS
from scanner.assessment import RISK_METHOD, checklist_results

NAVY = colors.HexColor("#102A43")
TEAL = colors.HexColor("#0F8999")
INK = colors.HexColor("#243746")
MUTED = colors.HexColor("#596B7A")
RULE = colors.HexColor("#D8E0E7")
PALE = colors.HexColor("#F3F6F8")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#B42318"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#A15C00"),
    "low": colors.HexColor("#176B87"),
    "info": colors.HexColor("#526579"),
}
SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Info")
FONT_REGULAR = "AuditTimes"
FONT_BOLD = "AuditTimes-Bold"
FONT_ITALIC = "AuditTimes-Italic"
FONT_BOLD_ITALIC = "AuditTimes-BoldItalic"
FONT_MONO = "Courier"


def _font_can_be_subset_embedded(path: Path) -> bool:
    try:
        data = path.read_bytes()
        if len(data) < 12:
            return False
        table_count = struct.unpack_from(">H", data, 4)[0]
        os2_offset = None
        for index in range(table_count):
            record_offset = 12 + index * 16
            if record_offset + 16 > len(data):
                return False
            if data[record_offset:record_offset + 4] == b"OS/2":
                os2_offset = struct.unpack_from(">I", data, record_offset + 8)[0]
                break
        if os2_offset is None or os2_offset + 10 > len(data):
            return False
        embedding_flags = struct.unpack_from(">H", data, os2_offset + 8)[0]
    except (OSError, struct.error):
        return False

    restricted_or_unsupported = 0x0002 | 0x0100 | 0x0200
    return not (embedding_flags & restricted_or_unsupported)


def _times_font_paths() -> dict[str, Path] | None:
    candidates: list[dict[str, Path]] = []
    windows_dir = os.environ.get("WINDIR")
    if windows_dir:
        fonts = Path(windows_dir) / "Fonts"
        candidates.append({
            "regular": fonts / "times.ttf",
            "bold": fonts / "timesbd.ttf",
            "italic": fonts / "timesi.ttf",
            "bold_italic": fonts / "timesbi.ttf",
        })

    candidates.extend([
        {
            "regular": Path("/Library/Fonts/Times New Roman.ttf"),
            "bold": Path("/Library/Fonts/Times New Roman Bold.ttf"),
            "italic": Path("/Library/Fonts/Times New Roman Italic.ttf"),
            "bold_italic": Path("/Library/Fonts/Times New Roman Bold Italic.ttf"),
        },
        {
            "regular": Path("/System/Library/Fonts/Supplemental/Times New Roman.ttf"),
            "bold": Path("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf"),
            "italic": Path("/System/Library/Fonts/Supplemental/Times New Roman Italic.ttf"),
            "bold_italic": Path("/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf"),
        },
        {
            "regular": Path("/usr/share/fonts/truetype/msttcorefonts/times.ttf"),
            "bold": Path("/usr/share/fonts/truetype/msttcorefonts/timesbd.ttf"),
            "italic": Path("/usr/share/fonts/truetype/msttcorefonts/timesi.ttf"),
            "bold_italic": Path("/usr/share/fonts/truetype/msttcorefonts/timesbi.ttf"),
        },
    ])

    for paths in candidates:
        if all(path.is_file() for path in paths.values()) and all(
            _font_can_be_subset_embedded(path) for path in paths.values()
        ):
            return paths
    return None


def _register_report_fonts() -> tuple[str, str, str, str, str]:
    paths = _times_font_paths()
    if paths is None:
        return "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic", FONT_MONO

    registered = {
        FONT_REGULAR: TTFont(FONT_REGULAR, str(paths["regular"])),
        FONT_BOLD: TTFont(FONT_BOLD, str(paths["bold"])),
        FONT_ITALIC: TTFont(FONT_ITALIC, str(paths["italic"])),
        FONT_BOLD_ITALIC: TTFont(FONT_BOLD_ITALIC, str(paths["bold_italic"])),
    }
    for font in registered.values():
        pdfmetrics.registerFont(font)
    pdfmetrics.registerFontFamily(
        FONT_REGULAR,
        normal=FONT_REGULAR,
        bold=FONT_BOLD,
        italic=FONT_ITALIC,
        boldItalic=FONT_BOLD_ITALIC,
    )
    return FONT_REGULAR, FONT_BOLD, FONT_ITALIC, FONT_BOLD_ITALIC, FONT_MONO


def _text(value: object) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, (str, int, float)):
        return str(value)
    return "Not available"


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    text = escape(_text(value)).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")
    return Paragraph(text, style)


def _paragraph_styles(fonts: tuple[str, str, str, str, str]) -> dict[str, ParagraphStyle]:
    regular, bold, italic, bold_italic, mono = fonts
    sample = getSampleStyleSheet()
    return {
        "cover_brand": ParagraphStyle(
            "CoverBrand", parent=sample["Normal"], fontName=bold, fontSize=18,
            leading=22, textColor=NAVY, alignment=TA_CENTER, spaceAfter=14,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=sample["Title"], fontName=bold, fontSize=26,
            leading=31, textColor=NAVY, alignment=TA_CENTER, spaceAfter=12,
            wordWrap="CJK",
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=sample["Normal"], fontName=bold, fontSize=13,
            leading=18, textColor=TEAL, alignment=TA_CENTER, spaceAfter=8,
            wordWrap="CJK",
        ),
        "cover_note": ParagraphStyle(
            "CoverNote", parent=sample["Normal"], fontName=regular, fontSize=12,
            leading=17, textColor=MUTED, alignment=TA_CENTER, wordWrap="CJK",
        ),
        "section": ParagraphStyle(
            "AuditSection", parent=sample["Heading2"], fontName=bold, fontSize=17,
            leading=21, textColor=NAVY, spaceBefore=8, spaceAfter=10,
            keepWithNext=True, wordWrap="CJK",
        ),
        "subsection": ParagraphStyle(
            "AuditSubsection", parent=sample["Heading3"], fontName=bold, fontSize=13,
            leading=16, textColor=NAVY, spaceBefore=8, spaceAfter=5,
            keepWithNext=True, wordWrap="CJK",
        ),
        "body": ParagraphStyle(
            "AuditBody", parent=sample["BodyText"], fontName=regular, fontSize=12,
            leading=16, textColor=INK, spaceAfter=7, alignment=TA_LEFT,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "AuditSmall", parent=sample["BodyText"], fontName=regular, fontSize=10,
            leading=13, textColor=MUTED, spaceAfter=4, wordWrap="CJK",
        ),
        "table": ParagraphStyle(
            "AuditTable", parent=sample["BodyText"], fontName=regular, fontSize=10,
            leading=12, textColor=INK, spaceAfter=0, wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "AuditTableHeader", parent=sample["BodyText"], fontName=bold,
            fontSize=10, leading=12, textColor=colors.white, spaceAfter=0,
            wordWrap="CJK",
        ),
        "finding_title": ParagraphStyle(
            "AuditFindingTitle", parent=sample["Heading3"], fontName=bold,
            fontSize=14, leading=17, textColor=NAVY, spaceBefore=9, spaceAfter=5,
            keepWithNext=True, wordWrap="CJK",
        ),
        "label": ParagraphStyle(
            "AuditLabel", parent=sample["BodyText"], fontName=bold, fontSize=12,
            leading=15, textColor=NAVY, spaceBefore=4, spaceAfter=3,
            keepWithNext=True, wordWrap="CJK",
        ),
        "code": ParagraphStyle(
            "AuditCode", parent=sample["Code"], fontName=mono, fontSize=9,
            leading=12, textColor=INK, backColor=PALE, borderColor=RULE,
            borderWidth=0.5, borderPadding=7, leftIndent=5, rightIndent=5,
            spaceBefore=3, spaceAfter=8, wordWrap="CJK",
        ),
        "risk": ParagraphStyle(
            "AuditRisk", parent=sample["Normal"], fontName=bold, fontSize=13,
            leading=16, textColor=TEAL, spaceAfter=6, wordWrap="CJK",
        ),
        "card_label": ParagraphStyle(
            "AuditCardLabel", parent=sample["Normal"], fontName=regular,
            fontSize=10, leading=12, textColor=MUTED, alignment=TA_CENTER,
            wordWrap="CJK",
        ),
        "card_value": ParagraphStyle(
            "AuditCardValue", parent=sample["Normal"], fontName=bold,
            fontSize=18, leading=21, textColor=NAVY, alignment=TA_CENTER,
            wordWrap="CJK",
        ),
        "italic": ParagraphStyle(
            "AuditItalic", parent=sample["BodyText"], fontName=italic,
            fontSize=12, leading=16, textColor=INK, spaceAfter=7, wordWrap="CJK",
        ),
        "bold_italic": ParagraphStyle(
            "AuditBoldItalic", parent=sample["BodyText"], fontName=bold_italic,
            fontSize=12, leading=16, textColor=INK, spaceAfter=7, wordWrap="CJK",
        ),
    }


def _risk_level(counts: dict[str, int]) -> str:
    if counts["Critical"]:
        return "Critical"
    if counts["High"]:
        return "High"
    if counts["Medium"]:
        return "Medium"
    return "Low"


def _scan_checks() -> str:
    names = [
        "dependency-use review heuristic (not an advisory lookup)"
        if check.__name__ == "check_dependencies"
        else check.__name__.removeprefix("check_").replace("_", " ").title()
        for check in CHECKS
    ]
    return ", ".join(names) if names else "Not available"


def _footer(canvas, document, generated_at: str) -> None:
    canvas.saveState()
    page_width, _ = document.pagesize
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.5)
    canvas.line(document.leftMargin, 0.55 * inch, page_width - document.rightMargin, 0.55 * inch)
    canvas.setFillColor(MUTED)
    canvas.setFont(document._audit_regular_font, 9)
    canvas.drawString(document.leftMargin, 0.36 * inch, "SecureCodeAudit | Static Analysis Report")
    canvas.drawRightString(page_width - document.rightMargin, 0.36 * inch, f"{generated_at}  |  Page {canvas.getPageNumber() - 1}")
    canvas.restoreState()


def _summary_cards(counts: dict[str, int], total: int, styles: dict[str, ParagraphStyle]) -> Table:
    metrics = [("Total findings", total)] + [(level, counts[level]) for level in SEVERITY_LEVELS]
    cells = []
    for label, value in metrics:
        cells.append([
            _paragraph(label, styles["card_label"]),
            _paragraph(value, styles["card_value"]),
        ])
    rows = [cells[:3], cells[3:]]
    table = Table(rows, colWidths=[(A4[0] - 1.5 * inch) / 3] * 3)
    commands = [
        ("FONTNAME", (0, 0), (-1, -1), styles["table"].fontName),
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    table.setStyle(TableStyle(commands))
    return table


def _finding_table(findings: list[dict], analyzed_filename: str, styles: dict[str, ParagraphStyle]) -> Table:
    header = ["ID", "Severity", "Vulnerability", "CWE", "File", "Line", "Status"]
    rows = [[_paragraph(item, styles["table_header"]) for item in header]]
    for index, finding in enumerate(findings, start=1):
        severity = _text(finding.get("severity"))
        severity_style = ParagraphStyle(
            f"Severity{index}", parent=styles["table"],
            textColor=SEVERITY_COLORS.get(severity.lower(), MUTED),
        )
        cwe = finding.get("cwe")
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else "Unavailable"
        review = finding.get("review") if isinstance(finding.get("review"), dict) else {}
        rows.append([
            _paragraph(finding.get("finding_id") or f"F-{index:04d}", styles["table"]),
            _paragraph(severity, severity_style),
            _paragraph(finding.get("title") or finding.get("category"), styles["table"]),
            _paragraph(cwe_id, styles["table"]),
            _paragraph(finding.get("file") or analyzed_filename, styles["table"]),
            _paragraph(finding.get("line"), styles["table"]),
            _paragraph(review.get("status") or finding.get("status") or "Open", styles["table"]),
        ])
    widths = [35, 50, 115, 45, 90, 32, 59]
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["table"].fontName),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _dependency_table(results: list[dict], styles: dict[str, ParagraphStyle]) -> Table:
    header = ("Package", "Version", "Advisory", "Status", "Details", "Fixed version", "Recommendation")
    rows = [[_paragraph(value, styles["table_header"]) for value in header]]
    for result in results:
        rows.append([
            _paragraph(result.get("package"), styles["table"]),
            _paragraph(result.get("version"), styles["table"]),
            _paragraph(result.get("vulnerability_id"), styles["table"]),
            _paragraph(result.get("status"), styles["table"]),
            _paragraph(result.get("details"), styles["table"]),
            _paragraph(result.get("fixed_version"), styles["table"]),
            _paragraph(result.get("recommendation"), styles["table"]),
        ])
    table = Table(rows, colWidths=[52, 48, 65, 62, 105, 55, 100], repeatRows=1, hAlign="LEFT", splitByRow=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["table"].fontName),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _add_finding(story: list, index: int, finding: dict, analyzed_filename: str, styles: dict[str, ParagraphStyle]) -> None:
    identifier = finding.get("finding_id") or f"F-{index:04d}"
    title = finding.get("title") or finding.get("category") or "Finding"
    severity = _text(finding.get("severity"))
    severity_color = SEVERITY_COLORS.get(severity.lower(), MUTED)
    title_paragraph = _paragraph(f"{identifier} | {title}", styles["finding_title"])

    meta = [
        [_paragraph("Severity", styles["small"]), _paragraph(severity, styles["small"]),
         _paragraph("Priority", styles["small"]), _paragraph(finding.get("priority"), styles["small"])],
        [_paragraph("Affected file", styles["small"]), _paragraph(finding.get("file") or analyzed_filename, styles["small"]),
         _paragraph("Line", styles["small"]), _paragraph(finding.get("line"), styles["small"])],
    ]
    meta_table = Table(meta, colWidths=[0.9 * inch, 2.3 * inch, 0.8 * inch, 2.4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["table"].fontName),
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("TEXTCOLOR", (1, 0), (1, 0), severity_color),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BOX", (0, 0), (-1, -1), 0.4, RULE),
    ]))
    story.append(KeepTogether([title_paragraph, meta_table, Spacer(1, 7)]))
    review = finding.get("review") if isinstance(finding.get("review"), dict) else {}
    story.append(_paragraph(
        f"Remediation tracking status: {review.get('status') or finding.get('status') or 'Open'}",
        styles["small"],
    ))
    if review.get("notes"):
        story.extend([
            _paragraph("Review / remediation notes", styles["label"]),
            _paragraph(review["notes"], styles["body"]),
        ])

    fields = (
        ("Description", "description"),
        ("Potential impact", "impact"),
        ("Recommended remediation", "recommendation"),
    )
    for label, key in fields:
        value = finding.get(key)
        if value is not None and value != "":
            story.extend([_paragraph(label, styles["label"]), _paragraph(value, styles["body"])])

    cwe = finding.get("cwe")
    if isinstance(cwe, dict):
        cwe_id = str(cwe.get("id", ""))
        cwe_title = str(cwe.get("title", ""))
        match = re.fullmatch(r"CWE-(\d+)", cwe_id)
        cwe_content = escape(f"{cwe_id} — {cwe_title} ({cwe.get('confidence', 'review required')})")
        if match:
            cwe_content = f'<link href="https://cwe.mitre.org/data/definitions/{match.group(1)}.html" color="#087D91">{cwe_content}</link>'
        story.extend([
            _paragraph("CWE Reference", styles["label"]),
            Paragraph(cwe_content, styles["body"]),
        ])
    else:
        story.extend([
            _paragraph("CWE Reference", styles["label"]),
            _paragraph("Mapping unavailable; no reliable rule-level mapping is defined.", styles["small"]),
        ])
    owasp = finding.get("owasp")
    if isinstance(owasp, dict):
        url = str(owasp.get("url", ""))
        label = escape(f"{owasp.get('id', '')} — {owasp.get('title', '')} ({owasp.get('confidence', 'review required')})")
        link = f'<link href="{escape(url)}" color="#087D91">{label}</link>' if url.startswith("https://owasp.org/") else label
        story.extend([_paragraph("OWASP Reference", styles["label"]), Paragraph(link, styles["body"])])
    else:
        story.extend([
            _paragraph("OWASP Reference", styles["label"]),
            _paragraph("Mapping unavailable; no reliable rule-level mapping is defined.", styles["small"]),
        ])

    principles = finding.get("principles")
    if isinstance(principles, list) and principles:
        story.extend([
            _paragraph("Security Principles Affected", styles["label"]),
            _paragraph(", ".join(str(item) for item in principles), styles["body"]),
        ])

    evidence = finding.get("evidence") or finding.get("source_snippet")
    story.append(_paragraph("Evidence / source snippet", styles["label"]))
    if evidence:
        story.append(_paragraph(evidence, styles["code"]))
    else:
        story.append(_paragraph("Not available from the scanner result.", styles["small"]))
    secure_example = finding.get("secure_example")
    if secure_example:
        story.extend([
            _paragraph("Scanner-provided remediation example", styles["label"]),
            _paragraph(secure_example, styles["code"]),
        ])
    story.append(Spacer(1, 8))


def generate_report_pdf(result: dict) -> BytesIO:
    findings = result["findings"]
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("Scan results must contain a list of finding objects.")

    counts = {level: sum(1 for finding in findings if finding.get("severity") == level) for level in SEVERITY_LEVELS}
    total = len(findings)
    risk = result.get("risk_level")
    if risk not in ("Critical", "High", "Medium", "Low"):
        risk = _risk_level(counts)
    analyzed_filename = _text(result.get("analyzed_filename"))
    scanned_at = _text(result.get("scanned_at"))
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    fonts = _register_report_fonts()
    styles = _paragraph_styles(fonts)
    regular_font = fonts[0]
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.82 * inch,
        title="SecureCodeAudit Python Application Security Assessment Report",
        subject="Static Application Security Testing (SAST) assessment",
    )
    document._audit_regular_font = regular_font
    story = [
        Spacer(1, 1.12 * inch),
        _paragraph("SecureCodeAudit", styles["cover_brand"]),
        Table([[""]], colWidths=[4.5 * inch], rowHeights=[3], style=TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), regular_font),
            ("BACKGROUND", (0, 0), (-1, -1), TEAL),
        ]), hAlign="CENTER"),
        Spacer(1, 0.38 * inch),
        _paragraph("PYTHON APPLICATION SECURITY\nASSESSMENT REPORT", styles["cover_title"]),
        _paragraph("Static Application Security Testing (SAST)", styles["cover_subtitle"]),
        Spacer(1, 0.4 * inch),
    ]
    cover_metadata = [
        [_paragraph("Report ID", styles["table"]), _paragraph(result.get("scan_id"), styles["table"])],
        [_paragraph("Application", styles["table"]), _paragraph("SecureCodeAudit", styles["table"])],
        [_paragraph("Analyzed filename", styles["table"]), _paragraph(analyzed_filename, styles["table"])],
        [_paragraph("Finding filter", styles["table"]), _paragraph(result.get("severity_filter") or "All severities", styles["table"])],
        [_paragraph("Scan date and time", styles["table"]), _paragraph(scanned_at, styles["table"])],
        [_paragraph("Overall risk level", styles["table"]), _paragraph(risk, styles["table"])],
        [_paragraph("Report generated", styles["table"]), _paragraph(generated_at, styles["table"])],
        [_paragraph("PDF typeface", styles["table"]), _paragraph(
            "Times New Roman (embedded)" if regular_font == FONT_REGULAR
            else "Times-Roman built-in serif fallback (Times New Roman font unavailable or cannot be embedded)",
            styles["table"],
        )],
    ]
    cover_table = Table(cover_metadata, colWidths=[1.65 * inch, 4.3 * inch], hAlign="CENTER")
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), regular_font),
        ("BACKGROUND", (0, 0), (0, -1), PALE),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([
        cover_table,
        Spacer(1, 0.5 * inch),
        _paragraph("Generated from the scan results provided by SecureCodeAudit.", styles["cover_note"]),
        PageBreak(),
        _paragraph("Executive Summary", styles["section"]),
        _summary_cards(counts, total, styles),
        Spacer(1, 12),
        _paragraph(f"Overall risk level (full scan): {risk}", styles["risk"]),
    ])
    if result.get("severity_filter") and result.get("severity_filter") != "All severities":
        story.append(_paragraph(
            f"Finding filter applied: {result['severity_filter']}. Severity totals below reflect findings included in this report; overall risk reflects the complete scan.",
            styles["small"],
        ))

    summary = result.get("summary")
    if summary:
        story.append(_paragraph(summary, styles["body"]))
    if findings:
        top_findings = sorted(
            enumerate(findings, start=1),
            key=lambda item: (
                {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}.get(item[1].get("severity"), 6),
                item[1].get("priority", 999) if isinstance(item[1].get("priority"), (int, float)) else 999,
            ),
        )[:3]
        concerns = "; ".join(
            f"{_text(finding.get('title') or finding.get('category'))} ({_text(finding.get('severity'))})"
            for _, finding in top_findings
        )
        story.append(_paragraph(f"Highest-priority concerns identified: {concerns}.", styles["body"]))
    else:
        story.append(_paragraph(
            "No configured vulnerability patterns were reported by this scan. This result does not replace manual review.",
            styles["body"],
        ))

    story.extend([
        _paragraph("Assessment Scope and Methodology", styles["section"]),
        _paragraph(f"Analyzed filename: {analyzed_filename}", styles["body"]),
        _paragraph(f"Scan date and time: {scanned_at}", styles["body"]),
        _paragraph(
            "Analyzed Python files: " + ", ".join(str(item) for item in result.get("files_analyzed", []))
            if result.get("files_analyzed") else "Analyzed Python files: Not available",
            styles["body"],
        ),
        _paragraph("Assessment type: Static Application Security Testing (SAST).", styles["body"]),
        _paragraph("The application parses submitted Python source as text using AST-based configured checks. Submitted source code is not executed.", styles["body"]),
        _paragraph(f"Configured scanner rule checks: {_scan_checks()}.", styles["body"]),
        _paragraph("Static analysis identifies potential security weaknesses in source code. Findings may require manual review and do not establish that an application is exploitable.", styles["italic"]),
        _paragraph("This educational prototype performs pattern-based checks and does not provide complete data-flow analysis, runtime testing, or proof of exploitability. A dependency advisory lookup is included only when its results are attached to this scan.", styles["body"]),
        _paragraph("Risk methodology", styles["subsection"]),
        _paragraph(result.get("risk_method") or RISK_METHOD, styles["body"]),
        CondPageBreak(1.5 * inch),
        _paragraph("Vulnerability Summary", styles["section"]),
        _paragraph(f"{total} finding(s) included in this report. Table status is reported only when the scanner provides it.", styles["small"]),
        _finding_table(findings, analyzed_filename, styles),
        _paragraph("Detailed Findings", styles["section"]),
    ])
    if not findings:
        story.append(_paragraph("No findings were returned. No vulnerability details or remediation actions are applicable to this scan.", styles["body"]))
    for index, finding in enumerate(findings, start=1):
        _add_finding(story, index, finding, analyzed_filename, styles)

    not_detected = result.get("not_detected_findings", [])
    if not_detected:
        story.append(_paragraph("Findings Not Detected in the Latest Scan", styles["section"]))
        story.append(_paragraph("These earlier findings were not reported by this scan. They have not been marked resolved.", styles["body"]))
        for finding in not_detected:
            review = finding.get("review") if isinstance(finding.get("review"), dict) else {}
            story.append(_paragraph(
                f"{finding.get('finding_id') or 'Finding'} — {finding.get('title') or finding.get('category')} "
                f"({finding.get('severity') or 'Severity unavailable'}), "
                f"{finding.get('file') or 'File unavailable'}:{finding.get('line') or 'Line unavailable'} — "
                f"{review.get('status') or finding.get('status') or 'Open'}",
                styles["body"],
            ))

    story.extend([
        CondPageBreak(1.5 * inch),
        _paragraph("Security Checklist", styles["section"]),
        _paragraph("Pass is reserved for a defined control with positive evidence. A rule not matching is Not Assessed, not Pass.", styles["body"]),
    ])
    checklist = result.get("checklist") or checklist_results(findings, bool(result.get("syntax_error")))
    checklist_rows = [[
        _paragraph(value, styles["table_header"])
        for value in ("Check", "Status", "Evidence", "Recommendation")
    ]]
    for item in checklist:
        checklist_rows.append([
            _paragraph(f"{item.get('rule_id', '')} — {item.get('category', '')}", styles["table"]),
            _paragraph(item.get("status", "Not Assessed"), styles["table"]),
            _paragraph(item.get("evidence", "Not available"), styles["table"]),
            _paragraph(item.get("recommendation", "Not available"), styles["table"]),
        ])
    checklist_table = Table(
        checklist_rows,
        colWidths=[95, 60, 170, 123],
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    checklist_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["table"].fontName),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(checklist_table)
    dependencies = result.get("dependency_results") or {"status": "Not assessed", "results": []}
    story.extend([
        _paragraph("Dependency Audit", styles["section"]),
        _paragraph(f"Status: {dependencies.get('status', 'Not assessed')}", styles["body"]),
        _paragraph("Dependency audit results are separate from source-code rule findings.", styles["small"]),
    ])
    dependency_results = dependencies.get("results", []) if isinstance(dependencies, dict) else []
    if dependency_results:
        story.append(_dependency_table(dependency_results, styles))
        story.append(_paragraph(
            "An OSV response with no advisory is limited to the queried version and does not establish that a package or application is safe.",
            styles["small"],
        ))

    story.append(_paragraph("Remediation Recommendations", styles["section"]))
    if findings:
        severity_order = ("Critical", "High", "Medium", "Low", "Info")
        for severity in severity_order:
            matching = [(index, finding) for index, finding in enumerate(findings, start=1) if finding.get("severity") == severity]
            if not matching:
                continue
            story.append(_paragraph(severity, styles["subsection"]))
            for index, finding in matching:
                title = finding.get("title") or finding.get("category") or "Finding"
                recommendation = finding.get("recommendation")
                if recommendation:
                    identifier = finding.get("finding_id") or f"F-{index:04d}"
                    story.append(_paragraph(f"{identifier} — {title}: {recommendation}", styles["body"]))
    else:
        story.append(_paragraph("No finding-specific recommendations were returned. Continue manual review and maintain secure development practices.", styles["body"]))

    story.extend([
        _paragraph("Conclusion", styles["section"]),
        _paragraph(
            f"The scan indicates a {risk.lower()} risk posture based on the findings returned by the configured static checks "
            f"({total} included; {counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, "
            f"{counts['Low']} low, and {counts['Info']} informational).",
            styles["body"],
        ),
    ])
    if findings:
        key_recommendations = [
            finding.get("recommendation")
            for finding in findings
            if finding.get("severity") in ("Critical", "High") and finding.get("recommendation")
        ]
        if key_recommendations:
            story.append(_paragraph(f"Prioritize remediation of critical and high findings, including: {key_recommendations[0]}", styles["body"]))
    else:
        story.append(_paragraph("No configured patterns were detected; manual review remains necessary.", styles["body"]))
    story.append(_paragraph(
        "Static analysis has inherent limitations. Manually validate findings in application context and perform additional review or testing where appropriate.",
        styles["body"],
    ))

    document.build(
        story,
        onFirstPage=lambda canvas, doc: None,
        onLaterPages=lambda canvas, doc: _footer(canvas, doc, generated_at),
    )
    buffer.seek(0)
    return buffer

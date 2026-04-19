"""
PDF Formatter - Generates a professional PDF audit report using fpdf2.
The PDF is formatted as a compliance document suitable for auditors and executives.
It includes a header with compliance status, summary statistics, and detailed
findings with AI-generated attack scenarios and remediation steps.
"""

# Standard library imports
import logging                      # For recording formatter activity
import os                           # For building file paths and creating directories
from typing import Any              # Type hint: Any means a variable can hold any data type

# Create a logger for this module
logger = logging.getLogger(__name__)

# Read the report output directory from environment variable
REPORT_DIR = os.getenv("REPORT_OUTPUT_DIR", "./reports")


def _safe(text: str) -> str:
    """
    Sanitize a string for fpdf2's built-in Arial font (Latin-1 only).
    Replaces common Unicode punctuation with ASCII equivalents and drops
    any remaining non-Latin-1 characters that would cause a render error.
    """
    replacements = {
        "\u2018": "'", "\u2019": "'",   # curly single quotes
        "\u201c": '"', "\u201d": '"',   # curly double quotes
        "\u2013": "-", "\u2014": "--",  # en-dash, em-dash
        "\u2026": "...",                # ellipsis
        "\u00e2\u0080\u0099": "'",      # UTF-8 mis-decoded right single quote
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    # Drop any character outside Latin-1 range (codepoint > 255)
    return text.encode("latin-1", errors="ignore").decode("latin-1")


def save(report: dict[str, Any], output_dir: str) -> str:
    """
    Generate and save a PDF audit report.
    report: the complete report dictionary from reporter.build_report()
    output_dir: the directory path where the file should be saved
                passed in by reporter.py which manages directory structure
    Returns the full file path where the PDF file was saved.
    """
    # Import fpdf2 here so the rest of the module works even if fpdf2 is not installed
    from fpdf import FPDF

    # Build the output filename using the same report ID as the other formats
    filename = os.path.join(output_dir, f"{report['report_id']}.pdf")

    # Create a new PDF document
    pdf = FPDF()

    # Add the first page
    pdf.add_page()

    # Set page margins: left, top, right all 15mm
    pdf.set_margins(15, 15, 15)

    # ── HEADER ──

    # Main title: Arial bold 18pt dark navy
    pdf.set_font("Arial", "B", 18)
    pdf.set_text_color(26, 26, 46)
    pdf.cell(0, 10, "ComplianceGuard Audit Report", ln=True, align="C")
    pdf.ln(3)

    # Metadata lines: Arial regular 10pt gray
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Report ID: {report['report_id']}", ln=True, align="C")
    pdf.cell(0, 6, f"Generated: {report['generated_at']}", ln=True, align="C")
    pdf.cell(0, 6, f"Agent Version: {report['agent_version']}", ln=True, align="C")
    pdf.ln(4)

    # Compliance status badge: colored filled cell
    # Red for non-compliant, green for compliant
    if report["compliance_status"] == "NON-COMPLIANT":
        pdf.set_fill_color(220, 53, 69)     # Red
    else:
        pdf.set_fill_color(40, 167, 69)     # Green

    pdf.set_text_color(255, 255, 255)       # White text on colored background
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, report["compliance_status"], ln=True, align="C", fill=True)
    pdf.ln(5)

    # ── SUMMARY ──

    # Section header
    pdf.set_text_color(26, 26, 46)
    pdf.set_font("Arial", "B", 13)
    pdf.cell(0, 8, "Scan Summary", ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    # Summary statistics as label-value pairs
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(60, 60, 60)
    s = report["summary"]
    pdf.cell(0, 7, f"Containers Scanned: {s['containers_scanned']}", ln=True)
    pdf.cell(0, 7, f"Total Findings: {s['total_findings']}", ln=True)
    pdf.cell(0, 7, f"Critical: {s['critical']}  |  High: {s['high']}  |  Medium: {s['medium']}", ln=True)
    pdf.cell(0, 7, f"AI Classified: {s['ai_classified']}/{s['total_findings']}", ln=True)
    pdf.ln(5)

    # ── FINDINGS ──

    # Section header
    pdf.set_text_color(26, 26, 46)
    pdf.set_font("Arial", "B", 13)
    pdf.cell(0, 8, "Compliance Findings", ln=True)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    # Map severity levels to RGB color tuples for badges
    severity_colors = {
        "CRITICAL": (220, 53, 69),
        "HIGH":     (253, 126, 20),
        "MEDIUM":   (255, 193, 7),
        "LOW":      (23, 162, 184)
    }

    # Write each finding as a structured block
    for i, finding in enumerate(report["findings"]):

        # Add a new page if we are near the bottom
        if pdf.get_y() > 250:
            pdf.add_page()
            pdf.ln(5)

        # Finding subheader: number, container, rule
        pdf.set_font("Arial", "B", 11)
        pdf.set_text_color(26, 26, 46)
        pdf.cell(0, 8, f"Finding {i+1}: {finding['container']} - {finding['rule_id']}", ln=True)

        # Severity badge as a small colored filled cell
        color = severity_colors.get(finding["severity"], (108, 117, 125))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(30, 6, finding["severity"], fill=True)

        # PCI control reference next to the badge
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Arial", "", 9)
        pdf.cell(0, 6, f"  {finding['pci_control']}", ln=True)
        pdf.ln(1)

        # Declared vs observed drift — use single full-width cells to avoid x-position drift
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "", 9)
        pdf.cell(0, 6, f"Declared:  {_safe(str(finding.get('declared', 'N/A')))}", ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 6, f"Observed:  {_safe(str(finding.get('observed', 'N/A')))}", ln=True)

        # Attack scenario — reset x before every multi_cell call
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 6, "Attack Scenario:", ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "", 9)
        pdf.multi_cell(0, 5, _safe(finding.get("attack_scenario", "N/A")))

        # Business risk
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 6, "Business Risk:", ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "", 9)
        pdf.multi_cell(0, 5, _safe(finding.get("business_risk", "N/A")))

        # Remediation steps as a numbered list
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 6, "Remediation Steps:", ln=True)
        pdf.set_font("Arial", "", 9)
        for j, step in enumerate(finding.get("remediation_steps", []), 1):
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, _safe(f"  {j}. {step}"))

        # Estimated fix time
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 6, f"Estimated Fix Time:  {_safe(finding.get('estimated_fix_time', 'N/A'))}", ln=True)

        # Separator line between findings
        pdf.set_draw_color(220, 220, 220)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(6)

    # ── FOOTER ──

    # Tamper detection hash in small italic gray text
    pdf.set_font("Arial", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, f"SHA-256: {report['report_hash']}", ln=True)
    pdf.cell(0, 6, "Verify integrity by recomputing SHA-256 of report content and comparing.", ln=True)

    pdf.output(filename)

    logger.info(f"PDF report saved: {filename}")
    return filename

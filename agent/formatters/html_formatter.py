"""
HTML Formatter - Generates a self-contained HTML report that opens in any browser.
The HTML report is styled for human readability with color-coded severity badges,
summary statistics cards, and a full findings table with AI analysis.
No external CSS or JavaScript dependencies: the file is fully self-contained.
"""

# Standard library imports
import logging                      # For recording formatter activity
import os                           # For building file paths and creating directories
from typing import Any              # Type hint: Any means a variable can hold any data type

# Create a logger for this module
logger = logging.getLogger(__name__)


def save(report: dict[str, Any], output_dir: str) -> str:
    """
    Generate and save a human-readable HTML report from the audit findings.
    report: the complete report dictionary from reporter.build_report()
    output_dir: the directory path where the file should be saved
                passed in by reporter.py which manages directory structure
    Returns the full file path where the HTML file was saved.
    """
    # Build the filename using the same report ID as the JSON report
    # This keeps all three formats consistently named for easy correlation
    filename = os.path.join(output_dir, f"{report['report_id']}.html")

    # Determine the status banner color based on compliance result
    status_color = "#dc3545" if report["compliance_status"] == "NON-COMPLIANT" else "#28a745"

    # Map severity levels to badge colors following standard security dashboard conventions
    severity_colors = {
        "CRITICAL": "#dc3545",      # Red for critical
        "HIGH":     "#fd7e14",      # Orange for high
        "MEDIUM":   "#ffc107",      # Yellow for medium
        "LOW":      "#17a2b8"       # Blue for low
    }

    # Build the HTML table rows for each finding
    # Each finding becomes one row with all its AI-enriched fields
    findings_rows = ""
    for finding in report["findings"]:

        # Get the badge color for this finding's severity
        color = severity_colors.get(finding["severity"], "#6c757d")

        # Build the remediation steps as an HTML ordered list
        steps = finding.get("remediation_steps", [])
        steps_html = "<ol>" + "".join(f"<li>{s}</li>" for s in steps) + "</ol>"

        # Build one table row for this finding
        # Inline styles keep the HTML fully self-contained with no external CSS
        findings_rows += f"""
        <tr>
            <td><code>{finding['container']}</code></td>
            <td><code>{finding['rule_id']}</code></td>
            <td><span style="
                background-color: {color};
                color: white;
                padding: 2px 8px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            ">{finding['severity']}</span></td>
            <td><code>{finding['pci_control']}</code></td>
            <td>{finding.get('attack_scenario', 'N/A')}</td>
            <td>{finding.get('business_risk', 'N/A')}</td>
            <td>{steps_html}</td>
            <td>{finding.get('estimated_fix_time', 'N/A')}</td>
        </tr>"""

    # Build the complete HTML document as a self-contained string
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ComplianceGuard Report {report['report_id']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0; padding: 20px; background: #f8f9fa; color: #333;
        }}
        .header {{
            background: #1a1a2e; color: white; padding: 30px;
            border-radius: 8px; margin-bottom: 20px;
        }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 24px; }}
        .header p {{ margin: 5px 0; opacity: 0.8; font-size: 14px; }}
        .status-badge {{
            display: inline-block; background: {status_color}; color: white;
            padding: 6px 16px; border-radius: 20px; font-weight: bold;
            font-size: 14px; margin-top: 10px;
        }}
        .summary-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; margin-bottom: 20px;
        }}
        .stat-card {{
            background: white; padding: 20px; border-radius: 8px;
            text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-card .number {{ font-size: 32px; font-weight: bold; margin-bottom: 5px; }}
        .stat-card .label {{ font-size: 13px; color: #666; text-transform: uppercase; }}
        .table-container {{
            background: white; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; margin-bottom: 20px;
        }}
        .table-container h2 {{
            padding: 20px; margin: 0; background: #f8f9fa;
            border-bottom: 1px solid #dee2e6; font-size: 18px;
        }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{
            background: #343a40; color: white; padding: 12px 15px;
            text-align: left; font-weight: 600; white-space: nowrap;
        }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #dee2e6; vertical-align: top; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background: #f8f9fa; }}
        code {{ background: #f1f3f4; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
        ol {{ margin: 0; padding-left: 18px; }}
        ol li {{ margin-bottom: 4px; }}
        .footer {{
            background: white; padding: 15px 20px; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 12px; color: #666;
        }}
        .footer code {{ word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ComplianceGuard Audit Report</h1>
        <p>Report ID: {report['report_id']}</p>
        <p>Generated: {report['generated_at']}</p>
        <p>Agent Version: {report['agent_version']}</p>
        <div class="status-badge">{report['compliance_status']}</div>
    </div>

    <div class="summary-grid">
        <div class="stat-card">
            <div class="number">{report['summary']['containers_scanned']}</div>
            <div class="label">Containers Scanned</div>
        </div>
        <div class="stat-card">
            <div class="number">{report['summary']['total_findings']}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#dc3545">{report['summary']['critical']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#fd7e14">{report['summary']['high']}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ffc107">{report['summary']['medium']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#28a745">{report['summary']['ai_classified']}</div>
            <div class="label">AI Classified</div>
        </div>
    </div>

    <div class="table-container">
        <h2>Compliance Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Container</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th>PCI Control</th>
                    <th>Attack Scenario</th>
                    <th>Business Risk</th>
                    <th>Remediation Steps</th>
                    <th>Fix Time</th>
                </tr>
            </thead>
            <tbody>{findings_rows}</tbody>
        </table>
    </div>

    <div class="footer">
        <strong>Report Integrity Hash (SHA-256):</strong><br>
        <code>{report['report_hash']}</code><br><br>
        To verify this report has not been tampered with, recompute the SHA-256 hash
        of the report content (excluding the report_hash field) and compare.
        Generated by ComplianceGuard v{report['agent_version']}.
    </div>
</body>
</html>"""

    # Write the HTML string to disk
    with open(filename, "w") as f:
        f.write(html)

    logger.info(f"HTML report saved: {filename}")
    return filename

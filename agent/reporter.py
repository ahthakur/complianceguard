"""
Reporter module - Orchestrates audit report generation across all output formats.
This module builds the core report structure, coordinates the three formatters
(JSON, HTML, PDF), and prints the rich terminal summary for operators.
Each output format is handled by a dedicated formatter in agent/formatters/.
"""

# Standard library imports
import hashlib                      # For computing SHA-256 hash for tamper detection
import json                         # For serializing report data when computing the hash
import logging                      # For recording reporter activity
import os                           # For reading environment variables
from datetime import datetime       # For generating ISO 8601 timestamps
from typing import Any              # Type hint: Any means a variable can hold any data type

# Third-party imports
from rich.console import Console    # Rich: renders beautiful formatted terminal output
from rich.table import Table        # Rich: renders data as formatted terminal tables
from rich.panel import Panel        # Rich: renders content inside a bordered panel
from rich import box                # Rich: provides box drawing styles for tables

# Import the three formatter modules from the formatters subpackage
# Each formatter owns exactly one output format
from agent.formatters import json_formatter     # Handles JSON output
from agent.formatters import html_formatter     # Handles HTML output
from agent.formatters import pdf_formatter      # Handles PDF output

# Create a logger and Rich console for this module
logger = logging.getLogger(__name__)
console = Console()

# Read the report output directory from environment variable
REPORT_DIR = os.getenv("REPORT_OUTPUT_DIR", "./reports")


def generate_report_id() -> str:
    """
    Generate a unique report ID based on the current UTC timestamp.
    Format: CG-YYYYMMDD-HHMMSS (e.g. CG-20260419-142233)
    """
    # Format current UTC time as compact timestamp
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"CG-{timestamp}"


def compute_report_hash(report_data: dict[str, Any]) -> str:
    """
    Compute a SHA-256 hash of the report content for tamper detection.
    Sort keys before hashing to ensure identical data always produces
    the same hash regardless of key ordering in the dictionary.
    """
    # Serialize with sorted keys so hash is deterministic
    report_json = json.dumps(report_data, sort_keys=True)
    # Encode to bytes then compute SHA-256 and return as hex string
    return hashlib.sha256(report_json.encode("utf-8")).hexdigest()


def prepare_report_dirs() -> tuple:
    """
    Prepare the report output directory structure.
    Creates two subdirectories inside REPORT_DIR:
      _LastReport: always contains only the most recent report (3 files: JSON, HTML, PDF)
      _Archive: contains all previous reports moved from _LastReport on each run
    This keeps the reports folder navigable: open _LastReport to see the latest,
    open _Archive to see historical reports.
    Returns a tuple of (last_report_dir, archive_dir) paths.
    """
    # Build paths for the two subdirectories
    last_report_dir = os.path.join(REPORT_DIR, "_LastReport")   # Latest report lives here
    archive_dir = os.path.join(REPORT_DIR, "_Archive")          # All previous reports live here

    # Create both directories if they do not already exist
    # exist_ok=True means no error if the directory is already there
    os.makedirs(last_report_dir, exist_ok=True)
    os.makedirs(archive_dir, exist_ok=True)

    # Move any existing files from _LastReport into _Archive
    # This happens before writing the new report so _LastReport always has only the latest
    existing_files = os.listdir(last_report_dir)    # List everything currently in _LastReport

    for filename in existing_files:
        # Build the full source and destination paths
        src = os.path.join(last_report_dir, filename)
        dst = os.path.join(archive_dir, filename)

        # Only move files, not subdirectories
        # os.path.isfile checks that src is a regular file before moving
        if os.path.isfile(src):
            # Move the file from _LastReport to _Archive
            # os.rename is an atomic move operation on the same filesystem
            os.rename(src, dst)
            logger.info(f"Archived previous report file: {filename}")

    return last_report_dir, archive_dir     # Return both paths for the formatters to use


def build_report(classified_result: dict[str, Any]) -> dict[str, Any]:
    """
    Build the core report structure from classified findings.
    This is the shared data model that all three formatters consume.
    classified_result: full output from classifier.classify_all()
    Returns a complete report dictionary including SHA-256 hash.
    """
    report_id = generate_report_id()
    timestamp = datetime.utcnow().isoformat() + "Z"     # Z suffix = UTC

    findings = classified_result.get("findings", [])
    summary = classified_result.get("summary", {})

    # Determine overall compliance status
    compliance_status = "NON-COMPLIANT" if findings else "COMPLIANT"

    # Build the report body without the hash field first
    # The hash is computed over this content and then appended
    report = {
        "report_id": report_id,
        "generated_at": timestamp,
        "agent_version": "1.0.0",
        "compliance_status": compliance_status,
        "summary": {
            "total_findings":     summary.get("total_findings", 0),
            "critical":           summary.get("critical", 0),
            "high":               summary.get("high", 0),
            "medium":             summary.get("medium", 0),
            "containers_scanned": summary.get("containers_scanned", 0),
            "ai_classified":      summary.get("ai_classified", 0),
        },
        "pci_controls_evaluated": [
            "PCI-DSS-v4.0-7.2.1",
            "PCI-DSS-v4.0-2.2.1",
            "PCI-DSS-v4.0-1.3.1",
            "PCI-DSS-v4.0-1.3.2",
        ],
        "findings": findings,
    }

    # Compute and append the tamper detection hash
    report["report_hash"] = compute_report_hash(report)

    return report


def print_terminal_summary(report: dict[str, Any], report_path: str) -> None:
    """
    Print a rich formatted summary table to the terminal.
    This gives operators an immediate visual overview when running interactively.
    report: the complete report dictionary
    report_path: the JSON file path to display in the header panel
    """
    # Status panel: red for non-compliant, green for compliant
    status = report["compliance_status"]
    status_color = "red" if status == "NON-COMPLIANT" else "green"

    console.print(Panel(
        f"[bold]Report ID:[/bold] {report['report_id']}\n"
        f"[bold]Generated:[/bold] {report['generated_at']}\n"
        f"[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]\n"
        f"[bold]JSON report:[/bold] {report_path}",
        title="[bold blue]ComplianceGuard Audit Report[/bold blue]",
        border_style="blue"
    ))

    # Summary statistics
    s = report["summary"]
    console.print(f"\n[bold]Scan Summary:[/bold]")
    console.print(f"  Containers scanned: {s['containers_scanned']}")
    console.print(f"  Total findings:     {s['total_findings']}")
    console.print(f"  [red]Critical:[/red]           {s['critical']}")
    console.print(f"  [yellow]High:[/yellow]               {s['high']}")
    console.print(f"  [blue]Medium:[/blue]             {s['medium']}")
    console.print(f"  AI classified:      {s['ai_classified']}/{s['total_findings']}")

    # Findings table
    if report["findings"]:
        table = Table(
            title="Compliance Findings",
            box=box.ROUNDED,
            show_lines=True
        )
        table.add_column("Container",   style="cyan", no_wrap=True)
        table.add_column("Rule",        style="white")
        table.add_column("Severity",    justify="center")
        table.add_column("PCI Control", style="yellow")
        table.add_column("Fix Time",    justify="center")

        for finding in report["findings"]:
            sev = finding["severity"]
            if sev == "CRITICAL":
                sev_display = f"[red bold]{sev}[/red bold]"
            elif sev == "HIGH":
                sev_display = f"[yellow]{sev}[/yellow]"
            else:
                sev_display = f"[blue]{sev}[/blue]"

            table.add_row(
                finding["container"],
                finding["rule_id"],
                sev_display,
                finding["pci_control"],
                finding.get("estimated_fix_time", "N/A")
            )

        console.print(table)

    # Tamper detection hash footer
    console.print(f"\n[dim]SHA-256: {report['report_hash']}[/dim]")
    console.print(f"[dim]Verify: recompute hash of report content and compare[/dim]\n")


def generate_report(classified_result: dict[str, Any]) -> str:
    """
    Full report generation pipeline: build the report, save in all three formats,
    and print the terminal summary.
    classified_result: full output from classifier.classify_all()
    Saves three output files into reports/_LastReport/ and moves previous reports
    to reports/_Archive/ before writing the new ones.
    Returns the JSON file path as the primary reference.
    This is the main entry point called by main.py.
    """
    logger.info("Generating audit report...")

    # Step 1: Prepare the directory structure
    # Move any existing _LastReport files to _Archive before writing new ones
    last_report_dir, archive_dir = prepare_report_dirs()
    logger.info(f"Report directory ready: {last_report_dir}")

    # Step 2: Build the shared report data model with SHA-256 hash
    report = build_report(classified_result)

    # Step 3: Save in all three formats into _LastReport
    # Each formatter receives the target directory explicitly
    json_path = json_formatter.save(report, last_report_dir)    # Machine-readable JSON
    html_path = html_formatter.save(report, last_report_dir)    # Human-readable HTML
    pdf_path  = pdf_formatter.save(report, last_report_dir)     # Auditor-ready PDF

    # Step 4: Print the rich terminal summary for the operator
    print_terminal_summary(report, json_path)

    # Step 5: Log all three output paths
    logger.info(f"JSON: {json_path}")
    logger.info(f"HTML: {html_path}")
    logger.info(f"PDF:  {pdf_path}")
    logger.info("Report generation complete")

    return json_path

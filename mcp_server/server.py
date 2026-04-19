"""
ComplianceGuard MCP Server
Exposes compliance report data and scanning capabilities as MCP tools
that Claude can call conversationally.

Tools available:
  - get_last_report: returns full findings from the latest compliance scan
  - get_findings_by_severity: filters findings by severity level
  - get_container_status: returns observed state for a specific container
  - run_compliance_scan: triggers a fresh compliance scan and returns results

Usage:
  python3.11 -m mcp_server.server

Then connect Claude Desktop or Claude Code to this server via MCP settings.
"""

# Standard library imports
import json                         # For reading JSON report files
import logging                      # For recording server activity
import os                           # For building file paths
import subprocess                   # For triggering agent scans as a subprocess
import sys                          # For path manipulation
from pathlib import Path            # For clean file path operations
from typing import Any              # Type hint: Any means any data type

# Add the parent directory to sys.path so we can import agent modules
# This allows the MCP server to import scanner.py directly for container status
sys.path.insert(0, str(Path(__file__).parent.parent))

# Third-party imports
from mcp.server.fastmcp import FastMCP    # FastMCP: the simplest way to build an MCP server

# Create the FastMCP server instance
# The name appears in Claude's tool list when connected
mcp = FastMCP("ComplianceGuard")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path to the reports directory relative to this file
# We go up one level (from mcp_server/) to reach the project root
REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Path to the _LastReport subdirectory
LAST_REPORT_DIR = REPORTS_DIR / "_LastReport"


def load_latest_report() -> dict[str, Any] | None:
    """
    Load the most recent JSON report from the _LastReport directory.
    Returns the parsed report dictionary or None if no report exists.
    """
    # Check if the _LastReport directory exists and has files
    if not LAST_REPORT_DIR.exists():
        return None

    # Find all JSON files in _LastReport
    # glob returns a generator of Path objects matching the pattern
    json_files = list(LAST_REPORT_DIR.glob("*.json"))

    # If no JSON files exist, no report has been generated yet
    if not json_files:
        return None

    # Sort by filename (which includes timestamp) and take the most recent
    # The CG-YYYYMMDD-HHMMSS format sorts correctly alphabetically
    latest = sorted(json_files)[-1]

    # Read and parse the JSON report file
    with open(latest, "r") as f:
        return json.load(f)


@mcp.tool()
def get_last_report() -> str:
    """
    Get the full findings from the most recent ComplianceGuard compliance scan.
    Returns a summary of all violations found, their severity levels,
    PCI-DSS control mappings, and AI-generated remediation guidance.
    Use this to understand the current compliance posture of the infrastructure.
    """
    # Load the latest report from disk
    report = load_latest_report()

    # Handle the case where no report has been generated yet
    if not report:
        return (
            "No compliance report found. Run a scan first using run_compliance_scan."
        )

    # Extract key fields for a clean response
    report_id = report.get("report_id", "unknown")
    generated_at = report.get("generated_at", "unknown")
    status = report.get("compliance_status", "unknown")
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    # Build a structured text response Claude can reason over
    lines = [
        f"ComplianceGuard Report: {report_id}",
        f"Generated: {generated_at}",
        f"Status: {status}",
        f"",
        f"Summary:",
        f"  Containers scanned: {summary.get('containers_scanned', 0)}",
        f"  Total findings: {summary.get('total_findings', 0)}",
        f"  Critical: {summary.get('critical', 0)}",
        f"  High: {summary.get('high', 0)}",
        f"  Medium: {summary.get('medium', 0)}",
        f"  AI classified: {summary.get('ai_classified', 0)}",
        f"",
        f"Findings:",
    ]

    # Add each finding as a structured block
    for i, finding in enumerate(findings, 1):
        lines.extend([
            f"",
            f"Finding {i}: {finding.get('container')} - {finding.get('rule_id')}",
            f"  Severity: {finding.get('severity')}",
            f"  PCI Control: {finding.get('pci_control')}",
            f"  Declared: {finding.get('declared')}",
            f"  Observed: {finding.get('observed')}",
            f"  Attack scenario: {finding.get('attack_scenario', 'N/A')}",
            f"  Business risk: {finding.get('business_risk', 'N/A')}",
            f"  Fix time: {finding.get('estimated_fix_time', 'N/A')}",
            f"  Remediation:",
        ])
        # Add each remediation step as a numbered list item
        for j, step in enumerate(finding.get("remediation_steps", []), 1):
            lines.append(f"    {j}. {step}")

    # Add the tamper detection hash at the end
    lines.extend([
        f"",
        f"Report integrity hash (SHA-256): {report.get('report_hash', 'N/A')}",
    ])

    return "\n".join(lines)


@mcp.tool()
def get_findings_by_severity(severity: str) -> str:
    """
    Get compliance findings filtered by severity level.
    severity: one of CRITICAL, HIGH, or MEDIUM (case-insensitive)
    Returns all findings matching the requested severity with full AI analysis.
    Use this to focus on the most urgent violations first.
    """
    # Normalize the severity input to uppercase for consistent comparison
    severity = severity.upper()

    # Validate that the severity level is one we recognize
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if severity not in valid_severities:
        return f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"

    # Load the latest report
    report = load_latest_report()
    if not report:
        return "No compliance report found. Run a scan first using run_compliance_scan."

    # Filter findings to only those matching the requested severity
    findings = [
        f for f in report.get("findings", [])
        if f.get("severity", "").upper() == severity
    ]

    # Handle the case where no findings match the requested severity
    if not findings:
        return f"No {severity} severity findings in the latest report. Infrastructure is compliant at this severity level."

    # Build the response
    lines = [
        f"{severity} Severity Findings ({len(findings)} total)",
        f"From report: {report.get('report_id')}",
        f"",
    ]

    for i, finding in enumerate(findings, 1):
        lines.extend([
            f"Finding {i}: {finding.get('container')} - {finding.get('rule_id')}",
            f"  PCI Control: {finding.get('pci_control')}",
            f"  Declared: {finding.get('declared')}",
            f"  Observed: {finding.get('observed')}",
            f"  Attack scenario: {finding.get('attack_scenario', 'N/A')}",
            f"  Business risk: {finding.get('business_risk', 'N/A')}",
            f"  Estimated fix time: {finding.get('estimated_fix_time', 'N/A')}",
            f"  Remediation steps:",
        ])
        for j, step in enumerate(finding.get("remediation_steps", []), 1):
            lines.append(f"    {j}. {step}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def get_container_status(container_name: str) -> str:
    """
    Get the current observed security state of a specific container.
    container_name: the name of the container (e.g. cg-data-processor)
    Returns the container's current security configuration and any
    compliance findings associated with it from the latest report.
    Use this to investigate a specific container in depth.
    """
    # Import scanner here to query live Docker state
    # We import inside the function to avoid startup errors if Docker is not running
    try:
        from agent.scanner import scan_containers
    except ImportError as e:
        return f"Cannot import scanner module: {e}. Make sure you are running from the complianceguard directory."

    # Scan live Docker state for all managed containers
    try:
        containers = scan_containers()
    except RuntimeError as e:
        return f"Cannot connect to Docker: {e}. Make sure Docker Desktop is running."

    # Find the requested container by name
    # We do a case-insensitive partial match so users do not need exact names
    matched = [
        c for c in containers
        if container_name.lower() in c["name"].lower()
    ]

    # Handle no match
    if not matched:
        available = [c["name"] for c in containers]
        return (
            f"Container '{container_name}' not found. "
            f"Available managed containers: {', '.join(available)}"
        )

    # Use the first match
    container = matched[0]

    # Build the live state response
    lines = [
        f"Container: {container['name']}",
        f"Status: {container['status']}",
        f"Image: {container['image']}",
        f"Running: {container['running']}",
        f"",
        f"Security Configuration (observed):",
        f"  Privileged: {container['privileged']}",
        f"  Read-only filesystem: {container['read_only']}",
        f"  Network mode: {container['network_mode']}",
        f"  Security options: {container['security_opt']}",
        f"  Capabilities dropped: {container['cap_drop']}",
        f"  Capabilities added: {container['cap_add']}",
        f"  Exposed ports: {container['ports']}",
        f"",
        f"Compliance tier: {container['labels'].get('complianceguard.tier', 'unknown')}",
        f"Policy: {container['labels'].get('complianceguard.policy', 'unknown')}",
    ]

    # Also pull findings for this container from the latest report
    report = load_latest_report()
    if report:
        container_findings = [
            f for f in report.get("findings", [])
            if f.get("container") == container["name"]
        ]

        if container_findings:
            lines.extend([
                f"",
                f"Active Compliance Findings ({len(container_findings)}):",
            ])
            for finding in container_findings:
                lines.extend([
                    f"  - [{finding['severity']}] {finding['rule_id']}: {finding['description']}",
                ])
        else:
            lines.extend([
                f"",
                f"No compliance findings for this container in the latest report.",
            ])

    return "\n".join(lines)


@mcp.tool()
def run_compliance_scan() -> str:
    """
    Trigger a full ComplianceGuard compliance scan of the live infrastructure.
    This runs the complete pipeline: scan, evaluate, classify with Claude AI,
    and generate updated reports. Takes approximately 60-90 seconds to complete
    as it makes Claude API calls for each finding.
    Returns a summary of the findings from the new scan.
    Use this to get fresh compliance data after making infrastructure changes.
    """
    logger.info("MCP tool: run_compliance_scan triggered")

    # Run the agent as a subprocess so it has its own process context
    # This is safer than importing and calling directly from within the MCP server
    try:
        # Run python3 -m agent.main from the project root directory
        # capture_output=True captures both stdout and stderr
        # timeout=300 gives the scan up to 5 minutes to complete
        result = subprocess.run(
            [sys.executable, "-m", "agent.main"],
            capture_output=True,        # Capture stdout and stderr
            text=True,                  # Return strings not bytes
            timeout=300,                # 5 minute timeout for full scan
            cwd=str(Path(__file__).parent.parent)   # Run from project root
        )

        # Check if the scan completed successfully
        # Exit code 0 = compliant, exit code 1 = violations found
        # Both are successful runs, not errors
        if result.returncode in [0, 1]:
            # Load the newly generated report
            report = load_latest_report()
            if report:
                summary = report.get("summary", {})
                status = report.get("compliance_status", "unknown")
                return (
                    f"Scan complete. Report: {report.get('report_id')}\n"
                    f"Status: {status}\n"
                    f"Containers scanned: {summary.get('containers_scanned', 0)}\n"
                    f"Total findings: {summary.get('total_findings', 0)}\n"
                    f"Critical: {summary.get('critical', 0)}\n"
                    f"High: {summary.get('high', 0)}\n"
                    f"Medium: {summary.get('medium', 0)}\n"
                    f"\nUse get_last_report to see full findings with AI analysis."
                )
            else:
                return "Scan completed but report could not be loaded."
        else:
            # A non-0/1 exit code means something went wrong
            return (
                f"Scan failed with exit code {result.returncode}.\n"
                f"Error: {result.stderr[:500] if result.stderr else 'No error output'}"
            )

    except subprocess.TimeoutExpired:
        return "Scan timed out after 5 minutes. Try running python3 -m agent.main manually."

    except Exception as e:
        return f"Failed to run scan: {e}"


if __name__ == "__main__":
    # Run the MCP server using stdio transport
    # stdio is the standard transport for MCP servers used with Claude Desktop and Claude Code
    logger.info("Starting ComplianceGuard MCP server...")
    mcp.run(transport="stdio")

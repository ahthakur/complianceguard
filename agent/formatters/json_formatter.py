"""
JSON Formatter - Saves the audit report as a machine-readable JSON file.
JSON is the primary output format: it is consumed by other tools, stored in
audit systems, and used to verify the SHA-256 tamper detection hash.
"""

# Standard library imports
import json                         # For serializing the report dictionary to JSON format
import logging                      # For recording formatter activity in the audit trail
import os                           # For building file paths and creating directories
from typing import Any              # Type hint: Any means a variable can hold any data type

# Create a logger for this module
logger = logging.getLogger(__name__)


def save(report: dict[str, Any], output_dir: str) -> str:
    """
    Save the audit report as a formatted JSON file.
    report: the complete report dictionary from reporter.build_report()
    output_dir: the directory path where the file should be saved
                passed in by reporter.py which manages directory structure
    Returns the full file path where the JSON file was saved.
    """
    # Build the output filename using the report ID inside the given directory
    filename = os.path.join(output_dir, f"{report['report_id']}.json")

    # Write the report to disk as formatted JSON with 2-space indentation
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"JSON report saved: {filename}")
    return filename

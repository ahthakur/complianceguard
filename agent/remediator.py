"""
Remediator module - Applies guided remediation to docker-compose.yml for compliance findings.
This module implements the guided remediation pattern:
  1. preview_remediation: shows the exact diff without applying any changes (dry-run)
  2. apply_remediation: applies the approved change, restarts the container, confirms resolution

Safety principles:
  - Never auto-apply changes without explicit user confirmation
  - Always show the exact before/after diff in dry-run
  - Every remediation is logged as a compliance audit event
  - Only remediates settings expressible in docker-compose.yml
"""

# Standard library imports
import logging                      # For recording remediation activity in the audit trail
import os                           # For building file paths
import subprocess                   # For running docker compose commands to restart containers
from datetime import datetime       # For timestamping remediation audit events
from pathlib import Path            # For clean file path operations
from typing import Any              # Type hint: Any means a variable can hold any data type

# Third-party imports
import yaml                         # For parsing and writing docker-compose.yml

# Create a logger for this module
logger = logging.getLogger(__name__)

# Path to docker-compose.yml relative to the project root
# We go up one level from agent/ to reach the project root
COMPOSE_FILE = Path(__file__).parent.parent / "docker-compose.yml"

# Path to the remediation audit log
# Every applied remediation is recorded here for compliance evidence
REMEDIATION_LOG = Path(__file__).parent.parent / "reports" / "remediation-audit.log"

# Map each rule ID to the exact docker-compose.yml fix that resolves it
# Each entry describes what field to change, what value to set, and a human description
# This is the remediation knowledge base: rule ID -> fix specification
REMEDIATION_MAP = {
    "no-privileged-containers": {
        "field": "privileged",              # The docker-compose field to change
        "value": False,                     # The correct value to set
        "description": "Set privileged: false to remove host kernel access",
        "requires_restart": True            # Whether the container needs restarting
    },
    "read-only-root-filesystem": {
        "field": "read_only",
        "value": True,
        "description": "Set read_only: true to prevent filesystem modification",
        "requires_restart": True
    },
    "drop-all-capabilities": {
        "field": "cap_drop",
        "value": ["ALL"],
        "description": "Add cap_drop: [ALL] to remove all Linux capabilities",
        "requires_restart": True
    },
    "no-new-privileges": {
        "field": "security_opt",
        "value": ["no-new-privileges:true"],
        "description": "Add no-new-privileges:true to security_opt to prevent privilege escalation",
        "requires_restart": True
    },
}


def load_compose_file() -> dict[str, Any]:
    """
    Load and parse the docker-compose.yml file into a Python dictionary.
    Returns the parsed compose configuration.
    Raises FileNotFoundError if docker-compose.yml does not exist.
    """
    # Check that the compose file exists before trying to read it
    if not COMPOSE_FILE.exists():
        raise FileNotFoundError(f"docker-compose.yml not found at {COMPOSE_FILE}")

    # Open and parse the YAML file
    with open(COMPOSE_FILE, "r") as f:
        # yaml.safe_load parses YAML safely without executing arbitrary code
        return yaml.safe_load(f)


def save_compose_file(compose_data: dict[str, Any]) -> None:
    """
    Save the modified compose configuration back to docker-compose.yml.
    compose_data: the modified compose dictionary to write
    Uses yaml.dump to serialize with clean formatting.
    """
    with open(COMPOSE_FILE, "w") as f:
        # default_flow_style=False uses block style (readable multi-line format)
        # allow_unicode=True preserves unicode characters
        # sort_keys=False preserves the original key ordering
        yaml.dump(compose_data, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)

    logger.info(f"docker-compose.yml updated successfully")


def get_current_value(
    compose_data: dict[str, Any],
    service_name: str,
    field: str
) -> Any:
    """
    Get the current value of a field for a specific service in docker-compose.yml.
    compose_data: the parsed compose configuration
    service_name: the name of the service (e.g. cg-data-processor)
    field: the field to read (e.g. privileged, read_only)
    Returns the current value or None if the field is not set.
    """
    # Navigate into the services section and find the specific service
    services = compose_data.get("services", {})
    service = services.get(service_name, {})

    # Return the field value, or None if it is not set
    return service.get(field)


def preview_remediation(rule_id: str, container_name: str) -> dict[str, Any]:
    """
    Generate a dry-run preview of the remediation for a specific finding.
    Shows exactly what would change in docker-compose.yml without applying anything.
    rule_id: the rule ID from the finding (e.g. no-privileged-containers)
    container_name: the container to remediate (e.g. cg-data-processor)
    Returns a dictionary with the proposed change details for display.
    """
    # Strip the cg- prefix from container name to get the service name
    # docker-compose service names do not have the cg- prefix
    # e.g. cg-data-processor -> data-processor
    service_name = container_name.replace("cg-", "", 1)

    # Check if we have a remediation recipe for this rule
    if rule_id not in REMEDIATION_MAP:
        return {
            "supported": False,
            "message": (
                f"No automated remediation available for rule '{rule_id}'. "
                f"This finding requires manual remediation. "
                f"Supported rules: {', '.join(REMEDIATION_MAP.keys())}"
            )
        }

    # Get the remediation recipe for this rule
    recipe = REMEDIATION_MAP[rule_id]

    # Load the current docker-compose.yml
    compose_data = load_compose_file()

    # Check that the service actually exists in docker-compose.yml
    services = compose_data.get("services", {})
    if service_name not in services:
        return {
            "supported": False,
            "message": (
                f"Service '{service_name}' not found in docker-compose.yml. "
                f"Available services: {', '.join(services.keys())}"
            )
        }

    # Get the current value of the field we would change
    current_value = get_current_value(compose_data, service_name, recipe["field"])

    # Build the preview result showing exactly what would change
    return {
        "supported": True,                  # This rule has an automated fix
        "rule_id": rule_id,                 # The rule being remediated
        "container": container_name,        # The container being fixed
        "service_name": service_name,       # The docker-compose service name
        "field": recipe["field"],           # The field that would change
        "current_value": current_value,     # What it is right now
        "proposed_value": recipe["value"],  # What it would be set to
        "description": recipe["description"],   # Human description of the change
        "requires_restart": recipe["requires_restart"],  # Whether restart needed
        "already_compliant": current_value == recipe["value"],  # Already fixed?
    }


def apply_remediation(rule_id: str, container_name: str) -> dict[str, Any]:
    """
    Apply the approved remediation to docker-compose.yml and restart the container.
    This function should only be called after the user has reviewed and approved
    the dry-run preview from preview_remediation().
    rule_id: the rule ID to remediate
    container_name: the container to fix
    Returns a result dictionary indicating success or failure.
    """
    # First run the preview to get the change details and validate inputs
    preview = preview_remediation(rule_id, container_name)

    # If the rule is not supported or inputs are invalid, return the error
    if not preview["supported"]:
        return {"success": False, "message": preview["message"]}

    # If the container is already compliant, no action needed
    if preview["already_compliant"]:
        return {
            "success": True,
            "message": f"{container_name} is already compliant for rule '{rule_id}'. No changes needed.",
            "changed": False
        }

    # Load the compose file fresh before making changes
    compose_data = load_compose_file()

    # Get the service name (strip the cg- prefix)
    service_name = preview["service_name"]

    # Get the recipe for this rule
    recipe = REMEDIATION_MAP[rule_id]

    # Apply the change to the service configuration
    # This modifies the in-memory dictionary before writing back to disk
    compose_data["services"][service_name][recipe["field"]] = recipe["value"]

    # Write the modified configuration back to docker-compose.yml
    save_compose_file(compose_data)

    # Log the remediation to the audit log for compliance evidence
    log_remediation_event(
        rule_id=rule_id,
        container=container_name,
        field=recipe["field"],
        old_value=preview["current_value"],
        new_value=recipe["value"],
        status="applied"
    )

    # Restart the container to apply the new configuration
    restart_result = restart_container(container_name)

    # Build the result message
    if restart_result["success"]:
        message = (
            f"Remediation applied successfully.\n"
            f"Changed {recipe['field']} from {preview['current_value']} "
            f"to {recipe['value']} for {container_name}.\n"
            f"Container restarted successfully.\n"
            f"Run a new compliance scan to confirm the finding is resolved."
        )
    else:
        message = (
            f"Remediation applied to docker-compose.yml but container restart failed.\n"
            f"Error: {restart_result['error']}\n"
            f"Run 'docker compose up -d' manually to restart the container."
        )

    return {
        "success": True,
        "changed": True,
        "rule_id": rule_id,
        "container": container_name,
        "field": recipe["field"],
        "old_value": preview["current_value"],
        "new_value": recipe["value"],
        "restart_success": restart_result["success"],
        "message": message
    }


def restart_container(container_name: str) -> dict[str, Any]:
    """
    Restart a specific container using docker compose.
    container_name: the full container name including cg- prefix
    Returns a dict with success status and any error message.
    """
    # Strip the cg- prefix to get the docker-compose service name
    service_name = container_name.replace("cg-", "", 1)

    logger.info(f"Restarting container: {container_name} (service: {service_name})")

    try:
        # Run docker compose up -d for the specific service
        # This recreates the container with the new configuration
        # --no-deps means do not restart dependent services
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--no-deps", service_name],
            capture_output=True,            # Capture stdout and stderr
            text=True,                      # Return strings not bytes
            timeout=60,                     # 60 second timeout for container restart
            cwd=str(COMPOSE_FILE.parent)    # Run from the project root directory
        )

        # Check if the command succeeded
        if result.returncode == 0:
            logger.info(f"Container {container_name} restarted successfully")
            return {"success": True}
        else:
            # The command failed, return the error output
            error = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Container restart failed: {error}")
            return {"success": False, "error": error}

    except subprocess.TimeoutExpired:
        # The restart took too long
        return {"success": False, "error": "Container restart timed out after 60 seconds"}

    except Exception as e:
        # Any other unexpected error
        return {"success": False, "error": str(e)}


def log_remediation_event(
    rule_id: str,
    container: str,
    field: str,
    old_value: Any,
    new_value: Any,
    status: str
) -> None:
    """
    Write a remediation event to the audit log file.
    Every applied remediation is recorded here as compliance evidence.
    This log is append-only: we never overwrite existing entries.
    """
    # Create the reports directory if it does not exist
    REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)

    # Build the log entry as a structured string
    # ISO 8601 timestamp ensures the log is sortable and parseable
    timestamp = datetime.utcnow().isoformat() + "Z"
    log_entry = (
        f"{timestamp} | REMEDIATION | {status.upper()} | "
        f"container={container} | rule={rule_id} | "
        f"field={field} | old={old_value} | new={new_value}\n"
    )

    # Append the entry to the log file
    # 'a' mode appends without overwriting existing content
    # This makes the log append-only for tamper-evidence
    with open(REMEDIATION_LOG, "a") as f:
        f.write(log_entry)

    logger.info(f"Remediation event logged: {log_entry.strip()}")

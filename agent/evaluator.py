"""
Evaluator module - Compares declared policy state against observed state and produces raw findings.
This is the policy engine of ComplianceGuard. It reads the YAML policy files (declared state),
compares them against the scanner output (observed state), and produces a structured list of
findings for the classifier to analyze.
"""

# Standard library imports
import logging                      # For recording what the evaluator does during each run
import os                           # For reading environment variables and building file paths
from typing import Any              # Type hint: Any means a variable can hold any data type

# Third-party imports
import yaml                         # PyYAML: parses YAML policy files into Python dictionaries

# Create a logger for this module
# Using __name__ (agent.evaluator) ties log messages to this specific module
logger = logging.getLogger(__name__)

# Read the policy directory path from environment variable
# Defaults to ./policies if the environment variable is not set
# This makes the path configurable without changing code
POLICY_DIR = os.getenv("POLICY_DIR", "./policies")


def load_policy(filename: str) -> dict[str, Any]:
    """
    Load and parse a single YAML policy file into a Python dictionary.
    filename: the name of the file inside the POLICY_DIR folder (e.g. container-policy.yaml)
    Returns a dictionary representing the full policy document.
    Raises FileNotFoundError if the policy file does not exist.
    """
    # Build the full file path by joining the policy directory and filename
    # os.path.join handles the slash between directory and filename correctly on all platforms
    path = os.path.join(POLICY_DIR, filename)

    # Log that we are loading this policy file so there is an audit trail
    logger.info(f"Loading policy: {path}")

    # Open the file and parse it as YAML
    # 'r' means read-only mode, we never modify policy files
    with open(path, "r") as f:
        # yaml.safe_load parses the YAML content into a Python dict
        # safe_load is used instead of load() for security: it prevents
        # execution of arbitrary Python objects embedded in YAML
        return yaml.safe_load(f)


def check_field(observed_value: Any, operator: str, expected_value: Any) -> bool:
    """
    Evaluate a single policy rule check against an observed container value.
    observed_value: what the scanner actually found on the container
    operator: the comparison type from the policy YAML (equals, not_equals, contains)
    expected_value: what the policy says the value should be
    Returns True if the container PASSES the check, False if it FAILS (drift detected).
    """
    if operator == "equals":
        # Direct equality check: observed must exactly match expected
        # Example: privileged must equal false
        return observed_value == expected_value

    elif operator == "not_equals":
        # Inequality check: observed must NOT match expected
        # Example: network_mode must not equal "host"
        return observed_value != expected_value

    elif operator == "contains":
        # Membership check: expected value must appear somewhere in the observed list
        # Example: security_opt list must contain "no-new-privileges:true"
        # We check if observed_value is a list first to avoid errors on non-list fields
        if isinstance(observed_value, list):
            return expected_value in observed_value
        # If the observed value is not a list, the check automatically fails
        # because we cannot check membership in a non-list
        return False

    # If an unknown operator is encountered, log a warning and return False
    # This is a safe default: unknown check = assume non-compliant
    logger.warning(f"Unknown operator: {operator}")
    return False


def evaluate_containers(
    observed_containers: list[dict[str, Any]],
    policy: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    Compare each observed container against every rule in the container policy.
    observed_containers: list of container state dicts from the scanner
    policy: the parsed container-policy.yaml as a Python dictionary
    Returns a list of finding dictionaries, one per violation found.
    Each finding contains all the information the classifier and reporter need.
    """
    findings = []                           # Empty list to collect all violations found

    # Extract the list of rules from the policy document
    # Each rule is a dict with id, description, severity, check, and pci_control fields
    rules = policy.get("rules", [])         # Default to empty list if no rules defined

    # Loop through every managed container the scanner found
    for container in observed_containers:

        # Get the container name for use in finding messages
        name = container["name"]

        # Check if the container is currently running
        # We still evaluate stopped containers because their config may still be non-compliant
        # and knowing a managed container is not running is itself a finding
        if not container["running"]:
            # Create a finding for the non-running container
            # This catches containers that crashed or were stopped unexpectedly
            findings.append({
                "container": name,                          # Which container has the issue
                "rule_id": "container-not-running",        # Unique identifier for this finding type
                "description": f"Managed container {name} is not running (status: {container['status']})",
                "severity": "HIGH",                        # Non-running managed containers are high severity
                "pci_control": "PCI-DSS-v4.0-2.2.1",     # System component availability requirement
                "declared": "running",                     # What we expected: the container should be up
                "observed": container["status"],           # What we found: exited, restarting, etc.
                "compliant": False                         # This is definitionally a violation
            })

        # Now evaluate every policy rule against this container's observed configuration
        for rule in rules:

            # Extract the check definition from the rule
            # check contains: field (what to look at), operator (how to compare), value (what to expect)
            check = rule.get("check", {})

            # Get the field name from the check definition
            # Example: "privileged", "read_only", "security_opt"
            field = check.get("field")

            # Look up the actual observed value for this field from the scanner output
            # If the field is not in the scanner output, default to None
            observed_value = container.get(field)

            # Get the comparison operator from the check definition
            operator = check.get("operator")

            # Get the expected value from the check definition
            expected_value = check.get("value")

            # Run the check: does the observed value pass or fail this rule?
            passed = check_field(observed_value, operator, expected_value)

            if not passed:
                # The container failed this rule: create a finding
                findings.append({
                    "container": name,                      # Which container failed
                    "rule_id": rule["id"],                  # The specific rule that was violated
                    "description": rule["description"],     # Human-readable description of the rule
                    "severity": rule["severity"],           # CRITICAL, HIGH, or MEDIUM from policy
                    "pci_control": rule["pci_control"],     # Which PCI-DSS v4.0 control this maps to
                    "declared": expected_value,             # What the policy says it should be
                    "observed": observed_value,             # What the scanner actually found
                    "compliant": False                      # This container failed this check
                })

                # Log the violation for the audit trail
                logger.warning(
                    f"VIOLATION: {name} failed rule '{rule['id']}' "
                    f"(expected {field}={expected_value}, got {observed_value})"
                )
            else:
                # The container passed this rule: log it but do not create a finding
                logger.info(f"PASS: {name} passed rule '{rule['id']}'")

    return findings                         # Return all findings for the classifier to process


def evaluate_all(observed_state: dict[str, Any]) -> dict[str, Any]:
    """
    Run the full policy evaluation across all resource types.
    observed_state: the full output from scanner.scan_all()
    Returns a structured evaluation result with all findings and summary statistics.
    This is the main entry point called by main.py.
    """
    logger.info("Starting policy evaluation...")

    # Load the container security policy from the policies directory
    # This is the declared state: what every managed container should look like
    container_policy = load_policy("container-policy.yaml")

    # Run container evaluation: compare observed containers against declared policy
    container_findings = evaluate_containers(
        observed_state["containers"],       # Observed state from the scanner
        container_policy                    # Declared state from the policy file
    )

    # Combine all findings from all resource types into one list
    # Structured as a list so network and RBAC findings can be added here later
    all_findings = container_findings

    # Calculate summary statistics for the report header
    total = len(all_findings)                                               # Total violations found
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL") # Count critical violations
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")         # Count high violations
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")     # Count medium violations

    # Log the evaluation summary
    logger.info(
        f"Evaluation complete: {total} findings "
        f"(CRITICAL: {critical}, HIGH: {high}, MEDIUM: {medium})"
    )

    # Build and return the full evaluation result dictionary
    # This is the input the classifier and reporter will consume
    return {
        "findings": all_findings,           # Full list of all violation findings
        "summary": {
            "total_findings": total,        # Total number of violations across all containers
            "critical": critical,           # Number of critical severity violations
            "high": high,                   # Number of high severity violations
            "medium": medium,               # Number of medium severity violations
            "containers_scanned": len(observed_state["containers"]),    # Total containers checked
        }
    }

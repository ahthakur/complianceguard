"""
Evaluator module - Compares declared policy state against observed state and produces raw findings.
This is the policy engine of ComplianceGuard. It reads the YAML policy files (declared state),
compares them against the scanner output (observed state), and produces a structured list of
findings for the classifier to analyze.
"""

import logging
import os
from typing import Any

import yaml

logger = logging.getLogger(__name__)

POLICY_DIR = os.getenv("POLICY_DIR", "./policies")


def load_policy(filename: str) -> dict[str, Any]:
    """Load and parse a single YAML policy file."""
    path = os.path.join(POLICY_DIR, filename)
    logger.info(f"Loading policy: {path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


def check_field(observed_value: Any, operator: str, expected_value: Any) -> bool:
    """
    Evaluate a single policy rule check against an observed container value.
    Returns True if the container PASSES the check, False if it FAILS.
    """
    if operator == "equals":
        return observed_value == expected_value

    elif operator == "not_equals":
        return observed_value != expected_value

    elif operator == "contains":
        if isinstance(observed_value, list):
            return expected_value in observed_value
        return False

    elif operator == "not_contains":
        if isinstance(observed_value, list):
            return expected_value not in observed_value
        if isinstance(observed_value, str):
            return expected_value not in observed_value
        return True

    elif operator == "not_contains_any":
        if isinstance(observed_value, list):
            return not any(v in observed_value for v in expected_value)
        return True

    elif operator == "is_empty":
        if expected_value:
            return observed_value is None or observed_value == [] or observed_value == ""
        return observed_value is not None and observed_value != [] and observed_value != ""

    elif operator == "greater_than":
        if observed_value is None:
            return False
        try:
            return float(observed_value) > float(expected_value)
        except (TypeError, ValueError):
            return False

    logger.warning(f"Unknown operator: {operator}")
    return False


def evaluate_containers(
    observed_containers: list[dict[str, Any]],
    policy: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    Compare each observed container against every rule in a policy.
    Works for both container-policy and network-policy rules.
    """
    findings = []
    rules = policy.get("rules", [])

    for container in observed_containers:
        name = container["name"]

        if not container["running"]:
            findings.append({
                "container": name,
                "rule_id": "container-not-running",
                "description": f"Managed container {name} is not running (status: {container['status']})",
                "severity": "HIGH",
                "pci_control": "PCI-DSS-v4.0-2.2.1",
                "declared": "running",
                "observed": container["status"],
                "compliant": False
            })

        for rule in rules:
            check = rule.get("check", {})
            field = check.get("field")
            observed_value = container.get(field)
            operator = check.get("operator")
            expected_value = check.get("value")

            passed = check_field(observed_value, operator, expected_value)

            if not passed:
                finding = {
                    "container": name,
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "pci_control": rule.get("pci_control", ""),
                    "declared": expected_value,
                    "observed": observed_value,
                    "compliant": False
                }
                if rule.get("cwe"):
                    finding["cwe"] = rule["cwe"]
                    finding["cwe_rationale"] = rule.get("cwe_rationale", "")

                findings.append(finding)
                logger.warning(
                    f"VIOLATION: {name} failed rule '{rule['id']}' "
                    f"(expected {field}={expected_value}, got {observed_value})"
                )
            else:
                logger.info(f"PASS: {name} passed rule '{rule['id']}'")

    return findings


def evaluate_all(observed_state: dict[str, Any]) -> dict[str, Any]:
    """
    Run full policy evaluation across all policy files.
    Loads both container-policy.yaml and network-policy.yaml.
    """
    logger.info("Starting policy evaluation...")

    containers = observed_state["containers"]
    all_findings = []

    container_policy = load_policy("container-policy.yaml")
    all_findings.extend(evaluate_containers(containers, container_policy))

    try:
        network_policy = load_policy("network-policy.yaml")
        all_findings.extend(evaluate_containers(containers, network_policy))
    except FileNotFoundError:
        logger.warning("network-policy.yaml not found, skipping network evaluation")

    total = len(all_findings)
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    logger.info(
        f"Evaluation complete: {total} findings "
        f"(CRITICAL: {critical}, HIGH: {high}, MEDIUM: {medium})"
    )

    return {
        "findings": all_findings,
        "summary": {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "containers_scanned": len(containers),
        }
    }

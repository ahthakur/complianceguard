"""
Remediator module - Applies guided remediation to docker-compose.yml for compliance findings.

Reads the desired state from policies/container-hardening.yaml (the hardening baseline)
rather than a hardcoded map. This separates:
  - What to CHECK: container-policy.yaml + network-policy.yaml (audit rules)
  - What to FIX TO: container-hardening.yaml (desired state)
  - What IS deployed: docker-compose.yml (actual state)
"""

import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any
from opentelemetry import trace

import yaml

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

COMPOSE_FILE = Path(__file__).parent.parent / "docker-compose.yml"
HARDENING_FILE = Path(__file__).parent.parent / "policies" / "container-hardening.yaml"
REMEDIATION_LOG = Path(__file__).parent.parent / "reports" / "remediation-audit.log"

# Maps rule IDs to the compose field they remediate and how.
# "source" tells the remediator which hardening baseline key to read the target value from.
# "action" is the type of fix: "set" overwrites, "remove" deletes a key,
# "remove_from_list" removes an item, "remove_port" removes a port binding.
REMEDIATION_MAP = {
    "no-privileged-containers": {
        "field": "privileged",
        "source": "privileged",
        "action": "set",
        "description": "Set privileged: false to remove host kernel access",
        "requires_restart": True,
    },
    "read-only-root-filesystem": {
        "field": "read_only",
        "source": "read_only",
        "action": "set",
        "description": "Set read_only: true to prevent filesystem modification",
        "requires_restart": True,
    },
    "drop-all-capabilities": {
        "field": "cap_drop",
        "source": "cap_drop",
        "action": "set",
        "description": "Add cap_drop: [ALL] to remove all Linux capabilities",
        "requires_restart": True,
    },
    "no-new-privileges": {
        "field": "security_opt",
        "source": "security_opt",
        "action": "set",
        "description": "Add no-new-privileges:true to prevent privilege escalation",
        "requires_restart": True,
    },
    "no-added-capabilities": {
        "field": "cap_add",
        "source": "cap_add",
        "action": "set",
        "description": "Remove all added capabilities",
        "requires_restart": True,
    },
    "no-host-network": {
        "field": "network_mode",
        "source": "network_mode",
        "action": "set",
        "description": "Remove host network mode to restore container network isolation",
        "requires_restart": True,
    },
    "no-host-pid": {
        "field": "pid",
        "source": "pid_mode",
        "action": "remove_if_host",
        "description": "Remove host PID namespace to restore process isolation",
        "requires_restart": True,
    },
    "no-docker-socket-mount": {
        "field": "volumes",
        "action": "remove_from_list",
        "match": "/var/run/docker.sock",
        "description": "Remove Docker socket mount to prevent host API access",
        "requires_restart": True,
    },
    "no-exposed-sensitive-ports": {
        "field": "ports",
        "action": "remove_sensitive_ports",
        "description": "Remove exposed sensitive ports (database/cache)",
        "requires_restart": True,
    },
    "memory-limit-required": {
        "field": "deploy",
        "action": "set_memory_limit",
        "source": "memory_limit",
        "description": "Set a memory limit to prevent resource exhaustion",
        "requires_restart": True,
    },
}


def load_hardening_baseline() -> dict[str, Any]:
    """Load the hardening baseline that defines desired state per service."""
    if not HARDENING_FILE.exists():
        logger.warning(f"Hardening baseline not found at {HARDENING_FILE}, using built-in defaults")
        return {"defaults": {}, "overrides": {}}
    with open(HARDENING_FILE, "r") as f:
        return yaml.safe_load(f)


def get_hardened_value(service_name: str, key: str) -> Any:
    """Get the desired value for a field from the hardening baseline."""
    baseline = load_hardening_baseline()
    defaults = baseline.get("defaults", {})
    overrides = baseline.get("overrides", {}).get(service_name, {})
    if key in overrides:
        return overrides[key]
    return defaults.get(key)


def load_compose_file() -> dict[str, Any]:
    if not COMPOSE_FILE.exists():
        raise FileNotFoundError(f"docker-compose.yml not found at {COMPOSE_FILE}")
    with open(COMPOSE_FILE, "r") as f:
        return yaml.safe_load(f)


def save_compose_file(compose_data: dict[str, Any]) -> None:
    with open(COMPOSE_FILE, "w") as f:
        yaml.dump(compose_data, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)
    logger.info("docker-compose.yml updated successfully")


def preview_remediation(rule_id: str, container_name: str) -> dict[str, Any]:
    """Generate a dry-run preview of the remediation without applying changes."""
    service_name = container_name.replace("cg-", "", 1)

    if rule_id not in REMEDIATION_MAP:
        return {
            "supported": False,
            "message": (
                f"No automated remediation available for rule '{rule_id}'. "
                f"Supported rules: {', '.join(REMEDIATION_MAP.keys())}"
            )
        }

    recipe = REMEDIATION_MAP[rule_id]
    compose_data = load_compose_file()
    services = compose_data.get("services", {})

    if service_name not in services:
        return {
            "supported": False,
            "message": (
                f"Service '{service_name}' not found in docker-compose.yml. "
                f"Available services: {', '.join(services.keys())}"
            )
        }

    service = services[service_name]
    action = recipe.get("action", "set")

    if action == "set":
        current_value = service.get(recipe["field"])
        proposed_value = get_hardened_value(service_name, recipe["source"])
        if proposed_value is None:
            proposed_value = recipe.get("fallback_value")
        already_compliant = current_value == proposed_value
    elif action == "remove_if_host":
        current_value = service.get("pid", "")
        proposed_value = "(remove pid field)"
        already_compliant = current_value == "" or "pid" not in service
    elif action == "remove_from_list":
        current_list = service.get(recipe["field"], [])
        match = recipe["match"]
        matching = [v for v in current_list if match in v]
        current_value = matching if matching else []
        proposed_value = "(remove matching entries)"
        already_compliant = len(matching) == 0
    elif action == "remove_sensitive_ports":
        baseline = load_hardening_baseline()
        sensitive = baseline.get("defaults", {}).get("sensitive_ports_deny", [])
        current_ports = service.get("ports", [])
        flagged = [p for p in current_ports if _port_matches_sensitive(p, sensitive)]
        current_value = flagged if flagged else []
        proposed_value = "(remove sensitive port mappings)"
        already_compliant = len(flagged) == 0
    elif action == "set_memory_limit":
        deploy = service.get("deploy", {})
        resources = deploy.get("resources", {})
        limits = resources.get("limits", {})
        current_value = limits.get("memory")
        proposed_value = get_hardened_value(service_name, recipe["source"]) or "256m"
        already_compliant = current_value is not None
    else:
        current_value = None
        proposed_value = None
        already_compliant = False

    return {
        "supported": True,
        "rule_id": rule_id,
        "container": container_name,
        "service_name": service_name,
        "field": recipe["field"],
        "current_value": current_value,
        "proposed_value": proposed_value,
        "description": recipe["description"],
        "requires_restart": recipe["requires_restart"],
        "already_compliant": already_compliant,
    }


def _port_matches_sensitive(port_entry: str, sensitive_ports: list[int]) -> bool:
    """Check if a compose port mapping exposes a sensitive port."""
    port_str = str(port_entry)
    for sp in sensitive_ports:
        if f":{sp}" in port_str or port_str.startswith(f"{sp}:") or port_str == str(sp):
            return True
    return False


def apply_remediation(rule_id: str, container_name: str) -> dict[str, Any]:
    """Apply the approved remediation to docker-compose.yml and restart the container."""
    with tracer.start_as_current_span(
        "remediation.apply",
        kind=trace.SpanKind.INTERNAL,
    ) as span:
        span.set_attribute("remediation.rule_id", rule_id)
        span.set_attribute("remediation.container", container_name)

        preview = preview_remediation(rule_id, container_name)

        if not preview["supported"]:
            span.set_attribute("remediation.outcome", "unsupported")
            span.set_attribute("remediation.changed", False)
            return {"success": False, "message": preview["message"]}

        if preview["already_compliant"]:
            span.set_attribute("remediation.outcome", "already_compliant")
            span.set_attribute("remediation.changed", False)
            return {
                "success": True,
                "message": f"{container_name} is already compliant for rule '{rule_id}'. No changes needed.",
                "changed": False
            }

        compose_data = load_compose_file()
        service_name = preview["service_name"]
        recipe = REMEDIATION_MAP[rule_id]
        service = compose_data["services"][service_name]
        action = recipe.get("action", "set")

        span.set_attribute("remediation.field", recipe["field"])
        span.set_attribute("remediation.old_value", str(preview["current_value"]))
        span.set_attribute("remediation.new_value", str(preview["proposed_value"]))

        if action == "set":
            new_value = get_hardened_value(service_name, recipe["source"])
            if new_value is None:
                new_value = recipe.get("fallback_value")
            if recipe["field"] == "network_mode" and new_value == "default":
                service.pop("network_mode", None)
            else:
                service[recipe["field"]] = new_value

        elif action == "remove_if_host":
            service.pop("pid", None)

        elif action == "remove_from_list":
            current_list = service.get(recipe["field"], [])
            match = recipe["match"]
            service[recipe["field"]] = [v for v in current_list if match not in v]
            if not service[recipe["field"]]:
                del service[recipe["field"]]

        elif action == "remove_sensitive_ports":
            baseline = load_hardening_baseline()
            sensitive = baseline.get("defaults", {}).get("sensitive_ports_deny", [])
            current_ports = service.get("ports", [])
            service["ports"] = [p for p in current_ports if not _port_matches_sensitive(p, sensitive)]
            if not service["ports"]:
                del service["ports"]

        elif action == "set_memory_limit":
            mem_value = get_hardened_value(service_name, recipe["source"]) or "256m"
            if "deploy" not in service:
                service["deploy"] = {}
            if "resources" not in service["deploy"]:
                service["deploy"]["resources"] = {}
            if "limits" not in service["deploy"]["resources"]:
                service["deploy"]["resources"]["limits"] = {}
            service["deploy"]["resources"]["limits"]["memory"] = mem_value

        save_compose_file(compose_data)

        span.add_event("compose_file_modified", attributes={
            "service": service_name,
            "field": recipe["field"],
        })

        log_remediation_event(
            rule_id=rule_id,
            container=container_name,
            field=recipe["field"],
            old_value=preview["current_value"],
            new_value=preview["proposed_value"],
            status="applied"
        )

        with tracer.start_as_current_span("remediation.restart_container") as restart_span:
            restart_span.set_attribute("container.name", container_name)
            restart_result = restart_container(container_name)
            restart_span.set_attribute("restart.success", restart_result["success"])
            if not restart_result["success"]:
                restart_span.set_status(
                    trace.Status(trace.StatusCode.ERROR, "Container restart failed")
                )

        span.set_attribute("remediation.changed", True)
        span.set_attribute("remediation.outcome", "applied")
        span.set_attribute("remediation.restart_success", restart_result["success"])

        if restart_result["success"]:
            message = (
                f"Remediation applied successfully.\n"
                f"Changed {recipe['field']} for {container_name}.\n"
                f"Old: {preview['current_value']}\n"
                f"New: {preview['proposed_value']}\n"
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
            "new_value": preview["proposed_value"],
            "restart_success": restart_result["success"],
            "message": message
        }


def restart_container(container_name: str) -> dict[str, Any]:
    """Restart a specific container using docker compose."""
    service_name = container_name.replace("cg-", "", 1)
    logger.info(f"Restarting container: {container_name} (service: {service_name})")

    try:
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--no-deps", service_name],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(COMPOSE_FILE.parent)
        )
        if result.returncode == 0:
            logger.info(f"Container {container_name} restarted successfully")
            return {"success": True}
        else:
            error = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Container restart failed: {error}")
            return {"success": False, "error": error}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Container restart timed out after 60 seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def log_remediation_event(
    rule_id: str,
    container: str,
    field: str,
    old_value: Any,
    new_value: Any,
    status: str
) -> None:
    """Write a remediation event to the audit log file."""
    REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().isoformat() + "Z"
    log_entry = (
        f"{timestamp} | REMEDIATION | {status.upper()} | "
        f"container={container} | rule={rule_id} | "
        f"field={field} | old={old_value} | new={new_value}\n"
    )
    with open(REMEDIATION_LOG, "a") as f:
        f.write(log_entry)
    logger.info(f"Remediation event logged: {log_entry.strip()}")

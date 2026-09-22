"""Scanner module - Queries live Docker state and returns observed configuration."""

# Standard library imports
import logging                    # Python built-in logging framework for recording what the agent does
from typing import Any            # Type hint helper: Any means a variable can hold any data type

# Third-party imports
import docker                     # Docker SDK for Python: lets us talk to the Docker engine via Python code

# Create a logger for this specific module
# __name__ gives it the module name (agent.scanner) so log messages show where they came from
logger = logging.getLogger(__name__)


def get_docker_client() -> docker.DockerClient:
    """
    Create and return a connected Docker client.
    The client is our communication channel to the Docker engine running on this machine.
    Returns a DockerClient object if successful, raises RuntimeError if Docker is unreachable.
    """
    try:
        client = docker.from_env()    # Read Docker connection settings from environment variables
                                      # On Mac this connects to Docker Desktop via the local socket
        client.ping()                 # Send a test request to Docker to confirm the connection works
                                      # Raises an exception immediately if Docker is not running
        return client                 # Return the connected client for use by other functions

    except Exception as e:
        # If Docker is not running or unreachable, raise a clear error message
        # This stops the agent early with a helpful message rather than a cryptic failure later
        raise RuntimeError(f"Cannot connect to Docker: {e}")


def scan_containers() -> list[dict[str, Any]]:
    """
    Query all ComplianceGuard-managed containers and return their observed state.
    We only scan containers that have the label complianceguard.managed=true
    so we do not accidentally scan unrelated containers on the same machine.
    Returns a list of dictionaries, one per container, with all security-relevant fields.
    """
    client = get_docker_client()      # Get a connected Docker client
    results = []                      # Empty list that will hold one dict per container

    try:
        # Ask Docker for all containers (running AND stopped) that have our management label
        # all=True means include stopped/crashed containers, not just running ones
        # filters restricts to only containers we manage, ignoring everything else on the machine
        containers = client.containers.list(
            all=True,
            filters={"label": "complianceguard.managed=true"}
        )

        # Loop through each managed container and extract its security configuration
        for container in containers:

            # attrs is the full raw JSON response from Docker for this container
            # It contains everything Docker knows about the container
            attrs = container.attrs

            # HostConfig contains the security and resource settings applied when the container started
            # This is where privileged mode, capabilities, and read-only settings live
            host_config = attrs.get("HostConfig", {})    # Use empty dict as default if missing

            # Config contains the container image settings like labels and environment variables
            config = attrs.get("Config", {})              # Use empty dict as default if missing

            # Build a clean, structured dictionary of only the fields we care about for compliance
            # This is the observed state: what is actually running, not what we declared
            # Extract bind mounts (host paths mounted into the container)
            binds = host_config.get("Binds") or []
            mount_sources = [b.split(":")[0] for b in binds if ":" in b]

            # Extract port numbers from port bindings (e.g. "6379/tcp" -> 6379)
            port_bindings = host_config.get("PortBindings") or {}
            exposed_port_numbers = []
            for port_key in port_bindings:
                if port_bindings[port_key]:
                    try:
                        exposed_port_numbers.append(int(port_key.split("/")[0]))
                    except ValueError:
                        pass

            observed = {
                "container_id": container.short_id,
                "name": container.name,
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "status": container.status,
                "labels": config.get("Labels", {}),
                "privileged": host_config.get("Privileged", False),
                "read_only": host_config.get("ReadonlyRootfs", False),
                "network_mode": host_config.get("NetworkMode", "default"),
                "security_opt": host_config.get("SecurityOpt") or [],
                "cap_drop": host_config.get("CapDrop") or [],
                "cap_add": host_config.get("CapAdd") or [],
                "ports": list(attrs.get("NetworkSettings", {})
                              .get("Ports", {}).keys()),
                "exposed_ports": exposed_port_numbers,
                "mounts": mount_sources,
                "memory_limit": host_config.get("Memory", 0),
                "pid_mode": host_config.get("PidMode", ""),
                "user": config.get("User", ""),
                "running": container.status == "running",
            }

            # Add this container's observed state to our results list
            results.append(observed)

            # Log that we successfully scanned this container
            # This creates an audit trail of what the agent scanned and when
            logger.info(f"Scanned container: {container.name} ({container.status})")

    except Exception as e:
        # Log the error with full details for debugging
        logger.error(f"Error scanning containers: {e}")
        # Re-raise the exception so the main orchestrator knows the scan failed
        raise

    finally:
        # Always close the Docker client connection when done
        # This releases the connection regardless of whether an error occurred
        client.close()

    return results              # Return the list of all scanned container states


def scan_all() -> dict[str, Any]:
    """
    Run the full infrastructure scan and return a structured observed state dictionary.
    This is the main entry point called by the evaluator.
    Currently scans containers. Designed to be extended with network and RBAC scanning.
    Returns a dict with a containers key holding the list of observed container states.
    """
    logger.info("Starting infrastructure scan...")    # Log scan start for audit trail

    # Build the observed state dictionary
    # Structured this way so we can add network_state and rbac_state later
    # without breaking anything that already reads containers
    observed_state = {
        "containers": scan_containers(),    # Run the container scan and store results
    }

    # Calculate summary statistics for the log output
    total = len(observed_state["containers"])                           # Total managed containers found
    running = sum(1 for c in observed_state["containers"] if c["running"])  # How many are actually running

    # Log the scan summary so operators know what was found
    logger.info(f"Scan complete: {total} managed containers found, {running} running")

    return observed_state    # Return the full observed state for the evaluator to process

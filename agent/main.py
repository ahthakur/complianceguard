"""ComplianceGuard Agent - Main orchestrator. Coordinates scanning, evaluation, classification and reporting."""

# Standard library imports
import logging                      # For configuring the root logger used by all modules
import os                           # For reading environment variables
import sys                          # For exiting with a non-zero code on failure

# Third-party imports
from dotenv import load_dotenv      # For loading .env file into environment variables

# Load .env before importing agent modules so module-level os.getenv() calls
# (e.g. ANTHROPIC_API_KEY in classifier.py) pick up the values from .env
load_dotenv()

# Internal module imports — the four pipeline stages
from agent.scanner import scan_all
from agent.evaluator import evaluate_all
from agent.classifier import classify_all
from agent.reporter import generate_report


def configure_logging() -> None:
    """
    Configure the root logger for the entire agent.
    All modules use logging.getLogger(__name__) which inherits this configuration.
    """
    logging.basicConfig(
        level=logging.INFO,                         # Show INFO and above (INFO, WARNING, ERROR)
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",  # Timestamp + level + module
        datefmt="%Y-%m-%d %H:%M:%S",               # Human-readable timestamp format
    )


def main() -> None:
    """
    Run one full ComplianceGuard scan cycle:
    1. Load environment variables from .env
    2. Scan live Docker infrastructure
    3. Evaluate observed state against declared policy
    4. Classify findings with Claude AI
    5. Generate and save the audit report
    """
    # Configure logging before anything else so all modules log consistently
    configure_logging()

    logger = logging.getLogger(__name__)
    logger.info("ComplianceGuard agent starting...")

    try:
        # Step 1: Scan live Docker infrastructure
        # Returns observed state dict: {"containers": [...]}
        logger.info("Phase 1/4: Scanning infrastructure...")
        observed = scan_all()

        # Step 2: Evaluate observed state against declared policy
        # Returns evaluation result dict: {"findings": [...], "summary": {...}}
        logger.info("Phase 2/4: Evaluating policy compliance...")
        evaluated = evaluate_all(observed)

        # Step 3: Classify findings with Claude AI
        # Returns classified result dict with AI-enriched findings
        logger.info("Phase 3/4: Classifying findings with Claude AI...")
        classified = classify_all(evaluated)

        # Step 4: Generate, save, and display the audit report
        # Returns the file path where the report was saved
        logger.info("Phase 4/4: Generating audit report...")
        report_path = generate_report(classified)

        logger.info(f"ComplianceGuard run complete. Report: {report_path}")

        # Exit with code 1 if there are any findings so CI/CD pipelines can detect non-compliance
        # Exit code 0 means fully compliant, exit code 1 means violations were found
        total = classified["summary"].get("total_findings", 0)
        sys.exit(1 if total > 0 else 0)

    except Exception as e:
        logger.error(f"Agent run failed: {e}")
        sys.exit(2)                             # Exit code 2 signals an agent execution error


if __name__ == "__main__":
    main()

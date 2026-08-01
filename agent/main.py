"""ComplianceGuard Agent - Main orchestrator."""

import logging
import os
import sys

from datetime import datetime

# Only the trace API is needed here. NOT the SDK classes -
# those live in observability.py and are already wired up.
from opentelemetry import trace

from dotenv import load_dotenv
load_dotenv()

from agent.scanner import scan_all
from agent.evaluator import evaluate_all
from agent.classifier import classify_all
from agent.reporter import generate_report

# lowercase 'observability' to match the filename
from agent.observability import initialize_observability, shutdown_observability
# Get a tracer ONCE at module level. This is the object you use
# to create spans. It works because observability.py registered
# the global TracerProvider.
tracer = trace.get_tracer(__name__)
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("opentelemetry").setLevel(logging.WARNING)


def main() -> None:
    # Order matters: logging first, then telemetry, then get the logger.
    configure_logging()
    initialize_observability()              # just call it, no return value
    logger = logging.getLogger(__name__)    # define logger BEFORE using it
    logger.info("ComplianceGuard agent starting...")
    # We capture the exit code in a variable and call sys.exit() at the
    # very end, AFTER the spans close and telemetry is flushed. This avoids
    # SystemExit propagating up through the open spans.
    exit_code = 0

    try:
        # ROOT SPAN: wraps the entire agent run. Everything nested inside
        # this 'with' block becomes a child of this span automatically.
        with tracer.start_as_current_span("compliance.run") as root_span:

            # --- Phase 1: Scan ---
            # This 'with' is nested inside the root span's block, so OTel
            # makes "compliance.scan" a child of "compliance.run".
            with tracer.start_as_current_span("compliance.scan") as span:
                logger.info("Phase 1/4: Scanning infrastructure...")
                observed = scan_all()
                # set_attribute is the correct way to add context to a span
                span.set_attribute("containers.scanned", len(observed.get("containers", [])))

            # --- Phase 2: Evaluate ---
            with tracer.start_as_current_span("compliance.evaluate") as span:
                logger.info("Phase 2/4: Evaluating policy compliance...")
                evaluated = evaluate_all(observed)
                span.set_attribute("findings.count", len(evaluated.get("findings", [])))

            # --- Phase 3: Classify ---
            with tracer.start_as_current_span("compliance.classify") as span:
                logger.info("Phase 3/4: Classifying findings with Claude AI...")
                classified = classify_all(evaluated)

            # --- Phase 4: Report ---
            with tracer.start_as_current_span("compliance.report") as span:
                logger.info("Phase 4/4: Generating audit report...")
                report_path = generate_report(classified)
                span.set_attribute("report.path", str(report_path))

            # Add a summary attribute to the ROOT span
            total = classified["summary"].get("total_findings", 0)
            root_span.set_attribute("findings.total", total)
            logger.info(f"ComplianceGuard run complete. Report: {report_path}")

            exit_code = 1 if total > 0 else 0

    except Exception as e:
        logger.error(f"Agent run failed: {e}")
        exit_code = 2
    finally:
        # Runs no matter what: success, violations, or error.
        # Flushes all buffered telemetry before the process ends.
        shutdown_observability()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
    
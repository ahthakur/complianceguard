"""
Classifier module - Sends compliance findings to the Claude API for AI-powered analysis.
This is the agentic AI layer of ComplianceGuard. It takes raw findings from the evaluator
and enriches each one with: a plain-English attack scenario, business risk explanation,
specific remediation steps, and confirmation of the PCI-DSS control mapping.
The Claude API acts as a security expert reasoning over each finding.
"""

# Standard library imports
import logging                      # For recording classifier activity in the audit trail
import os                           # For reading the API key from environment variables
import json                         # For parsing Claude API responses and formatting prompts
from typing import Any              # Type hint: Any means a variable can hold any data type

# Third-party imports
import anthropic                    # Official Anthropic Python SDK for calling the Claude API

# Create a logger for this module
logger = logging.getLogger(__name__)

# Read the Anthropic API key from the environment
# This must be set before running the agent: export ANTHROPIC_API_KEY=your-key
# We never hardcode API keys in source code: that would be a PCI-DSS violation itself
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# The Claude model to use for classification
# claude-3-5-haiku-20241022 is fast and cost-effective for structured analysis tasks
# Using a constant makes it easy to upgrade the model in one place
MODEL = "claude-haiku-4-5-20251001"


def build_classification_prompt(finding: dict[str, Any]) -> str:
    """
    Build a structured prompt for Claude to analyze a single compliance finding.
    finding: a single finding dictionary from the evaluator
    Returns a string prompt that instructs Claude to act as a security expert
    and produce a structured JSON analysis of the finding.
    """
    # Build the prompt as a multi-line string
    # We instruct Claude to return only JSON so we can parse the response reliably
    # The prompt includes all finding context so Claude has full information to reason over
    return f"""You are a senior security engineer and PCI-DSS compliance expert.
Analyze this compliance finding and respond with ONLY a valid JSON object, no other text.

Finding details:
- Container: {finding['container']}
- Rule violated: {finding['rule_id']}
- Description: {finding['description']}
- Severity: {finding['severity']}
- PCI-DSS Control: {finding['pci_control']}
- Declared (expected): {finding['declared']}
- Observed (actual): {finding['observed']}

Respond with exactly this JSON structure:
{{
    "attack_scenario": "A specific 2-3 sentence description of how an attacker could exploit this misconfiguration",
    "business_risk": "A specific 1-2 sentence explanation of the business and compliance risk",
    "remediation_steps": ["step 1", "step 2", "step 3"],
    "pci_requirement_detail": "One sentence explaining exactly which part of {finding['pci_control']} this violates",
    "estimated_fix_time": "e.g. 15 minutes, 1 hour, 1 day"
}}"""


def classify_finding(
    client: anthropic.Anthropic,
    finding: dict[str, Any]
) -> dict[str, Any]:
    """
    Send a single finding to the Claude API and return the enriched analysis.
    client: a connected Anthropic client instance (created once, reused for all findings)
    finding: a single finding dictionary from the evaluator
    Returns the original finding dictionary with AI analysis fields added.
    """
    # Log that we are classifying this specific finding
    logger.info(f"Classifying finding: {finding['rule_id']} on {finding['container']}")

    try:
        # Build the prompt for this specific finding
        prompt = build_classification_prompt(finding)

        # Call the Claude API with the classification prompt
        # We use the messages API which is the standard way to interact with Claude
        response = client.messages.create(
            model=MODEL,                    # Which Claude model to use
            max_tokens=1024,               # Maximum tokens in the response
                                           # 1024 is enough for structured JSON analysis
            messages=[
                {
                    "role": "user",        # We are the user sending the prompt
                    "content": prompt      # The full classification prompt we built above
                }
            ]
        )

        # Extract the text content from the API response
        # response.content is a list of content blocks
        # We take the first block and get its text attribute
        raw_response = response.content[0].text

        # Strip markdown code fences if the model wrapped the JSON in ```json ... ```
        # Some models return fenced code blocks even when instructed to return plain JSON
        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            # Remove the opening fence line (```json or ```) and the closing ```
            cleaned = cleaned.split("\n", 1)[-1]        # Drop the first line (```json)
            cleaned = cleaned.rsplit("```", 1)[0]       # Drop everything after the last ```
            cleaned = cleaned.strip()                   # Remove any surrounding whitespace

        # Parse the JSON response from Claude
        # Claude was instructed to return only JSON so this should parse cleanly
        # If Claude returns invalid JSON, the except block below handles it
        ai_analysis = json.loads(cleaned)

        # Create an enriched copy of the original finding with AI analysis added
        # We use dict unpacking (**finding) to copy all original fields
        # then add the new AI-generated fields on top
        enriched = {
            **finding,                                              # All original finding fields
            "attack_scenario": ai_analysis.get("attack_scenario", "N/A"),       # How it could be exploited
            "business_risk": ai_analysis.get("business_risk", "N/A"),           # Business impact
            "remediation_steps": ai_analysis.get("remediation_steps", []),      # How to fix it
            "pci_requirement_detail": ai_analysis.get("pci_requirement_detail", "N/A"),  # PCI detail
            "estimated_fix_time": ai_analysis.get("estimated_fix_time", "N/A"), # Time to fix
            "ai_classified": True                                   # Flag showing AI analysis was applied
        }

        # Log successful classification
        logger.info(f"Successfully classified: {finding['rule_id']} on {finding['container']}")

        return enriched                     # Return the enriched finding

    except json.JSONDecodeError as e:
        # Claude returned something that could not be parsed as JSON
        # Log the error and return the original finding with a classification error note
        logger.error(f"Failed to parse Claude response as JSON: {e}")
        return {
            **finding,                      # Keep all original finding fields
            "ai_classified": False,         # Flag showing AI classification failed
            "classification_error": str(e)  # Record what went wrong
        }

    except Exception as e:
        # Any other error (network issue, API error, rate limit, etc.)
        # Log it and return the original finding unmodified
        logger.error(f"Classification error for {finding['rule_id']}: {e}")
        return {
            **finding,
            "ai_classified": False,
            "classification_error": str(e)
        }


def classify_all(evaluation_result: dict[str, Any]) -> dict[str, Any]:
    """
    Run AI classification on all findings from the evaluator.
    evaluation_result: the full output from evaluator.evaluate_all()
    Returns the evaluation result with all findings enriched by Claude AI analysis.
    This is the main entry point called by main.py.
    """
    # Check that the API key is available before trying to make API calls
    # Fail fast with a clear error rather than letting API calls fail silently
    if not ANTHROPIC_API_KEY:
        raise ValueError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Copy .env.example to .env and add your API key."
        )

    # Create a single Anthropic client instance to reuse for all API calls
    # Creating one client and reusing it is more efficient than creating one per finding
    # The client reads ANTHROPIC_API_KEY from the environment automatically
    client = anthropic.Anthropic()

    # Get the list of findings from the evaluation result
    findings = evaluation_result.get("findings", [])

    # Log how many findings we are about to classify
    logger.info(f"Starting AI classification of {len(findings)} findings...")

    # Classify each finding by sending it to Claude
    # We process them sequentially to avoid rate limiting
    # Each call is independent so failures on one finding do not affect others
    classified_findings = []
    for i, finding in enumerate(findings):
        # Log progress so the user can see the agent is working
        logger.info(f"Classifying finding {i+1} of {len(findings)}...")

        # Classify this finding and add it to our results list
        classified = classify_finding(client, finding)
        classified_findings.append(classified)

    # Count how many findings were successfully classified by Claude
    successful = sum(1 for f in classified_findings if f.get("ai_classified"))

    # Log the classification summary
    logger.info(
        f"Classification complete: {successful}/{len(findings)} "
        f"findings successfully classified by AI"
    )

    # Build and return the complete classified result
    # We preserve the original summary and add classification metadata
    return {
        "findings": classified_findings,        # All findings now enriched with AI analysis
        "summary": {
            **evaluation_result["summary"],     # Preserve all original summary fields
            "ai_classified": successful,        # How many findings got AI analysis
        }
    }

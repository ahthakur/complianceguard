"""
Stability eval for ComplianceGuard.

Question this answers: given identical infrastructure and an identical prompt,
how much does the agent's output change from run to run, and which fields
are affected?

Method: scan and evaluate ONCE (both are deterministic Python, no API calls),
then send the same fixed set of findings through the classifier N times at
each temperature setting. Record every model-generated field for every run
and measure agreement.

Run from the repo root:
    python -m eval.stability_eval
    python -m eval.stability_eval --runs 5 --temps default,0.0
"""

import argparse
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

load_dotenv()

from agent.scanner import scan_all
from agent.evaluator import evaluate_all
from agent.classifier import classify_finding, MODEL

console = Console()

# The five fields the model actually generates. Everything else in a finding
# comes from evaluator.py via deterministic Python and cannot vary.
LLM_FIELDS = [
    "attack_scenario",
    "business_risk",
    "remediation_steps",
    "pci_requirement_detail",
    "estimated_fix_time",
]

# Fields where exact string match is a meaningful stability measure.
# Prose fields are tracked too, but near-zero exact agreement there is
# expected and is not by itself a defect.
SHORT_FIELDS = {"estimated_fix_time"}

# Fields that come from the evaluator, not the model. Measured as a control:
# these should be 100% stable, and if they are not, something is wrong with
# the harness rather than with the model.
CONTROL_FIELDS = ["rule_id", "severity", "pci_control", "container"]

OUT_DIR = Path("eval/results")


def finding_key(finding: dict) -> str:
    """Stable identifier for a finding across runs."""
    return f"{finding['container']}::{finding['rule_id']}"


def normalize(value):
    """Make a field value hashable and comparable across runs."""
    if isinstance(value, list):
        return json.dumps(value, sort_keys=True)
    return value


def run_once(client, findings, temperature, run_index):
    """Classify every finding once. Returns {finding_key: enriched_finding}."""
    def classify(f):
        return classify_finding(client, f, temperature=temperature)

    # Modest concurrency. Raise cautiously if you are on a higher API tier.
    with ThreadPoolExecutor(max_workers=3) as pool:
        enriched = list(pool.map(classify, findings))

    return {finding_key(f): f for f in enriched}


def analyze(runs, field_list):
    """
    runs: list of {finding_key: enriched_finding}, one entry per run.
    Returns per-field stats aggregated across all findings.
    """
    n_runs = len(runs)
    keys = sorted(runs[0].keys())

    stats = {}
    for field in field_list:
        identical_count = 0      # findings where all runs agreed exactly
        modal_rates = []         # per finding: most common value's share of runs
        distinct_counts = []     # per finding: how many different values appeared

        for key in keys:
            values = [normalize(run[key].get(field)) for run in runs]
            counts = Counter(values)
            distinct_counts.append(len(counts))
            modal_rates.append(counts.most_common(1)[0][1] / n_runs)
            if len(counts) == 1:
                identical_count += 1

        stats[field] = {
            "findings": len(keys),
            "fully_stable": identical_count,
            "fully_stable_pct": identical_count / len(keys) if keys else 0.0,
            "mean_modal_agreement": sum(modal_rates) / len(modal_rates) if modal_rates else 0.0,
            "mean_distinct_values": sum(distinct_counts) / len(distinct_counts) if distinct_counts else 0.0,
            "max_distinct_values": max(distinct_counts) if distinct_counts else 0,
        }
    return stats


def print_stats(label, stats, n_runs, field_list, title):
    table = Table(title=f"{title} — {label} (n={n_runs} runs)", box=box.ROUNDED)
    table.add_column("Field", style="cyan")
    table.add_column("Fully stable", justify="right")
    table.add_column("Modal agreement", justify="right")
    table.add_column("Distinct values (mean)", justify="right")
    table.add_column("Distinct (max)", justify="right")

    for field in field_list:
        s = stats[field]
        stable = f"{s['fully_stable']}/{s['findings']}"
        table.add_row(
            field,
            stable,
            f"{s['mean_modal_agreement']:.0%}",
            f"{s['mean_distinct_values']:.1f}",
            str(s["max_distinct_values"]),
        )
    console.print()
    console.print(table)


def print_fix_time_detail(runs):
    """The most legible evidence: show every fix-time value seen per finding."""
    table = Table(title="estimated_fix_time — every value observed", box=box.ROUNDED)
    table.add_column("Finding", style="cyan")
    table.add_column("Values across runs")

    for key in sorted(runs[0].keys()):
        values = [run[key].get("estimated_fix_time") for run in runs]
        counts = Counter(values)
        rendered = ", ".join(f"{v} (x{c})" for v, c in counts.most_common())
        table.add_row(key, rendered)

    console.print()
    console.print(table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10, help="runs per temperature setting")
    parser.add_argument("--temps", default="default,0.0",
                        help="comma-separated: 'default' for API default, or a float")
    args = parser.parse_args()

    # Quiet the agent's own logging so the harness output is readable.
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("agent").setLevel(logging.WARNING)

    if not os.getenv("ANTHROPIC_API_KEY"):
        console.print("[red]ANTHROPIC_API_KEY is not set.[/red]")
        sys.exit(1)

    # Deterministic phases: run once, reuse for every trial. This is the
    # whole point — the input to the model is frozen.
    console.print("[bold]Scanning and evaluating (deterministic, no API calls)...[/bold]")
    observed = scan_all()
    evaluated = evaluate_all(observed)
    findings = evaluated["findings"]

    if not findings:
        console.print("[yellow]No findings. Check that the drifted containers are running.[/yellow]")
        sys.exit(0)

    temps = []
    for t in args.temps.split(","):
        t = t.strip()
        temps.append(None if t == "default" else float(t))

    total_calls = len(findings) * args.runs * len(temps)
    console.print(
        f"{len(findings)} findings, {args.runs} runs, {len(temps)} temperature setting(s) "
        f"= [bold]{total_calls} API calls[/bold]"
    )

    client = anthropic.Anthropic()
    all_results = {}

    for temp in temps:
        label = "default (1.0)" if temp is None else f"temperature={temp}"
        console.print(f"\n[bold]Running {args.runs} trials at {label}...[/bold]")

        runs = []
        for i in range(args.runs):
            runs.append(run_once(client, findings, temp, i))
            console.print(f"  run {i + 1}/{args.runs} complete")

        llm_stats = analyze(runs, LLM_FIELDS)
        control_stats = analyze(runs, CONTROL_FIELDS)

        print_stats(label, control_stats, args.runs, CONTROL_FIELDS,
                    "Deterministic fields (control)")
        print_stats(label, llm_stats, args.runs, LLM_FIELDS,
                    "Model-generated fields")
        print_fix_time_detail(runs)

        all_results[label] = {
            "runs": args.runs,
            "model": MODEL,
            "llm_fields": llm_stats,
            "control_fields": control_stats,
            "raw": [
                {k: {f: v.get(f) for f in LLM_FIELDS} for k, v in run.items()}
                for run in runs
            ],
        }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = OUT_DIR / f"stability-{stamp}.json"
    with out_path.open("w") as f:
        json.dump(all_results, f, indent=2)

    console.print(f"\n[green]Raw results written to {out_path}[/green]")


if __name__ == "__main__":
    main()
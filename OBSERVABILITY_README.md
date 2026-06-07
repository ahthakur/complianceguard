# Observability (OpenTelemetry)

ComplianceGuard is instrumented end to end with [OpenTelemetry](https://opentelemetry.io/),
emitting **traces, metrics, and logs** for every agent run. This gives full
visibility into the agent's decision pipeline, including per-call LLM token
usage, latency, and cost.

## What is instrumented

The agent's four-stage pipeline is traced as a single distributed trace, with
each stage and each Claude API call captured as a nested span:

```
compliance.run                       (root span - full agent run)
├── compliance.scan                  (Docker container scan)
├── compliance.evaluate              (policy evaluation)
├── compliance.classify              (AI classification stage)
│   ├── llm.classify_finding         (Claude API call - finding 1)
│   ├── llm.classify_finding         (Claude API call - finding 2)
│   └── ... one span per finding
└── compliance.report                (report generation)
```

Each `llm.classify_finding` span (kind: CLIENT) carries:

- `llm.model` - the Claude model used
- `llm.input_tokens` / `llm.output_tokens` - token usage per call
- `llm.latency_ms` - call duration
- `llm.cost_usd` - estimated cost per call
- `finding.rule_id` / `finding.container` - which finding was classified

## Metrics

Four metrics are exported and aggregated across the run:

| Metric | Type | Purpose |
|--------|------|---------|
| `llm.tokens.input` | Counter | Total input tokens consumed |
| `llm.tokens.output` | Counter | Total output tokens generated |
| `llm.call.duration` | Histogram | Per-call latency (enables p50/p95/p99) |
| `llm.cost.usd` | Counter | Estimated total cost in USD |

All metrics are tagged with `model` so usage and cost can be broken down by
model in the dashboard.

## Architecture

```
ComplianceGuard agent
   (OpenTelemetry SDK)
        |  OTLP/gRPC
        v
   OTel Collector
        |
        +--- traces  --> Grafana Tempo
        +--- metrics --> Prometheus
                              |
                         Grafana (dashboards + trace waterfall)
```

The agent runs on the host and exports telemetry via OTLP to a local
OpenTelemetry Collector, which routes traces to Grafana Tempo and metrics to
Prometheus. Grafana provides the unified view: a trace waterfall and an LLM
observability dashboard.

This mirrors the **Grafana LGTM stack** (Loki, Grafana, Tempo, Mimir) used in
modern production observability setups.

## Running the observability backend

The backend (Collector, Tempo, Prometheus, Grafana) runs via Docker Compose:

```bash
cd cg-observability-backend
docker-compose up -d
```

Then run the agent as usual:

```bash
source venv/bin/activate
python -m agent.main
```

View the results in Grafana at `http://localhost:3001`:

- **Traces:** Explore > Tempo > Search to find the `compliance.run` trace and
  open the waterfall view.
- **Metrics:** Dashboards > ComplianceGuard > "Agent LLM Observability".

## Configuration

The agent exports to the Collector at `http://localhost:4317` by default.
Override with the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable.

Telemetry setup lives in `agent/observability.py`. It configures three
providers (traces, metrics, logs), each wired to an OTLP exporter. To switch
to console output for local debugging, swap the OTLP exporters for the console
exporters in that file.

## Why this matters

Distributed tracing surfaces insights that logs alone cannot. For example, the
trace waterfall immediately shows that the classification stage dominates total
runtime, and that the per-finding Claude API calls run sequentially. That makes
the optimization path obvious: parallelizing those calls would cut total
runtime substantially. As AI agents move into production, this kind of token,
cost, and latency observability becomes essential for operating them reliably
and economically.

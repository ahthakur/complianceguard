# ComplianceGuard

**AI-powered compliance drift detection agent with guided remediation for containerized infrastructure.**

ComplianceGuard continuously scans live Docker infrastructure against declarative YAML security policies, identifies drift between declared and observed state, classifies each violation using Claude AI, generates auditor-ready evidence reports mapped to PCI-DSS v4.0 controls, and provides guided remediation with dry-run approval workflows.

Built to demonstrate the core pattern behind modern security policy enforcement platforms: **policy as data, enforcement as code, evidence as output, remediation as a guided workflow.**

---

## What It Does

```
Declared state (YAML policies)
        │
        ▼
Phase 1 ── SCAN ──────── Queries live Docker container state
        │
        ▼
Phase 2 ── EVALUATE ──── Compares declared vs observed (drift detection)
        │
        ▼
Phase 3 ── CLASSIFY ──── Claude AI enriches each finding:
        │                  attack scenario, business risk,
        │                  PCI-DSS control mapping, remediation steps
        ▼
Phase 4 ── REPORT ─────── Generates JSON + HTML + PDF audit evidence
                           SHA-256 tamper detection hash included
                           Exit code 1 for CI/CD integration

Phase 5 ── REMEDIATE ──── Guided remediation via MCP server:
                           Dry-run preview → explicit approval → apply
                           Container restarted, audit log written
                           Re-scan confirms finding resolved
```

---

## Architecture

```
complianceguard/
├── policies/                    # Declared state: YAML policy files
│   ├── container-policy.yaml    # Container security rules
│   ├── network-policy.yaml      # Network access controls
│   └── rbac-policy.yaml         # Agent identity and access rules
│
├── agent/                       # The compliance agent
│   ├── main.py                  # Orchestrator: runs all four phases
│   ├── scanner.py               # Phase 1: queries live Docker state
│   ├── evaluator.py             # Phase 2: declared vs observed diff
│   ├── classifier.py            # Phase 3: Claude AI enrichment layer
│   ├── reporter.py              # Phase 4: report orchestrator
│   ├── remediator.py            # Phase 5: guided remediation engine
│   └── formatters/              # Output formatters (single responsibility)
│       ├── json_formatter.py    # Machine-readable audit evidence
│       ├── html_formatter.py    # Human-readable browser report
│       └── pdf_formatter.py     # Auditor-ready compliance document
│
├── mcp_server/                  # MCP server: Claude-queryable interface
│   └── server.py                # Six tools exposing compliance data and remediation
│
├── reports/
│   ├── _LastReport/             # Always contains the most recent run
│   ├── _Archive/                # All previous runs archived here
│   └── remediation-audit.log   # Append-only log of all applied remediations
│
└── docker-compose.yml           # Simulated infrastructure with intentional drift
```

---

## Policy as Declarative Config

Security rules are expressed as YAML data, not code. The agent reads the policy files and enforces them against live infrastructure. Changing what is allowed never requires touching the agent code.

```yaml
# policies/container-policy.yaml
rules:
  - id: no-privileged-containers
    description: "Containers must not run in privileged mode"
    severity: CRITICAL
    check:
      field: privileged
      operator: equals
      value: false
    pci_control: "PCI-DSS-v4.0-7.2.1"

  - id: drop-all-capabilities
    description: "Containers must drop all Linux capabilities"
    severity: HIGH
    check:
      field: cap_drop
      operator: contains
      value: "ALL"
    pci_control: "PCI-DSS-v4.0-7.2.1"
```

---

## AI Classification Layer

Each finding is sent to Claude AI which returns structured analysis:

```json
{
  "attack_scenario": "An attacker exploiting a vulnerability in the container could gain privileged access to the host kernel, allowing them to escape the container sandbox and compromise the entire underlying infrastructure.",
  "business_risk": "Running containers in privileged mode violates PCI-DSS access control requirements and significantly increases the blast radius of any container compromise.",
  "remediation_steps": [
    "Remove the 'privileged: true' flag from the container runtime configuration",
    "Replace privileged mode with specific Linux capabilities using CAP_ADD and CAP_DROP",
    "Redeploy the container with the updated configuration and validate functionality"
  ],
  "pci_requirement_detail": "PCI-DSS-v4.0-7.2.1 requires least privilege access for all system components to minimize the attack surface.",
  "estimated_fix_time": "30 minutes"
}
```

---

## MCP Server: Query and Remediate Conversationally

ComplianceGuard includes an MCP (Model Context Protocol) server that exposes compliance data and guided remediation as tools Claude can call conversationally.

### Available Tools

| Tool | Description |
|---|---|
| `get_last_report` | Returns full findings from the most recent scan with AI analysis |
| `get_findings_by_severity` | Filters findings by CRITICAL, HIGH, or MEDIUM |
| `get_container_status` | Returns live observed state for a specific container |
| `run_compliance_scan` | Triggers a fresh full compliance scan |
| `preview_remediation` | Dry-run: shows exact docker-compose.yml diff without applying |
| `apply_remediation` | Applies an approved fix, restarts container, logs to audit trail |

### Guided Remediation Workflow

```
You: Show me the remediation plan for the privileged container finding on cg-api-service

Claude: [calls preview_remediation("no-privileged-containers", "cg-api-service")]

        DRY-RUN REMEDIATION PREVIEW
        Container:   cg-api-service
        Rule:        no-privileged-containers

        Proposed change to docker-compose.yml:
          BEFORE:  privileged: True
          AFTER:   privileged: False

        Container restart required: True
        NO CHANGES HAVE BEEN APPLIED.

You: Apply the remediation for cg-api-service

Claude: [calls apply_remediation("no-privileged-containers", "cg-api-service")]

        Remediation applied successfully.
        privileged set to False in docker-compose.yml.
        Container restarted.
        Change logged to reports/remediation-audit.log.

You: Run a new compliance scan and tell me if cg-api-service is still flagged

Claude: [calls run_compliance_scan(), then get_last_report()]

        cg-api-service has zero findings. Remediation confirmed successful.
        7 findings remain on other containers.
```

### Remediation Audit Trail

Every applied remediation is appended to `reports/remediation-audit.log`:

```
2026-04-19T01:23:45Z | REMEDIATION | APPLIED | container=cg-api-service | rule=no-privileged-containers | field=privileged | old=True | new=False
```

This log is append-only and serves as a compliance evidence artifact.

### Connect to Claude Code

Add this to `~/.claude.json`:

```json
{
  "mcpServers": {
    "complianceguard": {
      "command": "/opt/homebrew/Cellar/python@3.11/3.11.15/Frameworks/Python.framework/Versions/3.11/bin/python3.11",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/complianceguard",
      "env": {
        "ANTHROPIC_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

---

## PCI-DSS v4.0 Control Mapping

Every finding is tagged to a specific PCI-DSS v4.0 control. The evidence pipeline produces auditor-ready exports that map directly to compliance requirements.

| Control | Requirement | Enforced By |
|---|---|---|
| PCI-DSS-v4.0-7.2.1 | Least privilege for all system components | Privileged mode check, capability drop check |
| PCI-DSS-v4.0-2.2.1 | Secure configuration of system components | no-new-privileges check, read-only filesystem check |
| PCI-DSS-v4.0-1.3.1 | Network access controls | Host network mode check |
| PCI-DSS-v4.0-1.3.2 | Sensitive port restrictions | Exposed port scan |

---

## Tamper-Evident Audit Reports

Every report includes a SHA-256 hash of its content. If a report is modified after generation, the hash no longer matches.

```
SHA-256: 75b39187c2eb9ec2d649462014b609ec9aff84c601e12fa112cd1b28daba1c80
Verify: recompute SHA-256 of report content (excluding hash field) and compare
```

---

## Quick Start

### Prerequisites

- Docker Desktop
- Python 3.9+
- Anthropic API key (get one at console.anthropic.com)

### Setup

```bash
# Clone the repository
git clone https://github.com/ahthakur/complianceguard.git
cd complianceguard

# Install dependencies
pip3 install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Start the simulated infrastructure
docker compose up -d

# Run the compliance agent
export $(cat .env | grep -v '#' | xargs)
python3 -m agent.main
```

### View Reports

```bash
# Open the HTML report in your browser
open reports/_LastReport/*.html

# Open the PDF report
open reports/_LastReport/*.pdf
```

---

## Simulated Infrastructure

The included `docker-compose.yml` spins up four containers with intentional misconfigurations to demonstrate drift detection:

| Container | Intentional Drift | Expected Findings |
|---|---|---|
| cg-api-service | `privileged: true` | CRITICAL: privileged mode |
| cg-data-processor | Privileged, no security opts, no cap_drop | CRITICAL + multiple HIGH |
| cg-legacy-service | No security hardening applied | Multiple HIGH and MEDIUM |
| cg-audit-logger | Fully compliant baseline | Zero findings |

---

## Report Output

Each run produces three files in `reports/_LastReport/`:

- **`CG-YYYYMMDD-HHMMSS.json`** Machine-readable audit evidence with full AI analysis
- **`CG-YYYYMMDD-HHMMSS.html`** Color-coded browser report with severity badges and findings table
- **`CG-YYYYMMDD-HHMMSS.pdf`** Professional compliance document suitable for auditors

Previous reports are automatically moved to `reports/_Archive/` on each run.

---

## CI/CD Integration

The agent exits with code `1` when violations are found and `0` when fully compliant:

```bash
python3 -m agent.main
if [ $? -ne 0 ]; then
  echo "Compliance violations detected. Blocking deployment."
  exit 1
fi
```

---

## Design Decisions

**Why declarative YAML policies?**
Separating policy (data) from enforcement (code) means security rules can be updated without touching the agent. The same pattern used by OPA, Kyverno, and Istio authorization policies.

**Why Claude AI for classification?**
Rule-based scanners detect drift but cannot explain risk in business terms or suggest specific remediation. The AI layer transforms raw findings into actionable intelligence: attack scenarios, compliance implications, and step-by-step fixes with time estimates.

**Why dry-run before apply for remediation?**
Security changes should never be applied without explicit human approval. The preview step shows the exact diff in docker-compose.yml before any change is made. The apply step requires a separate explicit confirmation. This is the guided remediation pattern: show, approve, apply, verify.

**Why an MCP server?**
The MCP server layer decouples the compliance data from how it is consumed. Security engineers can query findings and trigger remediations conversationally through Claude rather than running commands or reading raw JSON files.

**Why SHA-256 hashing?**
Compliance evidence must be tamper-evident. If a report can be modified after generation, it cannot be trusted as an audit artifact. The hash provides mathematical proof that the report content has not changed since it was produced.

**Why separate formatters?**
Each output format (JSON, HTML, PDF) is handled by a dedicated module following the single responsibility principle. Adding a new format means adding one file without touching existing code.

**Why exit code 1 on violations?**
Standard Unix convention for security scanners. Enables CI/CD pipelines to treat compliance violations as deployment blockers without any additional configuration.

---

## Backlog

- **Formatter refactor:** Move formatter classes into a proper plugin architecture
- **Network and RBAC scanning:** Extend scanner and evaluator to cover network policy drift and RBAC permission drift (policy files already exist)
- **Scheduled continuous monitoring:** Run the agent on a defined interval using the included schedule dependency
- **Vault integration:** Replace simulated secrets with HashiCorp Vault dynamic secrets for agent authentication
- **Webhook alerts:** Post findings to Slack or PagerDuty when CRITICAL violations are detected

---

## Tech Stack

| Component | Technology |
|---|---|
| Agent runtime | Python 3.9+ |
| Infrastructure simulation | Docker Compose |
| AI classification | Anthropic Claude API (claude-3-5-haiku) |
| MCP server | FastMCP (mcp 1.27.0) |
| Policy format | YAML |
| Terminal output | Rich |
| HTML reports | Self-contained HTML/CSS |
| PDF reports | fpdf2 |
| Tamper detection | SHA-256 (hashlib) |

---

## License

MIT

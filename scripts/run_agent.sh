#!/bin/bash
set -e
echo "Starting ComplianceGuard Agent..."
if [ -f .env ]; then
  export $(cat .env | grep -v '#' | xargs)
fi
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "ERROR: ANTHROPIC_API_KEY not set. Copy .env.example to .env and add your key."
  exit 1
fi
pip3 install -r requirements.txt --quiet
echo "Starting simulated infrastructure..."
docker compose up -d
sleep 3
echo "Running compliance scan..."
python3 -m agent.main
echo "Done. Check the reports/ directory for output."

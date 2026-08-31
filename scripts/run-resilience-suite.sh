#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

python3 -m unittest \
  ops.tests.test_agent_transport \
  ops.tests.test_agent_producer \
  ops.tests.test_collector \
  ops.tests.test_alert_engine \
  ops.tests.test_alert_delivery \
  ops.tests.test_state_backup \
  ops.tests.test_synthetic_probe \
  ops.tests.test_generic_log_collector

npm run test:raw -- \
  server/load-budget.test.ts \
  server/agent-control.test.ts \
  server/collector-contract.test.ts \
  server/docker-contract.test.ts \
  server/synthetic-contract.test.ts \
  server/application-security-state.test.ts \
  server/application-security-app.test.ts \
  scripts/check-public-monitor.test.mjs \
  --reporter=dot

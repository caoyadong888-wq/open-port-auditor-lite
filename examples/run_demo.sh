#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."

echo '$ python3 deliverables/audit_ports_lite.py --capture examples/fixtures/ss_edge_pass.txt --policy examples/policies/edge-web.json'
python3 deliverables/audit_ports_lite.py \
  --capture examples/fixtures/ss_edge_pass.txt \
  --policy examples/policies/edge-web.json

echo '$ python3 deliverables/audit_ports_lite.py --capture examples/fixtures/ss_edge_warn.txt --policy examples/policies/edge-web.json'
set +e
python3 deliverables/audit_ports_lite.py \
  --capture examples/fixtures/ss_edge_warn.txt \
  --policy examples/policies/edge-web.json
code=$?
set -e
echo "exit:${code}"
test "${code}" -eq 1

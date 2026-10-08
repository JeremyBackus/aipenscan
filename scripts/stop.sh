#!/bin/bash
# Stop the AIPenScan server + tunnel started by serve.sh.
cd "$(dirname "$0")/.."
for f in data/php.pid data/tunnel.pid; do
  if [ -f "$f" ]; then
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  fi
done
echo stopped

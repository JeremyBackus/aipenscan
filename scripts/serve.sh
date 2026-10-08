#!/bin/bash
# Serve AIPenScan locally and expose it through a Cloudflare quick tunnel.
# Usage: ./scripts/serve.sh [port]     (default port 8080)
set -e
cd "$(dirname "$0")/.."
PORT="${1:-8080}"
mkdir -p data

export PHP_CLI_SERVER_WORKERS=5
php -S "127.0.0.1:$PORT" -t public > data/php.log 2>&1 &
echo $! > data/php.pid

cloudflared tunnel --url "http://127.0.0.1:$PORT" > data/tunnel.log 2>&1 &
echo $! > data/tunnel.pid

echo "PHP server pid $(cat data/php.pid), tunnel pid $(cat data/tunnel.pid)"
for i in $(seq 1 15); do
  URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' data/tunnel.log 2>/dev/null | head -1 || true)
  if [ -n "$URL" ]; then
    echo "AIPenScan is live at: $URL"
    exit 0
  fi
  sleep 1
done
echo "Tunnel URL not found yet, check data/tunnel.log"
exit 1

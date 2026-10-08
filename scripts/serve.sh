#!/bin/bash
# Serve AIPenScan locally and expose it through a Cloudflare tunnel.
# Default: named tunnel provisioned by scripts/cf-tunnel.php
# (data/cf-tunnel-token + data/cf-tunnel.json).
# Usage: ./scripts/serve.sh [port] [--quick]
#   --quick uses a temporary trycloudflare.com URL instead of the named tunnel.
set -e
cd "$(dirname "$0")/.."
QUICK=0
PORT=""
for a in "$@"; do
  if [ "$a" = "--quick" ]; then QUICK=1; else PORT="$a"; fi
done
if [ -z "$PORT" ] && [ "$QUICK" = "0" ] && [ -f data/cf-tunnel.json ]; then
  PORT=$(php -r '$j=json_decode(file_get_contents("data/cf-tunnel.json"),true); echo $j["local_port"] ?? 8080;')
fi
PORT="${PORT:-8080}"
mkdir -p data

export PHP_CLI_SERVER_WORKERS=5
php -S "127.0.0.1:$PORT" -t public > data/php.log 2>&1 &
echo $! > data/php.pid

if [ "$QUICK" = "1" ] || [ ! -f data/cf-tunnel-token ]; then
  [ -f data/cf-tunnel-token ] || echo "note: no named tunnel configured, falling back to quick tunnel"
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
else
  HOST=$(php -r '$j=json_decode(file_get_contents("data/cf-tunnel.json"),true); echo $j["hostname"] ?? "";')
  TPORT=$(php -r '$j=json_decode(file_get_contents("data/cf-tunnel.json"),true); echo $j["local_port"] ?? "";')
  if [ -n "$TPORT" ] && [ "$TPORT" != "$PORT" ]; then
    echo "warning: serving on $PORT but tunnel ingress points at $TPORT"
  fi
  TUNNEL_TOKEN="$(cat data/cf-tunnel-token)" cloudflared tunnel run > data/tunnel.log 2>&1 &
  echo $! > data/tunnel.pid
  echo "PHP server pid $(cat data/php.pid), tunnel pid $(cat data/tunnel.pid)"
  echo "AIPenScan is live at: https://$HOST"
fi

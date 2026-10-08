# AIPenScan

A simple, black-and-white AI-assisted pre-pentest scanner in plain PHP (no frameworks).
You enter target domains plus optional endpoints, server details, IPs and instructions.
A primary AI (orchestrator) reviews the request, asks one follow-up question if
genuinely blocked, then dispatches specialist AI agents that probe the targets and
report findings. Everything streams to a real-time console, and every LLM call,
tool call, note and finding is kept in a per-scan audit log.

Agents are **read-only** (GET / DNS / TLS / certificate-transparency lookups) and
**scope-enforced**: they can only touch hosts you listed. Findings are
observations, not exploits. This tool runs *ahead* of an official pentest to catch
low-hanging fruit — it does not replace one.

## Quick start

```bash
# 1. Store your AI credential (from the secrets store / env) into config.local.php
OPENAI_KEY=... php scripts/setup.php store OPENAI_KEY api_key

# 2. Verify the key and see available models
php scripts/setup.php check

# 3. Serve + expose via Cloudflare quick tunnel
./scripts/serve.sh            # prints the public https://....trycloudflare.com URL
./scripts/stop.sh             # stop server + tunnel
```

Open the printed URL, fill in at least one domain, hit **Start scan**.

## Configuration

`config.defaults.php` holds every setting with comments. Local overrides go in
`config.local.php` (gitignored, chmod 600) or as `AIPEN_*` env vars
(`AIPEN_API_KEY`, `AIPEN_BASE_URL`, `AIPEN_ORCH_MODEL`, ...).

Key settings:

| key | default | notes |
|---|---|---|
| `base_url` / `api_key` | OpenAI | Any OpenAI-compatible endpoint works (OpenRouter, etc.) — just change `base_url` + key |
| `orch_model` | `gpt-5` | Strong model for the orchestrator |
| `agent_model` | `gpt-5-mini` | Cheap/fast model for agents |
| `max_agents_per_scan` | 6 | Cap on agents the orchestrator may dispatch |
| `probing` | `http` | `passive` (no requests to targets), `http` (+GET), `full` (+TCP port checks) |
| `allow_custom_scripts` | false | Keep false: generated report HTML is sanitized |

## How it works

1. `public/index.php` — new-scan form + scan history.
2. `POST public/api.php?action=create` — validates input, builds the scope
   (endpoint hosts are auto-added to scope and logged), inserts the scan row,
   spawns `php lib/runner.php <id>` detached.
3. `lib/runner.php` — state machine:
   - orchestrator reviews input → clarifying question (`awaiting_input`) or plan;
   - runs each planned agent sequentially (`lib/Agent.php` tool loop over
     `lib/Tools.php`: `http_get`, `dns_lookup`, `tls_info`, `crtsh_subdomains`,
     `port_check` when `probing=full`);
   - orchestrator synthesizes summary + next steps + custom report HTML.
4. `public/scan.php` — live console (SSE via `api.php?action=events`), findings,
   sanitized orchestrator report, full audit log, scan details.
5. Follow-up scans: the refocus form creates a child scan carrying parent
   findings/notes as context, so investigations continue without losing history.

Re-running `runner.php` for a scan is safe: finished agents are skipped,
tracked in `agents_done`.

## Data

SQLite at `data/aipenscan.sqlite` (WAL mode). Tables: `scans`, `events`
(console stream), `findings`, `audit` (every LLM call with token usage, every
tool call, agent notes, user actions). `data/` and `config.local.php` are
gitignored — never commit credentials.

## Scope rules

- Domains include their subdomains. IPs must be listed literally.
- Non-HTTP(S) schemes, credentialed URLs, unresolvable hosts, and anything
  outside the listed scope are refused by every tool, and refusals are logged.
- A listed domain that resolves to non-public space is allowed but flagged
  (covers lab targets while recording the anomaly).

## License

MIT.

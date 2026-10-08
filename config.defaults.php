<?php
// AIPenScan defaults. Committed to git.
// Secrets live in config.local.php (gitignored, chmod 600), written by:
//   php scripts/setup.php store OPENAI_KEY api_key
// Any key here can also be overridden with an AIPEN_* env var, e.g. AIPEN_API_KEY.
declare(strict_types=1);

return [
  // AI provider (OpenAI-compatible chat completions API).
  'provider'  => 'openai',
  'base_url'  => 'https://api.openai.com/v1',
  'api_key'   => '',

  // Models. Orchestrator = strong/expensive, agents = cheap/fast.
  // Run `php scripts/setup.php check` to list model ids available to your key.
  'orch_model'  => 'gpt-5',
  'agent_model' => 'gpt-5-mini',
  'orch_temperature'  => 0.2,
  'agent_temperature' => 0.2,

  // Output caps per LLM call (cost control).
  'orch_max_tokens'  => 8000,
  'agent_max_tokens' => 4000,

  // Orchestrator may dispatch at most this many agents per scan.
  'max_agents_per_scan' => 6,
  // Max tool-call iterations per agent.
  'max_agent_iterations' => 8,

  // Network probing level: 'passive' (dns/cert/crt.sh only, no requests to
  // targets), 'http' (+ GET requests to in-scope URLs), 'full' (+ TCP connect
  // on a small common-port list).
  'probing' => 'http',

  'http_timeout' => 15,
  'max_response_bytes' => 524288, // 512 KB cap per fetched response
  'user_agent' => 'AIPenScan/1.0 (authorized security assessment)',

  // The orchestrator can generate custom HTML for the scan report page.
  // Scripts/iframes/forms are always stripped unless this is true.
  'allow_custom_scripts' => false,

  'data_dir' => '',
];

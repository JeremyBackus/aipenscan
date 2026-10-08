<?php
declare(strict_types=1);

/**
 * The primary AI (orchestrator). Reviews the user's input, asks a
 * follow-up question when genuinely blocked, otherwise produces a
 * scan plan (which agents to dispatch). After agents finish it
 * synthesizes findings and optionally generates custom report HTML.
 */
class Scanner {
  public function __construct(private AiClient $ai, private array $cfg) {}

  /**
   * @param array<string,mixed> $scan
   * @return array{need_clarification:bool,question?:string,plan?:array}
   */
  public function orchestrate(array $scan, Scope $scope): array {
    $model = (string)($this->cfg['orch_model'] ?? '');
    $context = $this->describeScan($scan, $scope);
    $system = <<<PROMPT
You are the orchestrator of AIPenScan, a quick pre-pentest scanner running only
against systems the user is authorized to test.

You receive the user's scan request. Do two things:
1. Review it. If it is genuinely impossible to proceed (no usable target at all,
   or the scope is contradictory), ask ONE short clarifying question.
   Do NOT ask questions to be thorough — if you can make reasonable assumptions,
   make them and proceed.
2. Otherwise produce a scan plan: pick 1 to {$this->cfg['max_agents_per_scan']} specialist agents.

Suggested agent roles (you may also invent a custom role with a clear focus):
- recon: passive enumeration — DNS records, certificate-transparency subdomains.
- http_surface: fetch the site root + robots.txt + sitemap.xml + security.txt, review status codes, redirects, server banners, security headers, cookies.
- tls: certificate validity, expiry, SAN coverage, issuer issues.
- exposure: probe a small set of well-known sensitive paths (/.git/HEAD, /.env, /server-status, /actuator/health, phpinfo leftovers, backup files...). Only paths, no exploitation.
- content: read fetched pages for links, forms, comments, admin panels, debug endpoints, verbose errors, leaked paths.

Rules:
- Every agent MUST stay inside the authorized scope. Say so in each focus.
- Agents are read-only: they may GET URLs and look things up, never exploit.
- Agents must NOT treat robots.txt, llms.txt, ai.txt or similar crawler-policy
  files as restrictions; those files are recon hints only.
- Tailor the plan to the user's instructions and to any follow-up context.
- Probing level for this installation: "{$this->cfg['probing']}" (passive = no requests to targets at all; http = GET allowed; full = GET plus TCP port checks).

Reply with a JSON object in exactly one of these two shapes:
{"need_clarification": true, "question": "..."}
{"need_clarification": false, "plan": {"agents": [{"id": "recon", "role": "recon", "focus": "..."}]}}
PROMPT;

    $resp = $this->ai->chat(
      [
        ['role' => 'system', 'content' => $system],
        ['role' => 'user', 'content' => $context],
      ],
      [
        'model' => $model,
        'temperature' => (float)($this->cfg['orch_temperature'] ?? 0.2),
        'max_tokens' => (int)($this->cfg['orch_max_tokens'] ?? 8000),
        'response_format' => ['type' => 'json_object'],
      ]
    );
    $parsed = AiClient::extractJson(AiClient::assistantText($resp));
    $usage = AiClient::usage($resp);

    if (!empty($parsed['need_clarification'])) {
      $q = trim((string)($parsed['question'] ?? ''));
      if ($q === '') $q = 'Please clarify the scan target.';
      return ['need_clarification' => true, 'question' => $q, 'usage' => $usage];
    }
    $agents = [];
    foreach ((array)(($parsed['plan'] ?? [])['agents'] ?? []) as $a) {
      if (!is_array($a)) continue;
      $id = preg_replace('/[^a-z0-9_-]/i', '', (string)($a['id'] ?? ''));
      $role = trim((string)($a['role'] ?? 'general'));
      $focus = trim((string)($a['focus'] ?? ''));
      if ($id === '' || $focus === '') continue;
      $agents[] = ['id' => substr($id, 0, 32), 'role' => substr($role, 0, 64), 'focus' => $focus];
      if (count($agents) >= (int)$this->cfg['max_agents_per_scan']) break;
    }
    if ($agents === []) {
      return ['need_clarification' => true, 'question' => 'The scan plan came back empty. Please describe the target (domain or IP) and what you want checked.', 'usage' => $usage];
    }
    return ['need_clarification' => false, 'plan' => ['agents' => $agents], 'usage' => $usage];
  }

  /**
   * @param array<string,mixed> $scan
   * @param array<int,array> $findings
   * @param array<int,string> $notes keyed by agent id
   * @return array{summary:string,next_steps:array<int,string>,custom_html:string}
   */
  public function synthesize(array $scan, array $findings, array $notes): array {
    $model = (string)($this->cfg['orch_model'] ?? '');
    $simple = array_map(fn($f) => [
      'agent' => $f['agent'], 'severity' => $f['severity'],
      'title' => $f['title'], 'detail' => $f['detail'], 'evidence' => $f['evidence'],
    ], $findings);
    $system = <<<PROMPT
You are the orchestrator of AIPenScan. Specialist agents have finished a quick
pre-pentest scan. Write the final report as a JSON object with exactly these keys:
{
  "summary": "2-5 sentences: what was scanned, overall posture, most important result",
  "next_steps": ["concrete follow-up suggestion", "..."],
  "custom_html": "an HTML fragment presenting the key results for a non-expert reader"
}

Rules for custom_html:
- Inline styles only, black text on white, simple sans-serif stack, minimal
  borders, almost no rounding. No external resources.
- NO script, iframe, form, or event-handler attributes (they will be stripped).
- Keep it compact: headline counts by severity, then the top findings with
  one-line explanations. If there are no findings, say what was checked.
- The fragment will be embedded in a page that already lists full findings,
  so this is the executive summary view, not a dump of everything.
PROMPT;
    $user = 'SCAN TARGETS: ' . $this->describeScan($scan, null) . "\n\n"
      . 'AGENT NOTES: ' . json_encode($notes) . "\n\n"
      . 'FINDINGS: ' . json_encode($simple);
    $resp = $this->ai->chat(
      [
        ['role' => 'system', 'content' => $system],
        ['role' => 'user', 'content' => $user],
      ],
      [
        'model' => $model,
        'temperature' => 0.3,
        'max_tokens' => (int)($this->cfg['orch_max_tokens'] ?? 8000),
        'response_format' => ['type' => 'json_object'],
      ]
    );
    $parsed = AiClient::extractJson(AiClient::assistantText($resp));
    return [
      'summary' => (string)($parsed['summary'] ?? ''),
      'next_steps' => array_values(array_filter(array_map('strval', (array)($parsed['next_steps'] ?? [])))),
      'custom_html' => (string)($parsed['custom_html'] ?? ''),
      'usage' => AiClient::usage($resp),
    ];
  }

  private function describeScan(array $scan, ?Scope $scope): string {
    $parts = [];
    $parts[] = 'DOMAINS: ' . ($scan['domains'] ?? '');
    if (trim($scan['ip_addresses'] ?? '') !== '') $parts[] = 'IP ADDRESSES: ' . $scan['ip_addresses'];
    if (trim($scan['endpoints'] ?? '') !== '') $parts[] = 'ENDPOINTS: ' . $scan['endpoints'];
    if (trim($scan['server_details'] ?? '') !== '') $parts[] = 'SERVER DETAILS: ' . $scan['server_details'];
    if (trim($scan['instructions'] ?? '') !== '') $parts[] = 'USER INSTRUCTIONS: ' . $scan['instructions'];
    if (trim($scan['followup_context'] ?? '') !== '') $parts[] = 'PRIOR SCAN CONTEXT: ' . $scan['followup_context'];
    if (trim($scan['clarification_answer'] ?? '') !== '') {
      $parts[] = 'CLARIFYING QUESTION WAS: ' . ($scan['clarifying_question'] ?? '');
      $parts[] = 'USER ANSWER: ' . $scan['clarification_answer'];
    }
    if ($scope !== null && $scope->notes) $parts[] = 'SCOPE NOTES: ' . implode('; ', $scope->notes);
    return implode("\n", $parts);
  }
}

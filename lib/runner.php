<?php
// AIPenScan scan runner. Launched detached from the web UI:
//   php lib/runner.php <scan_id>
// Drives the orchestrator -> agents -> synthesis state machine.
// Safe to re-run: it resumes from the scan row and skips finished agents.
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
  http_response_code(403);
  exit('cli only');
}

require_once __DIR__ . '/bootstrap.php';

$scanId = (int)($argv[1] ?? 0);
if ($scanId <= 0) {
  fwrite(STDERR, "usage: php runner.php <scan_id>\n");
  exit(2);
}

$db = aipen_db();

// Single-runner guard per scan.
$lockPath = aipen_config()->get('data_dir') . "/scan-$scanId.lock";
$lockFp = fopen($lockPath, 'c');
if ($lockFp === false || !flock($lockFp, LOCK_EX | LOCK_NB)) {
  fwrite(STDERR, "scan $scanId: another runner is active\n");
  exit(0);
}

function runner_emit(Db $db, int $scanId, string $agent, string $type, string $msg, array $data = []): void {
  aipen_emit($db, $scanId, $agent, $type, $msg, $data);
  if ($type === 'finding' || $type === 'error' || $type === 'question' || $type === 'done') {
    echo "[$type] $agent: $msg\n";
  }
}

/** @return array<string,mixed>|null fresh row, or null if gone */
function runner_scan(Db $db, int $scanId): ?array {
  return $db->getScan($scanId);
}

function runner_cancelled(Db $db, int $scanId): bool {
  $s = $db->getScan($scanId);
  return $s === null || $s['status'] === 'cancelled';
}

try {
  $scan = runner_scan($db, $scanId);
  if ($scan === null) exit(0);
  if (in_array($scan['status'], ['complete', 'cancelled'], true)) exit(0);

  $key = aipen_config()->get('api_key');
  if ($key === '') throw new RuntimeException('no API key configured (run scripts/setup.php store)');
  $acfg = aipen_config()->all();
  unset($acfg['api_key']); // never pass the secret around in option arrays
  $ai = new AiClient($key, (string)aipen_config()->get('base_url'), 180);
  $orch = new Scanner($ai, $acfg);
  $scope = Scope::fromScan($scan);
  $scope->absorbEndpoints($scan['endpoints'] ?? '');
  if ($scope->isEmpty()) throw new RuntimeException('scan has no usable scope (no domains or IPs)');

  // ---- step 1: orchestrate (plan or clarifying question) ----
  if (trim($scan['plan_json'] ?? '') === '') {
    $db->updateScan($scanId, ['status' => 'running']);
    runner_emit($db, $scanId, 'orchestrator', 'status', 'reviewing scan request');
    $db->addAudit($scanId, 'orchestrator', 'orchestrate.start');
    $result = $orch->orchestrate($db->getScan($scanId), $scope);
    if (!empty($result['usage'])) {
      $db->addAudit($scanId, 'orchestrator', 'llm call (orchestrate)', '', ['usage' => $result['usage']]);
    }
    if (!empty($result['need_clarification'])) {
      $rounds = (int)$scan['clarify_rounds'] + 1;
      $db->updateScan($scanId, [
        'status' => 'awaiting_input',
        'clarifying_question' => $result['question'],
        'clarify_rounds' => $rounds,
      ]);
      runner_emit($db, $scanId, 'orchestrator', 'question', $result['question']);
      $db->addAudit($scanId, 'orchestrator', 'clarification.requested', $result['question']);
      exit(0);
    }
    $db->updateScan($scanId, ['status' => 'running', 'plan_json' => json_encode($result['plan'])]);
    $names = implode(', ', array_column($result['plan']['agents'], 'id'));
    runner_emit($db, $scanId, 'orchestrator', 'status', "scan plan ready, dispatching agents: $names");
    $db->addAudit($scanId, 'orchestrator', 'plan.ready', $names);
    $scan = runner_scan($db, $scanId);
  }

  // ---- step 2: run agents (skip ones already done) ----
  $plan = json_decode($scan['plan_json'], true);
  $done = json_decode($scan['agents_done'] ?? '[]', true);
  if (!is_array($done)) $done = [];
  $agentRunner = new Agent($ai, $acfg);

  foreach ((array)($plan['agents'] ?? []) as $agentDef) {
    if (runner_cancelled($db, $scanId)) {
      runner_emit($db, $scanId, 'orchestrator', 'status', 'scan cancelled by user');
      exit(0);
    }
    $aid = (string)($agentDef['id'] ?? 'agent');
    if (in_array($aid, $done, true)) continue;
    runner_emit($db, $scanId, $aid, 'status', "agent started (role: {$agentDef['role']})");
    $db->addAudit($scanId, $aid, 'agent.start', (string)($agentDef['focus'] ?? ''));

    $emit = function (string $type, string $agent, string $msg, array $data = []) use ($db, $scanId) {
      if ($type === 'audit') {
        $db->addAudit($scanId, $agent, (string)($msg), '', $data);
        return;
      }
      aipen_emit($db, $scanId, $agent, $type, $msg, $data);
    };
    $out = $agentRunner->run(
      $db->getScan($scanId), $agentDef, $scope,
      fn(string $t, string $a, string $m, array $d = []) => $emit($t, $a, $m, $d),
      fn() => runner_cancelled($db, $scanId)
    );

    foreach ($out['findings'] as $f) {
      $fid = $db->addFinding($scanId, $aid, $f['severity'], $f['title'], $f['detail'], $f['evidence']);
      runner_emit($db, $scanId, $aid, 'finding', "[{$f['severity']}] {$f['title']}", ['finding_id' => $fid]);
      $db->addAudit($scanId, $aid, 'finding.saved', $f['title'], ['severity' => $f['severity']]);
    }
    if (trim($out['notes']) !== '') {
      aipen_emit($db, $scanId, $aid, 'note', $out['notes']);
      $db->addAudit($scanId, $aid, 'agent.notes', $out['notes']);
    }
    $done[] = $aid;
    $db->updateScan($scanId, ['agents_done' => json_encode($done)]);
    runner_emit($db, $scanId, $aid, 'status', 'agent finished: ' . count($out['findings']) . ' finding(s)');
  }

  if (runner_cancelled($db, $scanId)) {
    runner_emit($db, $scanId, 'orchestrator', 'status', 'scan cancelled by user');
    exit(0);
  }

  // ---- step 3: synthesize ----
  runner_emit($db, $scanId, 'orchestrator', 'status', 'all agents done, writing final report');
  $findings = $db->getFindings($scanId);
  $notes = [];
  foreach ($db->getEventsSince($scanId, 0, 5000) as $e) {
    if ($e['type'] === 'note') $notes[$e['agent']] = $e['message'];
  }
  $rep = $orch->synthesize($db->getScan($scanId), $findings, $notes);
  if (!empty($rep['usage'])) {
    $db->addAudit($scanId, 'orchestrator', 'llm call (synthesize)', '', ['usage' => $rep['usage']]);
  }
  $counts = [];
  foreach ($findings as $f) $counts[$f['severity']] = ($counts[$f['severity']] ?? 0) + 1;
  $html = Sanitize::html($rep['custom_html'], (bool)aipen_config()->get('allow_custom_scripts'));
  $db->updateScan($scanId, [
    'status' => 'complete',
    'summary' => $rep['summary'],
    'custom_html' => $html,
  ]);
  $db->addAudit($scanId, 'orchestrator', 'scan.complete',
    $rep['summary'] . ' | next: ' . implode(' / ', $rep['next_steps']), ['severity_counts' => $counts]);
  runner_emit($db, $scanId, 'orchestrator', 'done',
    'scan complete: ' . count($findings) . ' finding(s). ' . $rep['summary'],
    ['next_steps' => $rep['next_steps'], 'severity_counts' => $counts]);
} catch (Throwable $e) {
  $msg = $e->getMessage();
  if (runner_scan($db, $scanId) !== null) {
    $db->updateScan($scanId, ['status' => 'error', 'error' => mb_substr($msg, 0, 2000)]);
    runner_emit($db, $scanId, 'orchestrator', 'error', $msg);
    $db->addAudit($scanId, 'runner', 'error', $msg);
  }
  fwrite(STDERR, "scan $scanId failed: $msg\n");
  exit(1);
}

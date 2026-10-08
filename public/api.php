<?php
// AIPenScan JSON API + SSE event stream.
declare(strict_types=1);

require_once __DIR__ . '/../lib/bootstrap.php';

$db = aipen_db();
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function api_input(): array {
  $ct = $_SERVER['CONTENT_TYPE'] ?? '';
  if (str_contains($ct, 'application/json')) {
    $dec = json_decode(file_get_contents('php://input'), true);
    return is_array($dec) ? $dec : [];
  }
  return $_POST;
}

function api_spawn_runner(int $scanId): void {
  $php = PHP_BINARY;
  $runner = AIPEN_ROOT . '/lib/runner.php';
  $log = aipen_config()->get('data_dir') . "/runner-$scanId.log";
  $cmd = sprintf('nohup %s %s %d >> %s 2>&1 & echo $!',
    escapeshellarg($php), escapeshellarg($runner), $scanId, escapeshellarg($log));
  @exec($cmd, $out);
}

try {
  // ---------- create a scan ----------
  if ($action === 'create' && $method === 'POST') {
    $in = api_input();
    $domains = trim((string)($in['domains'] ?? ''));
    if ($domains === '') aipen_json_out(['error' => 'at least one domain or IP is required'], 400);

    $id = $db->createScan([
      'domains' => $domains,
      'endpoints' => trim((string)($in['endpoints'] ?? '')),
      'server_details' => trim((string)($in['server_details'] ?? '')),
      'ip_addresses' => trim((string)($in['ip_addresses'] ?? '')),
      'instructions' => trim((string)($in['instructions'] ?? '')),
    ]);

    $scan = $db->getScan($id);
    $scope = Scope::fromScan($scan);
    $scope->absorbEndpoints($scan['endpoints']);
    if ($scope->isEmpty()) {
      $db->updateScan($id, ['status' => 'error', 'error' => 'no usable scope']);
      aipen_json_out(['error' => 'could not parse any domain or IP from the input'], 400);
    }
    aipen_emit($db, $id, 'orchestrator', 'status', 'scan created, scope: '
      . implode(', ', $scope->domains)
      . ($scope->ips ? ' | ips: ' . implode(', ', $scope->ips) : ''));
    foreach ($scope->notes as $n) aipen_emit($db, $id, 'orchestrator', 'log', $n);
    $db->addAudit($id, 'web', 'scan.created', "domains+ips in scope", [
      'domains' => $scope->domains, 'ips' => $scope->ips,
    ]);
    api_spawn_runner($id);
    aipen_json_out(['id' => $id]);
  }

  // ---------- scan state (scan + findings + audit summary) ----------
  if ($action === 'get' && $method === 'GET') {
    $id = (int)($_GET['scan_id'] ?? 0);
    $scan = $db->getScan($id);
    if ($scan === null) aipen_json_out(['error' => 'scan not found'], 404);
    $scan['children'] = $db->countChildren($id);
    aipen_json_out([
      'scan' => $scan,
      'findings' => $db->getFindings($id),
      'audit' => $db->getAudit($id),
    ]);
  }

  // ---------- answer a clarifying question ----------
  if ($action === 'answer' && $method === 'POST') {
    $in = api_input();
    $id = (int)($in['scan_id'] ?? 0);
    $answer = trim((string)($in['answer'] ?? ''));
    $scan = $db->getScan($id);
    if ($scan === null) aipen_json_out(['error' => 'scan not found'], 404);
    if ($scan['status'] !== 'awaiting_input') aipen_json_out(['error' => 'scan is not waiting for input'], 400);
    if ($answer === '') aipen_json_out(['error' => 'answer is empty'], 400);
    if ((int)$scan['clarify_rounds'] >= 2) {
      aipen_json_out(['error' => 'clarification limit reached for this scan, launch a follow-up scan instead'], 400);
    }
    $db->updateScan($id, ['clarification_answer' => $answer, 'status' => 'new']);
    aipen_emit($db, $id, 'user', 'log', 'answered clarifying question');
    $db->addAudit($id, 'user', 'clarification.answered', $answer);
    api_spawn_runner($id);
    aipen_json_out(['ok' => true]);
  }

  // ---------- cancel ----------
  if ($action === 'cancel' && $method === 'POST') {
    $in = api_input();
    $id = (int)($in['scan_id'] ?? 0);
    $scan = $db->getScan($id);
    if ($scan === null) aipen_json_out(['error' => 'scan not found'], 404);
    $db->updateScan($id, ['status' => 'cancelled']);
    aipen_emit($db, $id, 'user', 'status', 'cancel requested');
    $db->addAudit($id, 'user', 'scan.cancelled');
    aipen_json_out(['ok' => true]);
  }

  // ---------- launch a follow-up (child) scan ----------
  if ($action === 'refocus' && $method === 'POST') {
    $in = api_input();
    $id = (int)($in['scan_id'] ?? 0);
    $instructions = trim((string)($in['instructions'] ?? ''));
    $parent = $db->getScan($id);
    if ($parent === null) aipen_json_out(['error' => 'scan not found'], 404);
    if ($instructions === '') aipen_json_out(['error' => 'follow-up instructions are required'], 400);
    $prior = 'Follow-up of scan #' . $id . '. Parent summary: ' . ($parent['summary'] ?: '(none)') . '. ';
    $titles = [];
    foreach ($db->getFindings($id) as $f) $titles[] = "[{$f['severity']}] {$f['title']}";
    if ($titles) $prior .= 'Parent findings: ' . implode(' | ', array_slice($titles, 0, 30)) . '. ';
    $child = $db->createScan([
      'parent_id' => $id,
      'domains' => $parent['domains'],
      'endpoints' => $parent['endpoints'],
      'server_details' => $parent['server_details'],
      'ip_addresses' => $parent['ip_addresses'],
      'instructions' => "FOLLOW-UP INVESTIGATION (requested by user):\n" . $instructions,
      'followup_context' => $prior,
    ]);
    aipen_emit($db, $child, 'orchestrator', 'status', "follow-up scan of #$id created");
    $db->addAudit($child, 'web', 'scan.refocused', $instructions, ['parent_id' => $id]);
    api_spawn_runner($child);
    aipen_json_out(['id' => $child]);
  }

  // ---------- real-time event stream (SSE) ----------
  if ($action === 'events' && $method === 'GET') {
    $id = (int)($_GET['scan_id'] ?? 0);
    if ($db->getScan($id) === null) aipen_json_out(['error' => 'scan not found'], 404);
    $last = (int)($_SERVER['HTTP_LAST_EVENT_ID'] ?? $_GET['last_id'] ?? 0);
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    @set_time_limit(30);
    ignore_user_abort(true);
    $start = time();
    while (true) {
      $rows = $db->getEventsSince($id, $last);
      foreach ($rows as $r) {
        $last = max($last, (int)$r['id']);
        echo 'id: ' . $r['id'] . "\n";
        echo 'data: ' . json_encode($r) . "\n\n";
      }
      if ($rows) {
        if (function_exists('ob_flush')) @ob_flush();
        @flush();
      }
      if (time() - $start > 25) break;
      if (connection_aborted()) break;
      sleep(1);
    }
    exit;
  }

  aipen_json_out(['error' => 'unknown action'], 404);
} catch (Throwable $e) {
  aipen_json_out(['error' => $e->getMessage()], 500);
}

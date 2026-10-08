<?php
// AIPenScan scan detail: live console, findings, audit, notes, custom page.
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
$db = aipen_db();
$id = (int)($_GET['id'] ?? 0);
$scan = $db->getScan($id);
if ($scan === null) {
  http_response_code(404);
  exit('scan not found');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan #<?= (int)$scan['id'] ?> - AIPenScan</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="wrap" id="scan-page" data-scan-id="<?= (int)$scan['id'] ?>">
  <header class="top">
    <div>
      <p class="crumbs"><a href="index.php">AIPenScan</a> / scan #<?= (int)$scan['id'] ?><?= $scan['parent_id'] ? ' <span class="muted">(follow-up of <a href="scan.php?id=' . (int)$scan['parent_id'] . '">#' . (int)$scan['parent_id'] . '</a>)</span>' : '' ?></p>
      <h1>Scan #<?= (int)$scan['id'] ?> <span class="status <?= htmlspecialchars($scan['status']) ?>" id="scan-status"><?= htmlspecialchars($scan['status']) ?></span></h1>
      <p class="sub" id="scan-summary"><?= htmlspecialchars($scan['summary'] ?: 'Running...') ?></p>
    </div>
    <div class="topmeta"><?php if (!in_array($scan['status'], ['complete', 'cancelled', 'error'], true)): ?><button id="cancel-btn" type="button">Cancel scan</button><?php endif; ?></div>
  </header>

  <div id="question-box" class="card hidden">
    <h2>Orchestrator question</h2>
    <p id="question-text"></p>
    <form id="answer-form">
      <textarea name="answer" rows="2" required placeholder="Your answer..."></textarea>
      <div class="row"><button type="submit">Send answer and resume</button></div>
    </form>
  </div>

  <nav class="tabs" id="tabs">
    <button data-tab="console" class="active">Console</button>
    <button data-tab="findings">Findings <span id="finding-count"></span></button>
    <button data-tab="report">Report</button>
    <button data-tab="audit">Audit log</button>
    <button data-tab="details">Details</button>
  </nav>

  <section class="card tabpane" id="tab-console">
    <div id="console" class="console"><p class="muted">Connecting to live console...</p></div>
  </section>

  <section class="card tabpane hidden" id="tab-findings">
    <div id="findings"><p class="muted">No findings yet.</p></div>
  </section>

  <section class="card tabpane hidden" id="tab-report">
    <div id="custom-report"><?= $scan['custom_html'] ?: '<p class="muted">The orchestrator report will appear here when the scan completes.</p>' ?></div>
  </section>

  <section class="card tabpane hidden" id="tab-audit">
    <div id="audit"><p class="muted">Loading audit log...</p></div>
  </section>

  <section class="card tabpane hidden" id="tab-details">
    <dl class="details">
      <dt>Domains</dt><dd><pre><?= htmlspecialchars($scan['domains']) ?></pre></dd>
      <dt>Endpoints</dt><dd><pre><?= htmlspecialchars($scan['endpoints'] ?: '-') ?></pre></dd>
      <dt>IP addresses</dt><dd><pre><?= htmlspecialchars($scan['ip_addresses'] ?: '-') ?></pre></dd>
      <dt>Server details</dt><dd><pre><?= htmlspecialchars($scan['server_details'] ?: '-') ?></pre></dd>
      <dt>Instructions</dt><dd><pre><?= htmlspecialchars($scan['instructions'] ?: '-') ?></pre></dd>
      <?php if ($scan['followup_context']): ?><dt>Prior context</dt><dd><pre><?= htmlspecialchars($scan['followup_context']) ?></pre></dd><?php endif; ?>
      <dt>Plan</dt><dd><pre id="plan-pre"><?= htmlspecialchars($scan['plan_json'] ?: '-') ?></pre></dd>
      <?php if ($scan['error']): ?><dt>Error</dt><dd><pre><?= htmlspecialchars($scan['error']) ?></pre></dd><?php endif; ?>
    </dl>
  </section>

  <section class="card">
    <h2>Launch follow-up scan</h2>
    <p class="muted">Starts a child scan inheriting this scan's targets, findings and notes, refocused by your instructions.</p>
    <form id="refocus-form">
      <textarea name="instructions" rows="2" required placeholder="Dig deeper into the login page, check ..."></textarea>
      <div class="row"><button type="submit">Launch follow-up</button><span class="hint" id="refocus-msg"></span></div>
    </form>
  </section>
</div>
<script src="app.js"></script>
</body>
</html>

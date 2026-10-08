<?php
// AIPenScan home: new scan form + scan history.
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
$db = aipen_db();
$scans = $db->listScans(50);
$egressIp = aipen_egress_ip();
$userAgent = (string)aipen_config()->get('user_agent');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AIPenScan</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <h1>AIPenScan</h1>
      <p class="sub">Quick AI-assisted pre-pentest scanner. Finds likely exposures before the official scan.</p>
    </div>
    <div class="topmeta">scope-enforced &middot; read-only agents &middot; full audit log</div>
  </header>

  <section class="card">
    <h2>New scan</h2>
    <form id="new-scan-form">
      <label>Domains (required, one per line)
        <textarea name="domains" rows="3" required placeholder="example.com&#10;app.example.com"></textarea>
      </label>
      <div class="grid2">
        <label>Endpoints (optional, one per line)
          <textarea name="endpoints" rows="3" placeholder="https://example.com/login&#10;https://example.com/api/health"></textarea>
        </label>
        <label>IP addresses (optional, one per line)
          <textarea name="ip_addresses" rows="3" placeholder="203.0.113.10"></textarea>
        </label>
      </div>
      <label>Server details (optional)
        <textarea name="server_details" rows="2" placeholder="nginx 1.24 on Ubuntu, hosted on ..."></textarea>
      </label>
      <label>Specific instructions (optional)
        <textarea name="instructions" rows="2" placeholder="Focus on the login flow and any exposed admin panels."></textarea>
      </label>
      <div class="row">
        <button type="submit" id="start-btn">Start scan</button>
        <span class="hint">The orchestrator reviews this, may ask one follow-up question, then dispatches agents. Only hosts you list are ever touched.</span>
      </div>
      <p class="origin">Agent requests originate from this server
        (<?= $egressIp ? 'public IP <strong>' . htmlspecialchars($egressIp) . '</strong>' : '<strong>currently unavailable</strong>' ?>,
        not the tunnel hostname) with User-Agent <code><?= htmlspecialchars($userAgent) ?></code>.
        Allowlist the IP first if the target filters by source.</p>
      <p class="formerr" id="form-err"></p>
    </form>
  </section>

  <section class="card">
    <h2>Scans</h2>
    <?php if ($scans === []): ?>
      <p class="muted">No scans yet.</p>
    <?php else: ?>
    <table>
      <thead><tr><th>ID</th><th>Status</th><th>Targets</th><th>Findings</th><th>Updated</th></tr></thead>
      <tbody>
      <?php foreach ($scans as $s): ?>
        <tr>
          <td><a href="scan.php?id=<?= (int)$s['id'] ?>">#<?= (int)$s['id'] ?></a><?= $s['parent_id'] ? ' <span class="muted">child of #' . (int)$s['parent_id'] . '</span>' : '' ?></td>
          <td><span class="status <?= htmlspecialchars($s['status']) ?>"><?= htmlspecialchars($s['status']) ?></span></td>
          <td class="targets"><?= htmlspecialchars(trim(preg_replace('/\s+/', ' ', $s['domains'] . ' ' . $s['ip_addresses']))) ?></td>
          <td><?= (int)$s['finding_count'] ?></td>
          <td class="muted"><?= htmlspecialchars($s['updated_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <?php endif; ?>
  </section>
</div>
<script src="app.js"></script>
</body>
</html>

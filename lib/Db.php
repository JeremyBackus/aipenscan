<?php
declare(strict_types=1);

class Db {
  private PDO $pdo;

  public function __construct(string $path) {
    $dir = dirname($path);
    if (!is_dir($dir)) mkdir($dir, 0770, true);
    $this->pdo = new PDO('sqlite:' . $path, null, null, [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $this->pdo->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON;');
    $this->migrate();
  }

  public static function now(): string {
    return gmdate('Y-m-d\TH:i:s\Z');
  }

  private function migrate(): void {
    $this->pdo->exec("CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parent_id INTEGER NULL REFERENCES scans(id) ON DELETE SET NULL,
      status TEXT NOT NULL DEFAULT 'new',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      domains TEXT NOT NULL DEFAULT '',
      endpoints TEXT NOT NULL DEFAULT '',
      server_details TEXT NOT NULL DEFAULT '',
      ip_addresses TEXT NOT NULL DEFAULT '',
      instructions TEXT NOT NULL DEFAULT '',
      followup_context TEXT NOT NULL DEFAULT '',
      clarifying_question TEXT NOT NULL DEFAULT '',
      clarification_answer TEXT NOT NULL DEFAULT '',
      clarify_rounds INTEGER NOT NULL DEFAULT 0,
      plan_json TEXT NOT NULL DEFAULT '',
      agents_done TEXT NOT NULL DEFAULT '[]',
      custom_html TEXT NOT NULL DEFAULT '',
      summary TEXT NOT NULL DEFAULT '',
      error TEXT NOT NULL DEFAULT ''
    )");
    $this->pdo->exec("CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      agent TEXT NOT NULL DEFAULT '',
      type TEXT NOT NULL,
      message TEXT NOT NULL,
      data_json TEXT NOT NULL DEFAULT ''
    )");
    $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id, id)");
    $this->pdo->exec("CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      agent TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT 'info',
      title TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      evidence TEXT NOT NULL DEFAULT ''
    )");
    $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, id)");
    $this->pdo->exec("CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      meta_json TEXT NOT NULL DEFAULT ''
    )");
    $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit(scan_id, id)");
  }

  // ---- scans ----

  public function createScan(array $f): int {
    $st = $this->pdo->prepare("INSERT INTO scans
      (parent_id, status, created_at, updated_at, domains, endpoints, server_details,
       ip_addresses, instructions, followup_context)
      VALUES (:parent_id, 'new', :now, :now, :domains, :endpoints, :server_details,
       :ip_addresses, :instructions, :followup_context)");
    $st->execute([
      ':parent_id' => $f['parent_id'] ?? null,
      ':now' => self::now(),
      ':domains' => $f['domains'] ?? '',
      ':endpoints' => $f['endpoints'] ?? '',
      ':server_details' => $f['server_details'] ?? '',
      ':ip_addresses' => $f['ip_addresses'] ?? '',
      ':instructions' => $f['instructions'] ?? '',
      ':followup_context' => $f['followup_context'] ?? '',
    ]);
    return (int)$this->pdo->lastInsertId();
  }

  public function getScan(int $id): ?array {
    $st = $this->pdo->prepare("SELECT * FROM scans WHERE id = :id");
    $st->execute([':id' => $id]);
    $row = $st->fetch();
    return $row ?: null;
  }

  public function updateScan(int $id, array $f): void {
    $f['updated_at'] = self::now();
    $sets = [];
    $args = [':id' => $id];
    foreach ($f as $k => $v) {
      $sets[] = "$k = :$k";
      $args[":$k"] = $v;
    }
    $this->pdo->prepare("UPDATE scans SET " . implode(', ', $sets) . " WHERE id = :id")->execute($args);
  }

  /** @return array<int,array> */
  public function listScans(int $limit = 50): array {
    $st = $this->pdo->prepare("SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
      FROM scans s ORDER BY s.id DESC LIMIT :lim");
    $st->bindValue(':lim', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
  }

  public function countChildren(int $id): int {
    $st = $this->pdo->prepare("SELECT COUNT(*) AS c FROM scans WHERE parent_id = :id");
    $st->execute([':id' => $id]);
    return (int)$st->fetch()['c'];
  }

  // ---- events (real-time console) ----

  public function addEvent(int $scanId, string $agent, string $type, string $message, string $dataJson = ''): int {
    $st = $this->pdo->prepare("INSERT INTO events (scan_id, created_at, agent, type, message, data_json)
      VALUES (:sid, :now, :agent, :type, :msg, :data)");
    $st->execute([
      ':sid' => $scanId, ':now' => self::now(), ':agent' => $agent,
      ':type' => $type, ':msg' => $message, ':data' => $dataJson,
    ]);
    return (int)$this->pdo->lastInsertId();
  }

  /** @return array<int,array> */
  public function getEventsSince(int $scanId, int $lastId, int $limit = 500): array {
    $st = $this->pdo->prepare("SELECT * FROM events WHERE scan_id = :sid AND id > :last ORDER BY id ASC LIMIT :lim");
    $st->bindValue(':sid', $scanId, PDO::PARAM_INT);
    $st->bindValue(':last', $lastId, PDO::PARAM_INT);
    $st->bindValue(':lim', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
  }

  // ---- findings ----

  public function addFinding(int $scanId, string $agent, string $severity, string $title, string $detail, string $evidence): int {
    $st = $this->pdo->prepare("INSERT INTO findings (scan_id, created_at, agent, severity, title, detail, evidence)
      VALUES (:sid, :now, :agent, :sev, :title, :detail, :ev)");
    $st->execute([
      ':sid' => $scanId, ':now' => self::now(), ':agent' => $agent,
      ':sev' => strtolower($severity), ':title' => $title, ':detail' => $detail, ':ev' => $evidence,
    ]);
    return (int)$this->pdo->lastInsertId();
  }

  /** @return array<int,array> */
  public function getFindings(int $scanId): array {
    $st = $this->pdo->prepare("SELECT * FROM findings WHERE scan_id = :sid ORDER BY id ASC");
    $st->execute([':sid' => $scanId]);
    return $st->fetchAll();
  }

  // ---- audit log ----

  public function addAudit(int $scanId, string $actor, string $action, string $detail = '', array $meta = []): int {
    $st = $this->pdo->prepare("INSERT INTO audit (scan_id, created_at, actor, action, detail, meta_json)
      VALUES (:sid, :now, :actor, :action, :detail, :meta)");
    $st->execute([
      ':sid' => $scanId, ':now' => self::now(), ':actor' => $actor,
      ':action' => $action, ':detail' => $detail, ':meta' => $meta ? json_encode($meta) : '',
    ]);
    return (int)$this->pdo->lastInsertId();
  }

  /** @return array<int,array> */
  public function getAudit(int $scanId, int $limit = 500): array {
    $st = $this->pdo->prepare("SELECT * FROM audit WHERE scan_id = :sid ORDER BY id ASC LIMIT :lim");
    $st->bindValue(':sid', $scanId, PDO::PARAM_INT);
    $st->bindValue(':lim', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
  }
}

<?php
declare(strict_types=1);

define('AIPEN_ROOT', dirname(__DIR__));

require_once AIPEN_ROOT . '/lib/Config.php';
require_once AIPEN_ROOT . '/lib/Db.php';
require_once AIPEN_ROOT . '/lib/AiClient.php';
require_once AIPEN_ROOT . '/lib/Scope.php';
require_once AIPEN_ROOT . '/lib/Tools.php';
require_once AIPEN_ROOT . '/lib/Agent.php';
require_once AIPEN_ROOT . '/lib/Scanner.php';
require_once AIPEN_ROOT . '/lib/Sanitize.php';

function aipen_config(): Config {
  static $c = null;
  if ($c === null) $c = new Config(AIPEN_ROOT);
  return $c;
}

function aipen_db(): Db {
  static $d = null;
  if ($d === null) $d = new Db(aipen_config()->get('data_dir') . '/aipenscan.sqlite');
  return $d;
}

/** Write a console event (visible in the real-time stream). */
function aipen_emit(Db $db, int $scanId, string $agent, string $type, string $message, array $data = []): int {
  return $db->addEvent($scanId, $agent, $type, $message, $data ? json_encode($data) : '');
}

function aipen_json_out($payload, int $code = 200): void {
  http_response_code($code);
  header('Content-Type: application/json');
  echo json_encode($payload);
  exit;
}

/**
 * This server's public IP as seen by scan targets (requests go direct,
 * not through the tunnel hostname). Cached in data/ for 24h.
 */
function aipen_egress_ip(): ?string {
  $cache = aipen_config()->get('data_dir') . '/egress-ip.json';
  if (is_file($cache)) {
    $c = json_decode(@file_get_contents($cache), true);
    if (is_array($c) && isset($c['ip'], $c['at']) && (time() - (int)$c['at']) < 86400) {
      return (string)$c['ip'];
    }
  }
  foreach (['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com'] as $url) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT => 8,
      CURLOPT_USERAGENT => 'AIPenScan/1.0',
    ]);
    $out = curl_exec($ch);
    curl_close($ch);
    $ip = trim((string)$out);
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
      @file_put_contents($cache, json_encode(['ip' => $ip, 'at' => time()]));
      return $ip;
    }
  }
  return null;
}

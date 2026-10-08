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

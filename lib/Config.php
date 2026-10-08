<?php
declare(strict_types=1);

class Config {
  private array $data;

  public function __construct(string $root) {
    $defaults = require $root . '/config.defaults.php';
    $local = [];
    $localFile = $root . '/config.local.php';
    if (is_file($localFile)) {
      $loaded = require $localFile;
      if (is_array($loaded)) $local = $loaded;
    }
    $merged = array_merge($defaults, $local);
    foreach ($merged as $k => $v) {
      $env = getenv('AIPEN_' . strtoupper($k));
      if ($env !== false && $env !== '') $merged[$k] = $env;
    }
    if (empty($merged['data_dir'])) $merged['data_dir'] = $root . '/data';
    $this->data = $merged;
  }

  public function get(string $key, $default = null) {
    return $this->data[$key] ?? $default;
  }

  public function all(): array {
    $out = $this->data;
    if (!empty($out['api_key'])) $out['api_key'] = '***set***';
    return $out;
  }
}

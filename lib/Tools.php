<?php
declare(strict_types=1);

/**
 * Read-only network tools available to agents. Every request goes
 * through Scope enforcement first; refusals are returned as data
 * (and logged by the caller) rather than throwing.
 */
class Tools {
  /** @return array<string,mixed> OpenAI function definitions for the agent loop */
  public static function definitions(string $probing): array {
    $defs = [
      [
        'type' => 'function',
        'function' => [
          'name' => 'http_get',
          'description' => 'Fetch an in-scope http(s) URL with GET. Returns status, headers, a security-header assessment, body size and a text excerpt. Follows up to 4 redirects (each re-checked against scope).',
          'parameters' => [
            'type' => 'object',
            'properties' => [
              'url' => ['type' => 'string', 'description' => 'Full http(s) URL to fetch'],
            ],
            'required' => ['url'],
          ],
        ],
      ],
      [
        'type' => 'function',
        'function' => [
          'name' => 'dns_lookup',
          'description' => 'Look up DNS records (A, AAAA, MX, TXT, NS) for an in-scope host.',
          'parameters' => [
            'type' => 'object',
            'properties' => ['host' => ['type' => 'string']],
            'required' => ['host'],
          ],
        ],
      ],
      [
        'type' => 'function',
        'function' => [
          'name' => 'tls_info',
          'description' => 'Retrieve the TLS certificate chain details (subject, SANs, issuer, validity dates, signature algorithm) for an in-scope host and port.',
          'parameters' => [
            'type' => 'object',
            'properties' => [
              'host' => ['type' => 'string'],
              'port' => ['type' => 'integer', 'description' => 'TLS port, default 443'],
            ],
            'required' => ['host'],
          ],
        ],
      ],
      [
        'type' => 'function',
        'function' => [
          'name' => 'crtsh_subdomains',
          'description' => 'Passive subdomain enumeration via certificate transparency (crt.sh). No requests are sent to the target.',
          'parameters' => [
            'type' => 'object',
            'properties' => ['domain' => ['type' => 'string']],
            'required' => ['domain'],
          ],
        ],
      ],
    ];
    if ($probing === 'full') {
      $defs[] = [
        'type' => 'function',
        'function' => [
          'name' => 'port_check',
          'description' => 'TCP connect check on a small list of ports for an in-scope host. Max 25 ports per call.',
          'parameters' => [
            'type' => 'object',
            'properties' => [
              'host' => ['type' => 'string'],
              'ports' => ['type' => 'array', 'items' => ['type' => 'integer']],
            ],
            'required' => ['host', 'ports'],
          ],
        ],
      ];
    }
    return $defs;
  }

  /** @return array<string,mixed> */
  public static function dispatch(string $name, array $args, Scope $scope, array $cfg): array {
    try {
      switch ($name) {
        case 'http_get': return self::httpGet((string)($args['url'] ?? ''), $scope, $cfg);
        case 'dns_lookup': return self::dnsLookup((string)($args['host'] ?? ''), $scope);
        case 'tls_info': return self::tlsInfo((string)($args['host'] ?? ''), (int)($args['port'] ?? 443), $scope, $cfg);
        case 'crtsh_subdomains': return self::crtsh((string)($args['domain'] ?? ''), $scope, $cfg);
        case 'port_check': return self::portCheck((string)($args['host'] ?? ''), $args['ports'] ?? [], $scope, $cfg);
        default: return ['ok' => false, 'error' => "unknown tool '$name'"];
      }
    } catch (Throwable $e) {
      return ['ok' => false, 'error' => 'tool error: ' . $e->getMessage()];
    }
  }

  // ---------- implementations ----------

  /** @return array<string,mixed> */
  public static function httpGet(string $url, Scope $scope, array $cfg): array {
    [$allowed, $reason] = $scope->isAllowedUrl($url);
    if (!$allowed) return ['ok' => false, 'error' => 'refused: ' . $reason];

    $timeout = (int)($cfg['http_timeout'] ?? 15);
    $cap = (int)($cfg['max_response_bytes'] ?? 524288);
    $ua = (string)($cfg['user_agent'] ?? 'AIPenScan/1.0');
    $current = $url;
    $hops = [];

    for ($i = 0; $i <= 4; $i++) {
      if ($i > 0) {
        [$allowed, $reason] = $scope->isAllowedUrl($current);
        if (!$allowed) {
          return ['ok' => false, 'error' => 'refused: redirect target out of scope: ' . $reason, 'redirect_chain' => $hops];
        }
      }
      $t0 = microtime(true);
      $headers = [];
      $body = '';
      $ch = curl_init($current);
      curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_HEADER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT => $ua,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CERTINFO => true,
        CURLOPT_ENCODING => '',
        CURLOPT_NOPROGRESS => false,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
          $len = strlen($line);
          $line = trim($line);
          if ($line === '' || str_starts_with(strtoupper($line), 'HTTP/')) return $len;
          $p = strpos($line, ':');
          if ($p !== false) {
            $k = strtolower(trim(substr($line, 0, $p)));
            $v = trim(substr($line, $p + 1));
            if (isset($headers[$k])) {
              if (!is_array($headers[$k])) $headers[$k] = [$headers[$k]];
              $headers[$k][] = $v;
            } else {
              $headers[$k] = $v;
            }
          }
          return $len;
        },
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, $cap) {
          $room = $cap - strlen($body);
          if ($room <= 0) return -1; // abort: over cap
          $body .= substr($chunk, 0, $room);
          return strlen($chunk);
        },
        CURLOPT_PROGRESSFUNCTION => function () {
          return 0;
        },
      ]);
      curl_exec($ch);
      $errno = curl_errno($ch);
      $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
      $elapsed = round(microtime(true) - $t0, 2);
      $certinfo = curl_getinfo($ch, CURLINFO_CERTINFO);
      curl_close($ch);
      $hops[] = ['url' => $current, 'status' => $status];

      if ($errno === 23 && strlen($body) >= $cap) {
        // Aborted by our own write cap: still a usable (truncated) result.
        return self::httpResult(true, $current, $status, $headers, $body, $elapsed, $hops, true, $certinfo);
      }
      if ($errno !== 0 || $status === 0) {
        return ['ok' => false, 'error' => 'request failed (curl ' . $errno . ')', 'redirect_chain' => $hops];
      }
      if ($status >= 300 && $status < 400 && isset($headers['location'])) {
        $loc = is_array($headers['location']) ? end($headers['location']) : $headers['location'];
        $current = self::resolveUrl($current, $loc);
        continue;
      }
      return self::httpResult(true, $current, $status, $headers, $body, $elapsed, $hops, false, $certinfo);
    }
    return ['ok' => false, 'error' => 'too many redirects', 'redirect_chain' => $hops];
  }

  /** @return array<string,mixed> */
  private static function httpResult(bool $ok, string $url, int $status, array $headers, string $body, float $elapsed, array $hops, bool $truncated, $certinfo): array {
    $text = $body;
    if (!mb_check_encoding($text, 'UTF-8')) $text = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $text);
    return [
      'ok' => $ok,
      'url' => $url,
      'status' => $status,
      'elapsed_s' => $elapsed,
      'redirect_chain' => $hops,
      'headers' => $headers,
      'security_headers' => self::assessHeaders($headers, $url),
      'body_bytes_received' => strlen($body),
      'body_truncated' => $truncated,
      'body_excerpt' => mb_substr($text, 0, 4000),
    ];
  }

  /** @return array<string,mixed> deterministic security-header assessment */
  private static function assessHeaders(array $headers, string $url): array {
    $h = [];
    foreach ($headers as $k => $v) $h[$k] = is_array($v) ? end($v) : $v;
    $isHttps = str_starts_with(strtolower($url), 'https://');
    $missing = [];
    foreach (['content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy'] as $need) {
      if (!isset($h[$need])) $missing[] = $need;
    }
    if ($isHttps && !isset($h['strict-transport-security'])) $missing[] = 'strict-transport-security';
    $out = ['missing' => $missing];
    if (isset($h['server'])) $out['server_banner'] = $h['server'];
    if (isset($h['x-powered-by'])) $out['powered_by'] = $h['x-powered-by'];
    if (isset($h['set-cookie'])) {
      $cookies = is_array($headers['set-cookie']) ? $headers['set-cookie'] : [$headers['set-cookie']];
      $weak = [];
      foreach ($cookies as $c) {
        $name = explode('=', $c)[0];
        $lc = strtolower($c);
        $flags = [];
        if (!str_contains($lc, 'httponly')) $flags[] = 'no-httponly';
        if (!str_contains($lc, 'samesite')) $flags[] = 'no-samesite';
        if ($isHttps && !str_contains($lc, 'secure')) $flags[] = 'no-secure';
        if ($flags) $weak[] = trim($name) . ' (' . implode(',', $flags) . ')';
      }
      if ($weak) $out['weak_cookies'] = $weak;
    }
    if (isset($h['access-control-allow-origin']) && trim($h['access-control-allow-origin']) === '*') {
      $out['cors_wildcard'] = true;
    }
    return $out;
  }

  private static function resolveUrl(string $base, string $loc): string {
    if (preg_match('#^https?://#i', $loc)) return $loc;
    $b = parse_url($base);
    $root = ($b['scheme'] ?? 'http') . '://' . ($b['host'] ?? '');
    if (isset($b['port'])) $root .= ':' . $b['port'];
    if (str_starts_with($loc, '/')) return $root . $loc;
    $dir = rtrim(dirname($b['path'] ?? '/'), '/');
    return $root . $dir . '/' . $loc;
  }

  /** @return array<string,mixed> */
  public static function dnsLookup(string $host, Scope $scope): array {
    [$allowed, $reason] = $scope->isAllowedHost($host);
    if (!$allowed) return ['ok' => false, 'error' => 'refused: ' . $reason];
    $out = ['ok' => true, 'host' => $host];
    foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA, 'MX' => DNS_MX, 'TXT' => DNS_TXT, 'NS' => DNS_NS] as $label => $flag) {
      $recs = @dns_get_record($host, $flag);
      if (is_array($recs) && $recs) $out[$label] = $recs;
    }
    return $out;
  }

  /** @return array<string,mixed> */
  public static function tlsInfo(string $host, int $port, Scope $scope, array $cfg): array {
    [$allowed, $reason] = $scope->isAllowedHost($host);
    if (!$allowed) return ['ok' => false, 'error' => 'refused: ' . $reason];
    if ($port < 1 || $port > 65535) return ['ok' => false, 'error' => 'invalid port'];
    $timeout = min(10, (int)($cfg['http_timeout'] ?? 15));
    $ctx = stream_context_create(['ssl' => [
      'capture_peer_cert' => true,
      'capture_peer_cert_chain' => true,
      'verify_peer' => false,
      'verify_peer_name' => false,
      'SNI_enabled' => true,
      'peer_name' => $host,
    ]]);
    $fp = @stream_socket_client("tls://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($fp === false) return ['ok' => false, 'error' => "TLS connect failed: $errstr ($errno)"];
    $params = stream_context_get_params($ctx);
    fclose($fp);
    if (empty($params['options']['ssl']['peer_certificate'])) {
      return ['ok' => false, 'error' => 'no peer certificate captured'];
    }
    $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
    if ($cert === false) return ['ok' => false, 'error' => 'could not parse certificate'];
    $now = time();
    $out = [
      'ok' => true,
      'host' => $host,
      'port' => $port,
      'subject_cn' => $cert['subject']['CN'] ?? '',
      'subject_alt_names' => $cert['extensions']['subjectAltName'] ?? '',
      'issuer' => ($cert['issuer']['O'] ?? '') . ' / ' . ($cert['issuer']['CN'] ?? ''),
      'valid_from' => gmdate('Y-m-d', $cert['validFrom_time_t']),
      'valid_to' => gmdate('Y-m-d', $cert['validTo_time_t']),
      'days_remaining' => (int)floor(($cert['validTo_time_t'] - $now) / 86400),
      'signature_algorithm' => $cert['signatureTypeSN'] ?? '',
      'expired' => $cert['validTo_time_t'] < $now,
      'self_signed' => ($cert['subject']['CN'] ?? null) === ($cert['issuer']['CN'] ?? null)
        && ($cert['subject']['O'] ?? null) === ($cert['issuer']['O'] ?? null),
    ];
    $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    $out['chain_length'] = is_array($chain) ? count($chain) : 0;
    return $out;
  }

  /** @return array<string,mixed> */
  public static function crtsh(string $domain, Scope $scope, array $cfg): array {
    [$allowed, $reason] = $scope->isAllowedHost($domain);
    if (!$allowed) return ['ok' => false, 'error' => 'refused: ' . $reason];
    if (filter_var($domain, FILTER_VALIDATE_IP)) return ['ok' => false, 'error' => 'crt.sh needs a domain name, not an IP'];
    $ch = curl_init('https://crt.sh/?q=%25.' . rawurlencode($domain) . '&output=json');
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT => 25,
      CURLOPT_USERAGENT => $cfg['user_agent'] ?? 'AIPenScan/1.0',
    ]);
    $out = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($out === false || $errno !== 0) return ['ok' => false, 'error' => 'crt.sh request failed'];
    $rows = json_decode((string)$out, true);
    if (!is_array($rows)) return ['ok' => false, 'error' => 'crt.sh returned unexpected data'];
    $names = [];
    foreach ($rows as $r) {
      foreach (explode("\n", (string)($r['name_value'] ?? '')) as $n) {
        $n = strtolower(trim($n));
        $n = ltrim($n, '*.');
        if ($n !== '' && !str_contains($n, ' ') && !str_contains($n, '@')) $names[$n] = true;
      }
      if (count($names) > 500) break;
    }
    $names = array_keys($names);
    sort($names);
    return ['ok' => true, 'domain' => $domain, 'count' => count($names), 'subdomains' => array_slice($names, 0, 150)];
  }

  /** @return array<string,mixed> */
  public static function portCheck(string $host, $ports, Scope $scope, array $cfg): array {
    [$allowed, $reason] = $scope->isAllowedHost($host);
    if (!$allowed) return ['ok' => false, 'error' => 'refused: ' . $reason];
    if (!is_array($ports)) return ['ok' => false, 'error' => 'ports must be a list'];
    $ports = array_values(array_unique(array_filter(array_map('intval', $ports), fn($p) => $p >= 1 && $p <= 65535)));
    if (count($ports) > 25) return ['ok' => false, 'error' => 'max 25 ports per call'];
    if ($ports === []) return ['ok' => false, 'error' => 'no valid ports given'];
    $res = [];
    foreach ($ports as $p) {
      $t0 = microtime(true);
      $fp = @stream_socket_client("tcp://$host:$p", $errno, $errstr, 3);
      if (is_resource($fp)) {
        fclose($fp);
        $res[$p] = ['open' => true, 'elapsed_s' => round(microtime(true) - $t0, 2)];
      } else {
        $res[$p] = ['open' => false];
      }
    }
    return ['ok' => true, 'host' => $host, 'ports' => $res];
  }
}

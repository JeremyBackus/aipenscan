<?php
declare(strict_types=1);

/**
 * Scan scope: the set of domains and IPs the user authorized.
 * Every network tool call is checked against this. Anything out of
 * scope is refused and the refusal is logged.
 */
class Scope {
  /** @var array<int,string> lowercase domains */
  public array $domains = [];
  /** @var array<int,string> literal IP strings */
  public array $ips = [];
  /** @var array<int,string> notes, e.g. auto-expansions */
  public array $notes = [];

  public static function fromScan(array $scan): self {
    $s = new self();
    foreach (self::lines($scan['domains'] ?? '') as $line) {
      $h = self::cleanHost($line);
      if ($h === '') continue;
      if (filter_var($h, FILTER_VALIDATE_IP)) $s->addIp($h);
      else $s->addDomain($h);
    }
    foreach (self::lines($scan['ip_addresses'] ?? '') as $line) {
      $h = self::cleanHost($line);
      if ($h !== '' && filter_var($h, FILTER_VALIDATE_IP)) $s->addIp($h);
    }
    return $s;
  }

  /**
   * Parse the endpoints textarea. Hosts found there that are not yet in
   * scope are added automatically (and reported in notes) so agents can
   * fetch exactly the URLs the user pasted.
   * @return array<int,string> list of full URLs found
   */
  public function absorbEndpoints(string $text): array {
    $urls = [];
    foreach (self::lines($text) as $line) {
      $line = trim($line);
      if ($line === '') continue;
      if (!preg_match('#^https?://#i', $line)) $line = 'http://' . $line;
      $parts = parse_url($line);
      if ($parts === false || empty($parts['host'])) continue;
      $host = strtolower(rtrim($parts['host'], '.'));
      $urls[] = $line;
      if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!in_array($host, $this->ips, true)) {
          $this->ips[] = $host;
          $this->notes[] = "scope expanded: IP $host added from endpoints list";
        }
      } elseif (!self::hostInDomains($host, $this->domains)) {
        $this->domains[] = $host;
        $this->notes[] = "scope expanded: domain $host added from endpoints list";
      }
    }
    return $urls;
  }

  public function addDomain(string $d): void {
    $d = strtolower($d);
    if ($d !== '' && !in_array($d, $this->domains, true)) $this->domains[] = $d;
  }

  public function addIp(string $ip): void {
    if (!in_array($ip, $this->ips, true)) $this->ips[] = $ip;
  }

  public function isEmpty(): bool {
    return $this->domains === [] && $this->ips === [];
  }

  /** @return array{0:bool,1:string} [allowed, reason] */
  public function isAllowedUrl(string $url): array {
    $parts = parse_url(trim($url));
    if ($parts === false || empty($parts['host'])) return [false, 'unparseable URL'];
    $scheme = strtolower($parts['scheme'] ?? '');
    if ($scheme !== 'http' && $scheme !== 'https') return [false, "scheme '$scheme' is not allowed (http/https only)"];
    if (isset($parts['user']) || isset($parts['pass'])) return [false, 'URLs with credentials are not allowed'];
    $host = strtolower(rtrim($parts['host'], '.'));
    if ($host === '') return [false, 'empty host'];

    if (filter_var($host, FILTER_VALIDATE_IP)) {
      if (!in_array($host, $this->ips, true)) return [false, "IP $host is not in the authorized scope"];
      return [true, 'listed IP'];
    }
    if (!self::hostInDomains($host, $this->domains)) {
      return [false, "host $host is not in the authorized scope"];
    }
    // SSRF guard: a listed domain resolving to private/loopback space is
    // suspicious (DNS rebinding etc). Allow but flag — except unresolvable
    // hosts, which are refused so agents do not waste iterations.
    $resolved = @gethostbynamel($host);
    if ($resolved === false) return [false, "host $host does not resolve"];
    foreach ($resolved as $ip) {
      if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return [true, "listed domain (note: resolves to non-public IP $ip)"];
      }
    }
    return [true, 'listed domain'];
  }

  /** @return array{0:bool,1:string} */
  public function isAllowedHost(string $host): array {
    $host = strtolower(trim($host));
    if (filter_var($host, FILTER_VALIDATE_IP)) {
      if (!in_array($host, $this->ips, true)) return [false, "IP $host is not in the authorized scope"];
      return [true, 'listed IP'];
    }
    if (!self::hostInDomains($host, $this->domains)) {
      return [false, "host $host is not in the authorized scope"];
    }
    return [true, 'listed domain'];
  }

  /** @return array<int,string> */
  public static function lines(string $text): array {
    $out = [];
    foreach (preg_split('/\r\n|\r|\n/', $text) as $line) {
      $line = trim($line);
      if ($line !== '' && !str_starts_with($line, '#')) $out[] = $line;
    }
    return $out;
  }

  public static function cleanHost(string $s): string {
    $s = trim($s);
    $s = preg_replace('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', '', $s); // strip scheme
    $s = preg_split('#[/?\#\s]#', $s)[0];                       // strip path/query
    $s = preg_replace('/:\d+$/', '', $s);                         // strip port
    return strtolower(rtrim(trim($s), '.'));
  }

  /** @param array<int,string> $domains */
  private static function hostInDomains(string $host, array $domains): bool {
    foreach ($domains as $d) {
      if ($host === $d) return true;
      if (str_ends_with($host, '.' . $d)) return true; // subdomains included
    }
    return false;
  }
}

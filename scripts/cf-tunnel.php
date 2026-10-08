<?php
// Cloudflare named-tunnel provisioning for AIPenScan. No secrets in this file:
// the Global API key is read from a key file, the email from the environment.
//
//   printf '%s' "$CLOUDFLARE_TOKEN" > /tmp/aipenscan-cfkey && chmod 600 /tmp/aipenscan-cfkey
//   CF_KEY_FILE=/tmp/aipenscan-cfkey CF_EMAIL="$CLOUDFLARE_EMAIL" php scripts/cf-tunnel.php list
//   CF_KEY_FILE=/tmp/aipenscan-cfkey CF_EMAIL="$CLOUDFLARE_EMAIL" php scripts/cf-tunnel.php setup <zone_id> <hostname> [local_port]
//   shred -u /tmp/aipenscan-cfkey   # destroy the staged key when done
//
// setup: finds/creates tunnel 'aipenscan', sets remote ingress
// (hostname -> localhost:port), creates/updates the proxied DNS CNAME, and
// saves the run token (0600) + tunnel info into data/ (gitignored).
declare(strict_types=1);

$keyFile = getenv('CF_KEY_FILE') ?: '/tmp/aipenscan-cfkey';
$key = is_file($keyFile) ? trim(file_get_contents($keyFile)) : '';
$email = getenv('CF_EMAIL') ?: '';
if ($key === '' || $email === '') {
  fwrite(STDERR, "need key file ($keyFile) and CF_EMAIL env\n");
  exit(2);
}
define('AIPEN_DATA', dirname(__DIR__) . '/data');

function cf(string $method, string $path, $payload = null): array {
  global $key, $email;
  $ch = curl_init('https://api.cloudflare.com/client/v4' . $path);
  $headers = ['X-Auth-Email: ' . $email, 'X-Auth-Key: ' . $key, 'Content-Type: application/json'];
  curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers]);
  if ($payload !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
  $out = curl_exec($ch);
  $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
  curl_close($ch);
  $dec = json_decode((string)$out, true);
  return ['code' => $code, 'body' => $dec];
}

function cf_assert(array $r, string $what) {
  if ($r['code'] < 200 || $r['code'] >= 300) {
    fwrite(STDERR, "$what failed (HTTP {$r['code']}): " . substr(json_encode($r['body']), 0, 400) . "\n");
    exit(1);
  }
  $b = $r['body'];
  if (is_array($b) && array_key_exists('success', $b)) {
    if (empty($b['success'])) {
      fwrite(STDERR, "$what failed: " . substr(json_encode($b), 0, 400) . "\n");
      exit(1);
    }
    return $b['result'];
  }
  return $b; // raw (e.g. token string)
}

$step = $argv[1] ?? 'list';

if ($step === 'list') {
  $zones = cf_assert(cf('GET', '/zones?per_page=50'), 'list zones');
  foreach ($zones as $z) {
    echo $z['id'] . '  ' . $z['name'] . '  account=' . ($z['account']['id'] ?? '?') . ' status=' . ($z['status'] ?? '?') . "\n";
  }
  exit(0);
}

if ($step === 'setup') {
  [$zoneId, $hostname, $port] = [$argv[2] ?? '', $argv[3] ?? '', $argv[4] ?? '8091'];
  if ($zoneId === '' || $hostname === '') { fwrite(STDERR, "usage: setup <zone_id> <hostname> [port]\n"); exit(2); }
  $zone = cf_assert(cf('GET', "/zones/$zoneId"), 'get zone');
  $accountId = $zone['account']['id'];
  $zoneName = $zone['name'];
  echo "zone: $zoneName account: $accountId\n";

  // Find or create tunnel named 'aipenscan'.
  $tunnels = cf_assert(cf('GET', "/accounts/$accountId/cfd_tunnel?per_page=50"), 'list tunnels');
  if (is_array($tunnels) && array_key_exists('tunnels', $tunnels)) $tunnels = $tunnels['tunnels'];
  $tunnel = null;
  foreach ((array)$tunnels as $t) {
    if (!is_array($t)) continue;
    if (($t['name'] ?? '') === 'aipenscan' && empty($t['deleted_at'])) { $tunnel = $t; break; }
  }
  if ($tunnel === null) {
    $tunnel = cf_assert(cf('POST', "/accounts/$accountId/cfd_tunnel", ['name' => 'aipenscan']), 'create tunnel');
    echo "created tunnel: {$tunnel['id']}\n";
  } else {
    echo "reusing tunnel: {$tunnel['id']}\n";
  }
  $tid = $tunnel['id'];

  // Run token for `cloudflared tunnel run --token ...`.
  $tok = cf_assert(cf('GET', "/accounts/$accountId/cfd_tunnel/$tid/token"), 'get tunnel token');
  $runToken = is_array($tok) ? ($tok['token'] ?? '') : (string)$tok;
  if ($runToken === '') { fwrite(STDERR, "empty tunnel token\n"); exit(1); }

  // Remote ingress config: hostname -> local app.
  cf_assert(cf('PUT', "/accounts/$accountId/cfd_tunnel/$tid/configurations", ['config' => ['ingress' => [
    ['hostname' => $hostname, 'service' => "http://localhost:$port"],
    ['service' => 'http_status:404'],
  ]]]), 'set ingress config');
  echo "ingress set: $hostname -> http://localhost:$port\n";

  // DNS CNAME hostname -> <tunnel>.cfargotunnel.com (create or update).
  $short = preg_replace('/\.' . preg_quote($zoneName, '/') . '$/', '', $hostname);
  $target = "$tid.cfargotunnel.com";
  $existing = cf_assert(cf('GET', "/zones/$zoneId/dns_records?type=CNAME&name=" . urlencode($hostname)), 'list dns');
  if ($existing) {
    $rec = $existing[0];
    cf_assert(cf('PUT', "/zones/$zoneId/dns_records/{$rec['id']}", ['type' => 'CNAME', 'name' => $short, 'content' => $target, 'proxied' => true, 'ttl' => 1]), 'update dns');
    echo "dns updated: $hostname -> $target\n";
  } else {
    cf_assert(cf('POST', "/zones/$zoneId/dns_records", ['type' => 'CNAME', 'name' => $short, 'content' => $target, 'proxied' => true, 'ttl' => 1]), 'create dns');
    echo "dns created: $hostname -> $target\n";
  }

  file_put_contents(AIPEN_DATA . '/cf-tunnel-token', $runToken);
  chmod(AIPEN_DATA . '/cf-tunnel-token', 0600);
  file_put_contents(AIPEN_DATA . '/cf-tunnel.json', json_encode([
    'tunnel_id' => $tid, 'tunnel_name' => 'aipenscan', 'hostname' => $hostname,
    'zone' => $zoneName, 'local_port' => (int)$port, 'updated_at' => gmdate('c'),
  ], JSON_PRETTY_PRINT));
  echo "saved run token + tunnel info to data/\n";
  exit(0);
}

fwrite(STDERR, "unknown step\n");
exit(2);

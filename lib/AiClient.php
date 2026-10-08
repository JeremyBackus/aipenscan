<?php
declare(strict_types=1);

/** Minimal OpenAI-compatible chat completions client (curl). */
class AiClient {
  public function __construct(
    private string $apiKey,
    private string $baseUrl,
    private int $timeout = 180
  ) {
    $this->baseUrl = rtrim($baseUrl, '/');
  }

  /**
   * @param array<int,array> $messages
   * @return array decoded JSON response
   */
  public function chat(array $messages, array $opts): array {
    if (empty($opts['model'])) throw new InvalidArgumentException('chat: model is required');
    $payload = ['model' => $opts['model'], 'messages' => $messages];
    foreach (['temperature', 'max_tokens', 'tools', 'tool_choice', 'response_format'] as $k) {
      if (array_key_exists($k, $opts) && $opts[$k] !== null) $payload[$k] = $opts[$k];
    }
    [$code, $body] = $this->post('/chat/completions', $payload);
    $dec = json_decode($body, true);
    if ($code < 200 || $code >= 300) {
      throw new RuntimeException('AI API error HTTP ' . $code . ': ' . substr($body, 0, 500));
    }
    if (!is_array($dec) || !isset($dec['choices'][0]['message'])) {
      throw new RuntimeException('AI API returned an unexpected response: ' . substr($body, 0, 500));
    }
    return $dec;
  }

  public static function assistantText(array $response): string {
    return (string)($response['choices'][0]['message']['content'] ?? '');
  }

  /** @return array<int,array> tool calls in OpenAI format */
  public static function toolCalls(array $response): array {
    $msg = $response['choices'][0]['message'] ?? [];
    $calls = $msg['tool_calls'] ?? [];
    return is_array($calls) ? $calls : [];
  }

  public static function usage(array $response): array {
    return $response['usage'] ?? [];
  }

  /** List available model ids (used by setup --check). */
  public function listModels(): array {
    [$code, $body] = $this->get('/models');
    $dec = json_decode($body, true);
    if ($code < 200 || $code >= 300 || !isset($dec['data'])) {
      throw new RuntimeException('AI API error HTTP ' . $code . ': ' . substr($body, 0, 300));
    }
    $ids = [];
    foreach ($dec['data'] as $m) {
      if (isset($m['id'])) $ids[] = (string)$m['id'];
    }
    sort($ids);
    return $ids;
  }

  /** Strip code fences and decode a JSON object from model output. */
  public static function extractJson(string $text): array {
    $t = trim($text);
    if (str_starts_with($t, '```')) {
      $t = preg_replace('/^```[a-zA-Z0-9_-]*\s*/', '', $t);
      $t = preg_replace('/\s*```$/', '', $t);
    }
    $dec = json_decode(trim($t), true);
    if (is_array($dec)) return $dec;
    // Fall back to the largest {...} block.
    if (preg_match('/\{.*\}/s', $t, $m)) {
      $dec = json_decode($m[0], true);
      if (is_array($dec)) return $dec;
    }
    throw new RuntimeException('Could not parse JSON from model output: ' . substr($text, 0, 300));
  }

  /** @return array{0:int,1:string} [http code, body] */
  private function post(string $path, array $payload): array {
    $ch = curl_init($this->baseUrl . $path);
    $body = json_encode($payload);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $body,
      CURLOPT_TIMEOUT => $this->timeout,
      CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $this->apiKey,
      ],
    ]);
    $out = curl_exec($ch);
    if ($out === false) {
      $err = curl_error($ch);
      curl_close($ch);
      throw new RuntimeException('AI API request failed: ' . $err);
    }
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$code, (string)$out];
  }

  /** @return array{0:int,1:string} */
  private function get(string $path): array {
    $ch = curl_init($this->baseUrl . $path);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT => 30,
      CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $this->apiKey],
    ]);
    $out = curl_exec($ch);
    if ($out === false) {
      $err = curl_error($ch);
      curl_close($ch);
      throw new RuntimeException('AI API request failed: ' . $err);
    }
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$code, (string)$out];
  }
}

<?php
declare(strict_types=1);

/**
 * Sanitizes orchestrator-generated report HTML. Allows plain markup and
 * inline styles; strips anything executable or exfiltrating.
 */
class Sanitize {
  /** @return string safe HTML fragment */
  public static function html(string $html, bool $allowScripts): string {
    if ($allowScripts) return $html; // explicit operator opt-in, documented risk
    $html = trim($html);
    if ($html === '') return '';
    $prev = libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $doc->loadHTML('<div id="aipenroot">' . $html . '</div>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_use_internal_errors($prev);

    foreach (['script', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'form', 'input', 'textarea', 'select', 'button'] as $tag) {
      $nodes = $doc->getElementsByTagName($tag);
      for ($i = $nodes->length - 1; $i >= 0; $i--) {
        $n = $nodes->item($i);
        $n->parentNode->removeChild($n);
      }
    }
    $xp = new DOMXPath($doc);
    foreach ($xp->query('//*') as $el) {
      /** @var DOMElement $el */
      $remove = [];
      foreach ($el->attributes as $attr) {
        $name = strtolower($attr->name);
        $val = trim($attr->value);
        if (str_starts_with($name, 'on')) {
          $remove[] = $attr->name;
          continue;
        }
        if (in_array($name, ['href', 'src', 'xlink:href', 'action'], true)) {
          $low = strtolower(preg_replace('/\s+/', '', $val));
          if (str_starts_with($low, 'javascript:') || str_starts_with($low, 'data:text/html') || str_starts_with($low, 'vbscript:')) {
            $remove[] = $attr->name;
          }
        }
        if ($name === 'style' && preg_match('/expression\s*\(|behaviour\s*:/i', $val)) {
          $remove[] = $attr->name;
        }
      }
      foreach ($remove as $a) $el->removeAttribute($a);
    }
    $root = $doc->getElementById('aipenroot');
    if ($root === null) return '';
    $out = '';
    foreach ($root->childNodes as $child) $out .= $doc->saveHTML($child);
    return $out;
  }
}

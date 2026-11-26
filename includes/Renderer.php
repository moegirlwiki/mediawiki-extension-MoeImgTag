<?php

namespace Moegirl\ImgTag;

use MediaWiki\Html\Html;
use MediaWiki\MediaWikiServices;
use MediaWiki\Status\Status;
use MediaWiki\Parser\Parser;
use MediaWiki\Parser\PPFrame;
use MediaWiki\Parser\Sanitizer;

class Renderer {
  const IMG_SELF_CLOSING_MARK = 'data-img-unsafe-self-closing';

  public static function createImgElement(array $attribs = []) {
    $src = $attribs['src'] ?? '';

    // {{filepath:xxx|nowiki}} 可能会给出一个奇怪的 url，我们简单地处理一下
    if (strpos($src, '&#58;//') !== false) {
      // 替换 &#58; 为 :
      $src = str_replace('&#58;//', '://', $src);
    }
    // 如果开头是 //，我们补全协议
    if (strpos($src, '//') === 0) {
      $src = "https:$src";
    }

    if (empty($src)) {
      return ['', 'isHTML' => true];
    }

    $srcValidationStatus = self::validateSrc($src);
    if (!$srcValidationStatus->isGood()) {
      return [
        Html::rawElement(
          'span',
          [
            'class' => 'error moe-img-error',
            'data-src-input' => $src,
          ],
          $srcValidationStatus->getMessage()->text()
        ),
        'isError' => true,
        'isHTML' => true,
      ];
    }

    $attribs = array_merge($attribs, [
      'src' => $src,
      'style' => $attribs['style'] ?? '',
      'class' => $attribs['class'] ?? '',
    ]);
    $attribs = Sanitizer::validateTagAttributes($attribs, 'img');

    // 如果没有设置 loading 属性，则默认为 lazy
    if (isset($attribs['loading']) && $attribs['loading'] === 'eager') {
      $attribs['loading'] = 'eager';
    } else {
      $attribs['loading'] = 'lazy';
    }

    $html = Html::element('img', $attribs);

    return [
      $html,
      'isHTML' => true,
    ];
  }

  public static function renderImgTag($input, array $args, Parser $parser, PPFrame $ppframe) {
    $src = isset($args['src']) ? trim($args['src']) : '';
    $class = isset($args['class']) ? $args['class'] : '';

    // 在某些极其抽象的使用场景下，src 会出现在 $input 中
    // 比如用户错写成 <img>$input</img> 或者 {{ #tag:img | $input }}
    // 不论如何，我们还是处理一下
    if (empty($src) && !empty($input)) {
      $src = trim($input);
    }

    if (empty($src)) {
      return ''; // 如果 src 仍然为空，则不渲染 img 标签
    }

    $attribs = array_merge($args, [
      'src' => $src,
      'class' => $class ?? '',
    ]);

    // 添加额外属性方便维护
    $attribs['class'] .= ' moe-img-hook';

    return self::createImgElement($attribs);
  }

  public static function renderImgFunction(Parser $parser, ...$args): string|array {
    $options = self::extractParserFunctionOptions($args);
    $src = $options['src'] ?? $args[0] ?? '';
    if (empty($src)) {
      return '';
    }

    $attribs = array_merge($options, [
      'src' => $src,
      'class' => $options['class'] ?? '',
    ]);

    // 添加额外属性方便维护
    $attribs['class'] .= ' moe-img-function';

    switch ($parser->getOutputType()) {
      case Parser::OT_WIKI:
        return $attribs['src'];
      case Parser::OT_PLAIN:
        return [$attribs['src'], 'noparse' => true];
      default:
        return self::createImgElement($attribs);
    }
  }

  private static function extractParserFunctionOptions(array $options): array {
    $results = [];
    foreach ($options as $option) {
      $pair = array_map('trim', explode('=', $option, 2));
      if (count($pair) === 2) {
        $results[$pair[0]] = $pair[1];
      }
      if (count($pair) === 1) {
        $results[$pair[0]] = true;
      }
    }
    return $results;
  }

  public static function validateSrc($src = '') {
    $src = trim($src);
    $status = Status::newGood();

    $conf = MediaWikiServices::getInstance()->getMainConfig();
    $whiteList = $conf->get('MoeImgTagWhitelist');
    $blackList = $conf->get('MoeImgTagBlacklist');

    if (empty($src)) {
      return $status->newFatal('imgtag-empty-src');
    }

    // 禁止 ASCII 控制字符，防止绕过协议与域名校验
    if (preg_match('/[\x00-\x1f\x7f]/', $src)) {
      return $status->newFatal('imgtag-invalid-src');
    }

    // 禁止危险协议
    if (preg_match('/^\s*(data:|blob:|javascript:|vbscript:|file:|ftp:)/i', $src)) {
      return $status->newFatal('imgtag-invalid-src');
    }

    // 检查URL编码绕过
    $decodedSrc = urldecode($src);
    if (preg_match('/[\x00-\x1f\x7f]/', $decodedSrc) ||
        preg_match('/^\s*(data:|blob:|javascript:|vbscript:|file:|ftp:)/i', $decodedSrc)) {
      return $status->newFatal('imgtag-invalid-src');
    }

    $normalizedForParse = self::normalizeUrlForParsing($src);
    $parsedSrc = parse_url($normalizedForParse);
    if ($parsedSrc === false || !isset($parsedSrc['host']) || $parsedSrc['host'] === '') {
      return $status->newFatal('imgtag-invalid-src');
    }

    if (isset($parsedSrc['path']) && self::hasTraversalSegment($parsedSrc['path'])) {
      return $status->newFatal('imgtag-invalid-src');
    }

    // Check against whitelist
    if (!empty($whiteList) && !self::checkUrlMatch($src, $whiteList)) {
      return $status->newFatal('imgtag-not-whitelisted-src');
    }

    // Check against blacklist
    if (!empty($blackList) && self::checkUrlMatch($src, $blackList)) {
      return $status->newFatal('imgtag-blacklisted-src');
    }

    return $status;
  }

  /**
   * 检查给定的 URL 是否与指定的域名列表匹配
   *
   * @param string $url 要检查的 URL
   * @param array $patterns
   * 域名列表，其中每一项可能是一下情况之一：
   * - 主机名，如 'example.com'
   * - 带通配符的主机名，如 '*.example.com'
   * - 完整的 URL，如 'https://example.com'
   * - 带通配符的完整 URL，如 'https://*.example.com'
   * - 带有路径限定的 URL，如 'https://example.com/path'
   * - 带通配符的路径限定 URL，如 'https://*.example.com/path'
   * 
   * 匹配的例子：
   * - 'example.com' 将匹配 'http://example.com'、'https://example.com'、或者任何位于 'example.com' 的网址如 'http://example.com/path/to/resource'。
   * - '*.example.com' 将匹配 'http://sub.example.com'、'https://another.sub.example.com'，但不会匹配 'example.com' 或 'example.org'。
   * - 'https://example.com' 将匹配 'https://example.com'，但不会匹配 'http://example.com' 或 'https://anotherdomain.com'。
   * - 'https://*.example.com' 将匹配 'https://sub.example.com'，但不会匹配 'http://example.com' 或 'https://anotherdomain.com'。
   * - 'https://example.com/path' 将匹配 'https://example.com/path/to/resource'，但不会匹配 'https://example.com/anotherpath'。
   * - 'https://*.example.com/path' 将匹配 'https://sub.example.com/path/to/resource'，但不会匹配 'https://example.com/anotherpath' 或 'http://sub.example.com/path/to/resource'。
   * 
   * @return bool 如果 URL 匹配任意一个模式，则返回 true；否则返回 false
   */
  public static function checkUrlMatch(string $url, array $patterns): bool {
    $normalizedUrl = self::normalizeUrlForParsing($url);
    $parsedUrl = parse_url($normalizedUrl);
    if ($parsedUrl === false || !isset($parsedUrl['host']) || $parsedUrl['host'] === '') {
      return false; // 无效的 URL
    }

    // 拒绝包含 .. 路径遍历段（含多次编码）的 URL
    if (isset($parsedUrl['path']) && self::hasTraversalSegment($parsedUrl['path'])) {
      return false;
    }

    foreach ($patterns as $pattern) {
      if (is_string($pattern) && self::matchSinglePattern($parsedUrl, $pattern)) {
        return true;
      }
    }

    return false;
  }

  private static function normalizeUrlForParsing(string $url): string {
    // 浏览器会在解析 HTTP(S) URL 前去除 ASCII 控制字符，并将路径/权限部中的反斜杠视为正斜杠
    $url = preg_replace('/[\x00-\x1f\x7f]/', '', $url);
    $splitPos = strcspn($url, '?#');
    $authorityAndPath = str_replace('\\', '/', substr($url, 0, $splitPos));
    return $authorityAndPath . substr($url, $splitPos);
  }

  private static function matchSinglePattern(array $parsedUrl, string $pattern): bool {
    $pattern = trim($pattern);
    if ($pattern === '') {
      return false;
    }

    $hasScheme = strpos($pattern, '://') !== false;
    $isProtocolRelative = strpos($pattern, '//') === 0;
    $parsedPattern = parse_url(($hasScheme || $isProtocolRelative) ? $pattern : '//' . $pattern);
    if ($parsedPattern === false || !isset($parsedPattern['host']) || $parsedPattern['host'] === '') {
      return false;
    }

    $urlScheme = strtolower($parsedUrl['scheme'] ?? '');
    $patternScheme = isset($parsedPattern['scheme']) ? strtolower($parsedPattern['scheme']) : null;

    // 如果模式指定了协议，则必须匹配协议
    if ($patternScheme !== null && $urlScheme !== $patternScheme) {
      return false;
    }

    // 匹配主机名（支持通配符）
    if (!self::matchHost($parsedUrl['host'], $parsedPattern['host'])) {
      return false;
    }

    // 端口校验：模式指定了端口则精确匹配；模式指定了协议但未指定端口时，校验是否为该协议默认端口
    $urlPort = $parsedUrl['port'] ?? self::getDefaultPort($urlScheme);
    if (isset($parsedPattern['port'])) {
      if ($urlPort !== $parsedPattern['port']) {
        return false;
      }
    } elseif ($patternScheme !== null) {
      $defaultPatternPort = self::getDefaultPort($patternScheme);
      if ($defaultPatternPort !== null && $urlPort !== $defaultPatternPort) {
        return false;
      }
    }

    // 如果模式指定了路径，则禁止模式中出现 .. 段并按路径段前缀匹配
    $rawPatternPath = $parsedPattern['path'] ?? '';
    if ($rawPatternPath !== '' && $rawPatternPath !== '/') {
      if (self::hasTraversalSegment($rawPatternPath)) {
        return false;
      }
      $patternPath = self::normalizePath($rawPatternPath);
      if ($patternPath !== '/') {
        $urlPath = self::normalizePath($parsedUrl['path'] ?? '/');
        if (str_ends_with($patternPath, '/')) {
          if (!str_starts_with($urlPath, $patternPath)) {
            return false;
          }
        } else {
          if ($urlPath !== $patternPath && !str_starts_with($urlPath, $patternPath . '/')) {
            return false;
          }
        }
      }
    }

    // 如果模式指定了查询字符串，则保留重复键并严格比对解析后的查询参数
    if (isset($parsedPattern['query'])) {
      if (!isset($parsedUrl['query'])) {
        return false;
      }
      if (self::parseQueryPreservingDuplicates($parsedUrl['query']) !==
          self::parseQueryPreservingDuplicates($parsedPattern['query'])) {
        return false;
      }
    }

    return true;
  }

  private static function getDefaultPort(string $scheme): ?int {
    return match ($scheme) {
      'http' => 80,
      'https' => 443,
      default => null,
    };
  }

  private static function hasTraversalSegment(string $path): bool {
    $current = $path;
    for ($i = 0; $i < 10; $i++) {
      if (in_array('..', explode('/', $current), true)) {
        return true;
      }
      $next = rawurldecode($current);
      if ($next === $current) {
        break;
      }
      $current = $next;
    }
    return in_array('..', explode('/', $current), true);
  }

  private static function normalizePath(string $path): string {
    $decoded = rawurldecode($path);
    $segments = explode('/', $decoded);
    $resolved = [];

    foreach ($segments as $segment) {
      if ($segment === '' || $segment === '.') {
        continue;
      }
      $resolved[] = $segment;
    }

    $normalized = '/' . implode('/', $resolved);
    if (str_ends_with($decoded, '/') && $normalized !== '/') {
      $normalized .= '/';
    }

    return $normalized;
  }

  private static function parseQueryPreservingDuplicates(string $query): array {
    if ($query === '') {
      return [];
    }
    $params = [];
    foreach (explode('&', $query) as $part) {
      if ($part === '') {
        continue;
      }
      $pair = explode('=', $part, 2);
      $key = urldecode($pair[0]);
      $value = isset($pair[1]) ? urldecode($pair[1]) : '';
      $params[$key][] = $value;
    }
    ksort($params, SORT_STRING);
    return $params;
  }

  private static function canonicalizeHost(string $host): string {
    $host = strtolower(rawurldecode($host));
    $host = rtrim($host, '.');
    if ($host === '') {
      return '';
    }

    // 处理 IPv6 方括号主机名（如 [0:0:0:0:0:0:0:1] -> [::1]）
    if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
      $ipv6 = substr($host, 1, -1);
      $packed = @inet_pton($ipv6);
      if ($packed !== false) {
        return '[' . inet_ntop($packed) . ']';
      }
      return $host;
    }

    // 处理浏览器兼容的 IPv4 多种写法（十进制整数、十六进制、八进制、简写等）
    $canonicalIpv4 = self::canonicalizeIpv4($host);
    if ($canonicalIpv4 !== null) {
      return $canonicalIpv4;
    }

    // 处理国际化域名 (IDNA)
    if (preg_match('/[^\x00-\x7f]/', $host) && function_exists('idn_to_ascii')) {
      $labels = explode('.', $host);
      foreach ($labels as &$label) {
        if ($label !== '' && strpos($label, '*') === false && preg_match('/[^\x00-\x7f]/', $label)) {
          $ascii = idn_to_ascii($label, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
          if ($ascii !== false) {
            $label = $ascii;
          }
        }
      }
      $host = implode('.', $labels);
    }

    return $host;
  }

  private static function canonicalizeIpv4(string $host): ?string {
    $parts = explode('.', $host);
    $count = count($parts);
    if ($count < 1 || $count > 4) {
      return null;
    }

    $nums = [];
    foreach ($parts as $part) {
      if ($part === '') {
        return null;
      }
      $val = self::parseIpv4Number($part);
      if ($val === null) {
        return null;
      }
      $nums[] = $val;
    }

    for ($i = 0; $i < $count - 1; $i++) {
      if ($nums[$i] > 255) {
        return null;
      }
    }

    $lastLimit = 256 ** (5 - $count);
    if ($nums[$count - 1] >= $lastLimit) {
      return null;
    }

    $ipv4 = $nums[$count - 1];
    for ($i = 0; $i < $count - 1; $i++) {
      $ipv4 += $nums[$i] * (256 ** (3 - $i));
    }

    return long2ip($ipv4);
  }

  private static function parseIpv4Number(string $input): ?int {
    if (preg_match('/^0[xX]([0-9a-fA-F]+)$/', $input, $m)) {
      $val = hexdec($m[1]);
      return is_int($val) && $val >= 0 && $val <= 0xFFFFFFFF ? $val : null;
    }
    if (preg_match('/^0([0-7]+)$/', $input, $m)) {
      $val = octdec($m[1]);
      return is_int($val) && $val >= 0 && $val <= 0xFFFFFFFF ? $val : null;
    }
    if (preg_match('/^[0-9]+$/', $input)) {
      if ($input === '0') {
        return 0;
      }
      if (str_starts_with($input, '0')) {
        return null;
      }
      $val = (int)$input;
      return (string)$val === $input && $val >= 0 && $val <= 0xFFFFFFFF ? $val : null;
    }
    return null;
  }

  private static function matchHost(string $host, string $pattern): bool {
    $host = self::canonicalizeHost($host);
    $pattern = self::canonicalizeHost($pattern);

    if ($host === '' || $pattern === '' || $host[0] === '.') {
      return false;
    }

    if (strpos($pattern, '*') === false) {
      return $host === $pattern;
    }

    $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/';
    return preg_match($regex, $host) === 1;
  }
}
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
  private const MAX_HOST_LENGTH = 253;
  private const MAX_RAW_HOST_LENGTH = 1024;
  private static array $loggedConfigErrors = [];

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

    // 仅允许 http/https 协议（以及未展开的 // 协议相对 URL），防止 gopher:/ws: 等未知协议绕过
    if (isset($parsedSrc['scheme'])) {
      if (!in_array(strtolower($parsedSrc['scheme']), ['http', 'https'], true)) {
        return $status->newFatal('imgtag-invalid-src');
      }
    } elseif (!str_starts_with($normalizedForParse, '//')) {
      return $status->newFatal('imgtag-invalid-src');
    }

    if (isset($parsedSrc['path']) && self::hasTraversalSegment($parsedSrc['path'])) {
      return $status->newFatal('imgtag-invalid-src');
    }

    if (self::canonicalizeHost($parsedSrc['host']) === null) {
      return $status->newFatal('imgtag-invalid-src');
    }

    // Check against whitelist (白名单与黑名单互斥，若同时设置则只使用白名单)
    if (!self::validateListConfig('MoeImgTagWhitelist', $whiteList)) {
      return $status->newFatal('imgtag-invalid-config');
    }
    if ($whiteList !== []) {
      if (!self::checkUrlMatch($src, $whiteList)) {
        return $status->newFatal('imgtag-not-whitelisted-src');
      }
    } else {
      // Check against blacklist
      if (!self::validateListConfig('MoeImgTagBlacklist', $blackList)) {
        return $status->newFatal('imgtag-invalid-config');
      }
      if ($blackList !== []) {
        if (self::checkUrlMatch($src, $blackList)) {
          return $status->newFatal('imgtag-blacklisted-src');
        }
      }
    }

    return $status;
  }

  public static function validateConfig(): bool {
    $conf = MediaWikiServices::getInstance()->getMainConfig();
    $whiteListOk = self::validateListConfig('MoeImgTagWhitelist', $conf->get('MoeImgTagWhitelist'));
    $blackListOk = self::validateListConfig('MoeImgTagBlacklist', $conf->get('MoeImgTagBlacklist'));
    return $whiteListOk && $blackListOk;
  }

  private static function validateListConfig(string $configName, $patterns): bool {
    if (!is_array($patterns)) {
      self::logConfigErrorOnce(
        $configName,
        "Invalid \$wg{$configName} configuration: expected array, got " . gettype($patterns)
      );
      return false;
    }

    foreach ($patterns as $index => $pattern) {
      if (!is_string($pattern) || self::parsePattern($pattern) === null) {
        self::logConfigErrorOnce(
          $configName,
          "Invalid pattern at index {$index} in \$wg{$configName}"
        );
        return false;
      }
    }

    return true;
  }

  private static function logConfigErrorOnce(string $configName, string $message): void {
    $key = $configName . ':' . $message;
    if (isset(self::$loggedConfigErrors[$key])) {
      return;
    }
    self::$loggedConfigErrors[$key] = true;

    if (class_exists(\MediaWiki\Logger\LoggerFactory::class)) {
      \MediaWiki\Logger\LoggerFactory::getInstance('MoeImgTag')->error($message);
    } elseif (function_exists('wfLogWarning')) {
      wfLogWarning("[MoeImgTag] {$message}");
    }
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

    // 仅允许 http/https 协议（或未展开的 // 协议相对 URL），防止外部调用方误放行非 HTTP(S) 协议
    if (isset($parsedUrl['scheme'])) {
      if (!in_array(strtolower($parsedUrl['scheme']), ['http', 'https'], true)) {
        return false;
      }
    } elseif (!str_starts_with($normalizedUrl, '//')) {
      return false;
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
    // 浏览器会在解析 HTTP(S) URL 前去除首尾空白与 ASCII 控制字符，并将路径/权限部中的反斜杠视为正斜杠
    $url = trim(preg_replace('/[\x00-\x1f\x7f]/', '', $url));
    $splitPos = strcspn($url, '?#');
    $authorityAndPath = str_replace('\\', '/', substr($url, 0, $splitPos));
    return $authorityAndPath . substr($url, $splitPos);
  }

  private static function parsePattern(string $pattern): ?array {
    $pattern = trim($pattern);
    if ($pattern === '' || preg_match('/[\x00-\x1f\x7f]/', $pattern)) {
      return null;
    }

    $hasScheme = strpos($pattern, '://') !== false;
    $isProtocolRelative = strpos($pattern, '//') === 0;
    $parsedPattern = parse_url(($hasScheme || $isProtocolRelative) ? $pattern : '//' . $pattern);
    if ($parsedPattern === false || !isset($parsedPattern['host']) || $parsedPattern['host'] === '') {
      return null;
    }

    if (isset($parsedPattern['scheme']) &&
        !in_array(strtolower($parsedPattern['scheme']), ['http', 'https'], true)) {
      return null;
    }

    if (self::canonicalizeHost($parsedPattern['host'], true) === null) {
      return null;
    }

    if (isset($parsedPattern['path']) && self::hasTraversalSegment($parsedPattern['path'])) {
      return null;
    }

    return $parsedPattern;
  }

  private static function matchSinglePattern(array $parsedUrl, string $pattern): bool {
    $parsedPattern = self::parsePattern($pattern);
    if ($parsedPattern === null) {
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
    $path = str_replace('\\', '/', $path);
    foreach (explode('/', $path) as $segment) {
      if ($segment === '..') {
        return true;
      }
      if (strpos($segment, '%') !== false && self::segmentDecodesToTraversal($segment)) {
        return true;
      }
    }
    return false;
  }

  private static function segmentDecodesToTraversal(string $segment): bool {
    $current = $segment;
    for ($i = 0; $i < 64; $i++) {
      // 线性折叠任意层数的 %25（如 %25252e -> %2e），避免对长路径重复全量扫描
      $collapsed = preg_replace('/%(?:25)+([0-9a-fA-F]{2})/', '%$1', $current);
      $decoded = str_replace('\\', '/', rawurldecode($collapsed));

      if (in_array('..', explode('/', $decoded), true)) {
        return true;
      }
      if ($decoded === $current || strpos($decoded, '%') === false) {
        return false;
      }
      // 若解码出了新的斜杠，仅继续检查含 % 的子段
      if (strpos($decoded, '/') !== false) {
        foreach (explode('/', $decoded) as $sub) {
          if ($sub !== '' && strpos($sub, '%') !== false && self::segmentDecodesToTraversal($sub)) {
            return true;
          }
        }
        return false;
      }
      $current = $decoded;
    }
    // 超过极端嵌套层数直接按不安全拒绝
    return true;
  }

  private static function normalizePath(string $path): string {
    $path = str_replace('\\', '/', $path);
    $trimmed = str_starts_with($path, '/') ? substr($path, 1) : $path;
    $segments = explode('/', $trimmed);
    $resolved = [];
    $lastIndex = count($segments) - 1;
    $endsWithDot = false;

    foreach ($segments as $idx => $segment) {
      // 仅对非 %25 / %2F / %5C 的转义解码，并统一保留转义的大小写形式，防止 %252F 折叠为 %2F
      $decodedSegment = preg_replace_callback(
        '/%[0-9a-fA-F]{2}/',
        static function (array $m): string {
          $upper = strtoupper($m[0]);
          if ($upper === '%25' || $upper === '%2F' || $upper === '%5C') {
            return $upper;
          }
          return rawurldecode($m[0]);
        },
        $segment
      );
      if ($decodedSegment === '.') {
        if ($idx === $lastIndex) {
          $endsWithDot = true;
        }
        continue;
      }
      $resolved[] = $decodedSegment;
    }

    $normalized = '/' . implode('/', $resolved);
    if ($endsWithDot && $normalized !== '/' && !str_ends_with($normalized, '/')) {
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

  private static function canonicalizeHost(string $host, bool $allowWildcard = false): ?string {
    if ($host === '' || strlen($host) > self::MAX_RAW_HOST_LENGTH) {
      return null;
    }

    $host = strtolower(rawurldecode($host));
    if ($host === '' || strlen($host) > self::MAX_RAW_HOST_LENGTH) {
      return null;
    }

    if (!$allowWildcard && strpos($host, '*') !== false) {
      return null;
    }

    // 处理 IPv6 方括号主机名（如 [0:0:0:0:0:0:0:1] -> [::1]）
    if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
      $ipv6 = substr($host, 1, -1);
      $packed = @inet_pton($ipv6);
      if ($packed === false) {
        return null;
      }
      return '[' . inet_ntop($packed) . ']';
    }

    // 先处理国际化域名 (IDNA 非过渡模式)，使全角点（如 。）等字符先转换为标准 ASCII 点再做后续校验
    if (preg_match('/[^\x00-\x7f]/', $host)) {
      if (!function_exists('idn_to_ascii')) {
        return null;
      }
      $flags = defined('IDNA_NONTRANSITIONAL_TO_ASCII') ? IDNA_NONTRANSITIONAL_TO_ASCII : IDNA_DEFAULT;
      $labels = explode('.', $host);
      foreach ($labels as &$label) {
        if ($label !== '' && preg_match('/[^\x00-\x7f]/', $label)) {
          if (strpos($label, '*') !== false) {
            return null;
          }
          $idnaInfo = [];
          $ascii = idn_to_ascii($label, $flags, INTL_IDNA_VARIANT_UTS46, $idnaInfo);
          if ($ascii === false || ($idnaInfo['errors'] ?? 0) !== 0) {
            return null;
          }
          $label = $ascii;
        }
      }
      $host = implode('.', $labels);
    }

    // 浏览器仅将单个末尾点视为规范 FQDN，连续点（如 example.com..）为非法主机名
    if (str_ends_with($host, '.')) {
      $host = substr($host, 0, -1);
    }
    if ($host === '' || strlen($host) > self::MAX_HOST_LENGTH || $host[0] === '.' ||
        str_ends_with($host, '.') || strpos($host, '..') !== false ||
        preg_match('/[\s\/\\\\@:]/', $host)) {
      return null;
    }

    // 处理浏览器兼容的 IPv4 多种写法（十进制整数、十六进制、八进制、简写等）
    $canonicalIpv4 = self::canonicalizeIpv4($host);
    if ($canonicalIpv4 !== null) {
      return $canonicalIpv4;
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
    if (preg_match('/^0[xX]([0-9a-fA-F]*)$/', $input, $m)) {
      if ($m[1] === '') {
        return 0;
      }
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
    $host = self::canonicalizeHost($host, false);
    $pattern = self::canonicalizeHost($pattern, true);

    if ($host === null || $pattern === null) {
      return false;
    }

    if (strpos($pattern, '*') === false) {
      return $host === $pattern;
    }

    // 前导 *. 通配符必须匹配至少一个非空子域名标签，不能匹配根域名本身
    if (str_starts_with($pattern, '*.')) {
      $rest = substr($pattern, 2);
      if (strpos($rest, '*') === false) {
        $suffix = '.' . $rest;
        if (!str_ends_with($host, $suffix) || strlen($host) <= strlen($suffix)) {
          return false;
        }
        $sub = substr($host, 0, -strlen($suffix));
        return $sub !== '' && !str_ends_with($sub, '.');
      }

      // 若后续模式仍含 *（如 *.cdn.*.example.com），要求至少跳过一个非空子域名标签和点
      $offset = 0;
      while (($dotPos = strpos($host, '.', $offset)) !== false) {
        if ($dotPos > 0 && $host[$dotPos - 1] !== '.' &&
            self::matchGlob($rest, substr($host, $dotPos + 1))) {
          return true;
        }
        $offset = $dotPos + 1;
      }
      return false;
    }

    return self::matchGlob($pattern, $host);
  }

  private static function matchGlob(string $pattern, string $text): bool {
    $parts = explode('*', $pattern);
    $partCount = count($parts);
    if ($partCount === 1) {
      return $pattern === $text;
    }

    $prefix = $parts[0];
    if ($prefix !== '' && !str_starts_with($text, $prefix)) {
      return false;
    }
    $pos = strlen($prefix);

    $suffix = $parts[$partCount - 1];
    $end = strlen($text);
    if ($suffix !== '') {
      if (!str_ends_with($text, $suffix)) {
        return false;
      }
      $end -= strlen($suffix);
    }

    if ($pos > $end) {
      return false;
    }

    for ($i = 1; $i < $partCount - 1; $i++) {
      $segment = $parts[$i];
      if ($segment === '') {
        continue;
      }
      $found = strpos($text, $segment, $pos);
      if ($found === false || $found + strlen($segment) > $end) {
        return false;
      }
      $pos = $found + strlen($segment);
    }

    return true;
  }
}
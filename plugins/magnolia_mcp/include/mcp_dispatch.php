<?php

function mcp_limit_param(string $action): ?string
{
    $keys = [
        'do_search' => 'fetchrows',
        'search_get_previews' => 'fetchrows',
        'get_users' => 'fetchrows',
        'get_resource_log' => 'fetchrows',
        'resource_log_last_rows' => 'maxrecords',
    ];
    return $keys[$action] ?? null;
}

function mcp_build_query(string $function, array $params): string
{
    $out = ['function' => $function];
    foreach ($params as $k => $v) {
        if ($k === 'function') {
            continue;
        }
        if (is_array($v) || is_object($v)) {
            $out[$k] = json_encode($v);
        } else {
            $out[$k] = $v;
        }
    }
    return http_build_query($out);
}

function mcp_inject_limits(string $action, array $params): array
{
    $key = mcp_limit_param($action);
    if ($key === null) {
        return $params;
    }
    $n = (int) ($params[$key] ?? $params['limit'] ?? 50);
    $params[$key] = $n < 1 ? 50 : $n;
    return $params;
}

function mcp_url_param_keys(string $action): array
{
    $keys = [
        'create_resource' => ['url'],
        'upload_file_by_url' => ['url'],
        'replace_resource_file' => ['file_location', 'url'],
        'add_alternative_file' => ['file'],
    ];
    return $keys[$action] ?? [];
}

function mcp_ssrf_ipv4_ranges(): array
{
    return [
        ['10.0.0.0', '10.255.255.255'],
        ['172.16.0.0', '172.31.255.255'],
        ['192.168.0.0', '192.168.255.255'],
        ['127.0.0.0', '127.255.255.255'],
        ['169.254.0.0', '169.254.255.255'],
        ['0.0.0.0', '0.255.255.255'],
    ];
}

function mcp_ssrf_range_label(): string
{
    $parts = [];
    foreach (mcp_ssrf_ipv4_ranges() as [$a, $b]) {
        $parts[] = $a . '-' . $b;
    }
    $parts[] = '::1';
    $parts[] = 'fe80::/10';
    $parts[] = 'fc00::/7';
    return implode(', ', $parts);
}

function mcp_truncate_decoded($decoded, int $max_bytes = 51200): array
{
    $json = json_encode($decoded);
    if ($json === false) {
        return ['text' => json_encode(['error' => 'json_encode failed']), 'truncated' => false];
    }
    if (strlen($json) <= $max_bytes) {
        return ['text' => $json, 'truncated' => false];
    }
    if (!is_array($decoded)) {
        return ['text' => json_encode(['truncated' => true, 'notice' => 'Result exceeded size cap']), 'truncated' => true];
    }
    $list = array_is_list($decoded);
    $notice = ['truncated' => true, 'notice' => $list ? 'Result truncated; narrow the query' : 'Result exceeded size cap'];
    $acc = [];
    foreach ($decoded as $k => $v) {
        $try = $acc;
        $try[$k] = $v;
        if ($list) {
            $try[] = $notice;
        } else {
            $try['_notice'] = $notice;
        }
        if (strlen(json_encode($try)) > $max_bytes) {
            break;
        }
        $acc[$k] = $v;
    }
    if ($list) {
        $acc[] = $notice;
    } else {
        $acc['_notice'] = $notice;
    }
    return ['text' => json_encode($acc), 'truncated' => true];
}

function mcp_execute(string $action, array $params): array
{
    $params = mcp_inject_limits($action, $params);
    $query = mcp_build_query($action, $params);
    $prior = http_response_code();
    $prior = $prior === false ? 200 : (int) $prior;
    try {
        $raw = execute_api_call($query, false);
    } catch (Throwable $e) {
        $raw = $e;
    }
    if (!headers_sent()) {
        http_response_code($prior);
    }
    if ($raw instanceof Throwable) {
        return ['isError' => true, 'text' => $raw->getMessage(), 'http' => $prior];
    }
    if ($raw === false) {
        return ['isError' => true, 'text' => 'Unknown or failed API function', 'http' => $prior];
    }
    $decoded = json_decode((string) $raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $decoded = $raw;
    }
    if ($decoded === false || $decoded === null) {
        return ['isError' => true, 'text' => (string) $raw, 'http' => $prior];
    }
    if (is_string($decoded) && strncasecmp($decoded, 'FAILED:', 7) === 0) {
        return ['isError' => true, 'text' => $decoded, 'http' => $prior];
    }
    $trunc = mcp_truncate_decoded($decoded);
    $is_error = is_array($decoded) && in_array($decoded['status'] ?? '', ['fail', 'error'], true);
    return ['isError' => $is_error, 'text' => $trunc['text'], 'http' => $prior];
}

function mcp_strip_brackets(string $host): string
{
    if (strlen($host) >= 2 && $host[0] === '[' && str_ends_with($host, ']')) {
        return substr($host, 1, -1);
    }
    return $host;
}

function mcp_normalize_ip(string $ip): ?string
{
    $ip = mcp_strip_brackets($ip);
    $packed = inet_pton($ip);
    if ($packed === false) {
        return null;
    }
    if (strlen($packed) === 16) {
        $prefix = substr($packed, 0, 12);
        $mapped = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
        $compat = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        if ($prefix === $mapped || $prefix === $compat) {
            $v4 = inet_ntop(substr($packed, 12, 4));
            return $v4 === false ? null : $v4;
        }
    }
    $canonical = inet_ntop($packed);
    return $canonical === false ? null : $canonical;
}

function mcp_ip_blocked(string $ip): bool
{
    $normalized = mcp_normalize_ip($ip);
    if ($normalized === null) {
        return true;
    }
    if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($normalized);
        if ($long === false) {
            return true;
        }
        foreach (mcp_ssrf_ipv4_ranges() as [$a, $b]) {
            if ($long >= ip2long($a) && $long <= ip2long($b)) {
                return true;
            }
        }
        return false;
    }
    if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $packed = inet_pton($normalized);
        if ($packed === false) {
            return true;
        }
        $first = ord($packed[0]);
        if ($first === 0xfe && (ord($packed[1]) & 0xc0) === 0x80) {
            return true; // fe80::/10
        }
        if (($first & 0xfe) === 0xfc) {
            return true; // fc00::/7
        }
        return false;
    }
    return true;
}

if (!function_exists('mcp_resolve_ips')) {
    function mcp_resolve_ips(string $host): array
    {
        $ips = [];
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) {
            foreach ($v4 as $ip) {
                if (is_string($ip) && $ip !== '') {
                    $ips[] = $ip;
                }
            }
        }
        $records = @dns_get_record($host, DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $row) {
                if (isset($row['ipv6']) && is_string($row['ipv6'])) {
                    $ips[] = $row['ipv6'];
                }
            }
        }
        return array_values(array_unique($ips));
    }
}

function mcp_host_public(string $host): array
{
    $host = mcp_strip_brackets($host);
    $literal = mcp_normalize_ip($host);
    if ($literal !== null) {
        if (mcp_ip_blocked($literal)) {
            return ['ok' => false, 'error' => 'URL host is not allowed'];
        }
        return ['ok' => true, 'error' => null];
    }
    $ips = mcp_resolve_ips($host);
    if ($ips === []) {
        return ['ok' => false, 'error' => 'URL host could not be resolved'];
    }
    foreach ($ips as $ip) {
        if (mcp_ip_blocked($ip)) {
            return ['ok' => false, 'error' => 'URL host resolves to a private address'];
        }
    }
    return ['ok' => true, 'error' => null];
}

function mcp_url_allowed(string $url): array
{
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return ['ok' => false, 'error' => 'Invalid URL'];
    }
    $scheme = strtolower($parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        return ['ok' => false, 'error' => 'Only http(s) URLs are allowed'];
    }
    $host = mcp_strip_brackets((string) $parts['host']);
    $public = mcp_host_public($host);
    if (!$public['ok']) {
        return $public;
    }
    global $api_upload_urls;
    if (isset($api_upload_urls) && is_array($api_upload_urls)) {
        if ($api_upload_urls === []) {
            return ['ok' => false, 'error' => 'URL upload blocked: $api_upload_urls is empty; add hosts in ResourceSpace config'];
        }
        if (!in_array($host, $api_upload_urls, true)) {
            return ['ok' => false, 'error' => 'URL host is not in $api_upload_urls'];
        }
    }
    return ['ok' => true, 'error' => null];
}

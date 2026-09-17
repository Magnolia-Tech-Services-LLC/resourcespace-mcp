<?php

include_once __DIR__ . '/mcp_oauth_store.php';
include_once __DIR__ . '/mcp_dispatch.php';

function mcp_cimd_url_allowed(string $url): array
{
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return ['ok' => false, 'error' => 'Invalid URL'];
    }
    if (strtolower((string) $parts['scheme']) !== 'https') {
        return ['ok' => false, 'error' => 'Only https URLs are allowed'];
    }
    return mcp_host_public((string) $parts['host']);
}

if (!function_exists('mcp_http_get')) {
    function mcp_http_get(string $url, int $timeout, int $max_bytes, int $max_redirects): array
    {
        $current = $url;
        $left = $max_redirects;
        while (true) {
            $allowed = mcp_cimd_url_allowed($current);
            if (!$allowed['ok']) {
                return ['ok' => false, 'status' => 0, 'body' => '', 'error' => (string) $allowed['error']];
            }
            $headers = [];
            $ch = curl_init($current);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
            curl_setopt($ch, CURLOPT_MAXFILESIZE, $max_bytes);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $header) use (&$headers) {
                $len = strlen($header);
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return $len;
            });
            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($body === false) {
                return ['ok' => false, 'status' => $status, 'body' => '', 'error' => $err !== '' ? $err : 'fetch failed'];
            }
            if (strlen((string) $body) > $max_bytes) {
                return ['ok' => false, 'status' => $status, 'body' => '', 'error' => 'response too large'];
            }
            if ($status >= 300 && $status < 400) {
                $location = $headers['location'] ?? '';
                if ($left <= 0 || $location === '') {
                    return ['ok' => false, 'status' => $status, 'body' => '', 'error' => 'redirect not allowed'];
                }
                $left--;
                $current = mcp_oauth_absolute_url($current, $location);
                continue;
            }
            return ['ok' => true, 'status' => $status, 'body' => (string) $body, 'error' => null];
        }
    }
}

function mcp_oauth_absolute_url(string $base, string $location): string
{
    if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location) === 1) {
        return $location;
    }
    $parts = parse_url($base);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return $location;
    }
    $origin = $parts['scheme'] . '://' . $parts['host'];
    if (isset($parts['port'])) {
        $origin .= ':' . $parts['port'];
    }
    if (str_starts_with($location, '/')) {
        return $origin . $location;
    }
    $path = $parts['path'] ?? '/';
    $slash = strrpos($path, '/');
    $dir = $slash === false ? '/' : substr($path, 0, $slash + 1);
    return $origin . $dir . $location;
}

function mcp_oauth_is_loopback_host(string $host): bool
{
    $host = mcp_strip_brackets($host);
    if (strcasecmp($host, 'localhost') === 0) {
        return true;
    }
    $packed = inet_pton($host);
    if ($packed === false) {
        return false;
    }
    if (strlen($packed) === 16) {
        $loop6 = inet_pton('::1');
        if ($loop6 !== false && $packed === $loop6) {
            return true;
        }
        $ip = mcp_normalize_ip($host);
        return is_string($ip) && mcp_oauth_ipv4_is_loopback($ip);
    }
    return mcp_oauth_ipv4_is_loopback($host);
}

function mcp_oauth_ipv4_is_loopback(string $ip): bool
{
    $long = ip2long($ip);
    return $long !== false && $long >= ip2long('127.0.0.0') && $long <= ip2long('127.255.255.255');
}

function mcp_oauth_redirect_uri_matches(string $requested, array $registered): bool
{
    foreach ($registered as $uri) {
        if (!is_string($uri)) {
            continue;
        }
        if ($requested === $uri) {
            return true;
        }
        if (mcp_oauth_loopback_redirect_match($requested, $uri)) {
            return true;
        }
    }
    return false;
}

function mcp_oauth_loopback_redirect_match(string $requested, string $registered): bool
{
    $a = parse_url($requested);
    $b = parse_url($registered);
    if (!is_array($a) || !is_array($b)) {
        return false;
    }
    if (strtolower((string) ($a['scheme'] ?? '')) !== 'http' || strtolower((string) ($b['scheme'] ?? '')) !== 'http') {
        return false;
    }
    $ha = mcp_strip_brackets((string) ($a['host'] ?? ''));
    $hb = mcp_strip_brackets((string) ($b['host'] ?? ''));
    if ($ha === '' || strcasecmp($ha, $hb) !== 0) {
        return false;
    }
    if (!mcp_oauth_is_loopback_host($ha) || !mcp_oauth_is_loopback_host($hb)) {
        return false;
    }
    return ($a['path'] ?? '') === ($b['path'] ?? '') && ($a['query'] ?? '') === ($b['query'] ?? '');
}

function mcp_oauth_same_origin(string $a, string $b): bool
{
    $pa = parse_url($a);
    $pb = parse_url($b);
    if (!is_array($pa) || !is_array($pb)) {
        return false;
    }
    $sa = strtolower((string) ($pa['scheme'] ?? ''));
    $sb = strtolower((string) ($pb['scheme'] ?? ''));
    $ha = strtolower(mcp_strip_brackets((string) ($pa['host'] ?? '')));
    $hb = strtolower(mcp_strip_brackets((string) ($pb['host'] ?? '')));
    if ($sa === '' || $sa !== $sb || $ha === '' || $ha !== $hb) {
        return false;
    }
    $def = static function (string $scheme, array $parts): int {
        if (isset($parts['port'])) {
            return (int) $parts['port'];
        }
        return $scheme === 'https' ? 443 : 80;
    };
    return $def($sa, $pa) === $def($sb, $pb);
}

function mcp_oauth_cimd_redirect_ok(string $client_id_url, string $redirect_uri): bool
{
    $parts = parse_url($redirect_uri);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return false;
    }
    if (mcp_oauth_is_loopback_host((string) $parts['host'])) {
        $scheme = strtolower((string) $parts['scheme']);
        return $scheme === 'http' || $scheme === 'https';
    }
    return mcp_oauth_same_origin($client_id_url, $redirect_uri);
}

function mcp_oauth_redirect_uri_registrable(string $uri): bool
{
    $parts = parse_url($uri);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return false;
    }
    $scheme = strtolower((string) $parts['scheme']);
    if ($scheme === 'https') {
        return true;
    }
    return $scheme === 'http' && mcp_oauth_is_loopback_host((string) $parts['host']);
}

function mcp_oauth_cimd_cache_path(string $url): string
{
    return get_temp_dir(false, 'magnolia_mcp_cimd') . '/' . hash('sha256', $url) . '.json';
}

function mcp_oauth_fetch_cimd(string $url): array
{
    $allowed = mcp_cimd_url_allowed($url);
    if (!$allowed['ok']) {
        return ['ok' => false, 'json' => null, 'error' => (string) $allowed['error']];
    }
    $path = mcp_oauth_cimd_cache_path($url);
    if (is_file($path) && (time() - filemtime($path)) < 600) {
        $cached = json_decode((string) file_get_contents($path), true);
        if (is_array($cached)) {
            return ['ok' => true, 'json' => $cached, 'error' => null];
        }
    }
    $resp = mcp_http_get($url, 5, 65536, 3);
    if (!$resp['ok'] || (int) $resp['status'] !== 200) {
        return ['ok' => false, 'json' => null, 'error' => (string) ($resp['error'] ?? 'CIMD fetch failed')];
    }
    $json = json_decode((string) $resp['body'], true);
    if (!is_array($json)) {
        return ['ok' => false, 'json' => null, 'error' => 'CIMD is not JSON'];
    }
    file_put_contents($path, $resp['body']);
    return ['ok' => true, 'json' => $json, 'error' => null];
}

function mcp_oauth_client_fail(string $client_id, string $error): array
{
    return [
        'ok' => false,
        'client_id' => $client_id,
        'client_name' => '',
        'redirect_uris' => [],
        'display' => '',
        'error' => $error,
    ];
}

function mcp_oauth_load_client(string $client_id, string $redirect_uri): array
{
    if (str_starts_with($client_id, 'https://')) {
        $doc = mcp_oauth_fetch_cimd($client_id);
        if (!$doc['ok']) {
            return mcp_oauth_client_fail($client_id, (string) $doc['error']);
        }
        $json = $doc['json'];
        if (!is_array($json) || !hash_equals($client_id, (string) ($json['client_id'] ?? ''))) {
            return mcp_oauth_client_fail($client_id, 'CIMD client_id mismatch');
        }
        $method = $json['token_endpoint_auth_method'] ?? 'none';
        if ($method !== 'none') {
            return mcp_oauth_client_fail($client_id, 'CIMD token auth must be none');
        }
        $uris = $json['redirect_uris'] ?? null;
        if (!is_array($uris) || !mcp_oauth_redirect_uri_matches($redirect_uri, $uris)) {
            return mcp_oauth_client_fail($client_id, 'redirect_uri mismatch');
        }
        if (!mcp_oauth_cimd_redirect_ok($client_id, $redirect_uri)) {
            return mcp_oauth_client_fail($client_id, 'redirect_uri origin mismatch');
        }
        $host = parse_url($client_id, PHP_URL_HOST);
        return [
            'ok' => true,
            'client_id' => $client_id,
            'client_name' => is_string($json['client_name'] ?? null) ? $json['client_name'] : '',
            'redirect_uris' => $uris,
            'display' => is_string($host) ? mcp_strip_brackets($host) : '',
            'error' => null,
        ];
    }

    $row = mcp_oauth_get_client($client_id);
    if ($row === null) {
        return mcp_oauth_client_fail($client_id, 'unknown client');
    }
    $uris = json_decode((string) $row['redirect_uris'], true);
    if (!is_array($uris) || !mcp_oauth_redirect_uri_matches($redirect_uri, $uris)) {
        return mcp_oauth_client_fail($client_id, 'redirect_uri mismatch');
    }
    $name = (string) $row['client_name'];
    return [
        'ok' => true,
        'client_id' => (string) $row['client_id'],
        'client_name' => $name,
        'redirect_uris' => $uris,
        'display' => trim($name . ' ' . $row['client_id']),
        'error' => null,
    ];
}

function mcp_oauth_register_error(int $http, string $error, string $description = ''): array
{
    $body = ['error' => $error];
    if ($description !== '') {
        $body['error_description'] = $description;
    }
    return ['http' => $http, 'body' => $body];
}

function mcp_oauth_register(array $body, string $ip): array
{
    $uris = $body['redirect_uris'] ?? null;
    if (!is_array($uris) || $uris === [] || array_is_list($uris) === false) {
        return mcp_oauth_register_error(400, 'invalid_request', 'redirect_uris required');
    }
    foreach ($uris as $uri) {
        if (!is_string($uri) || $uri === '' || !mcp_oauth_redirect_uri_registrable($uri)) {
            return mcp_oauth_register_error(400, 'invalid_request', 'redirect_uris must be https or loopback http');
        }
    }
    if (array_key_exists('token_endpoint_auth_method', $body) && $body['token_endpoint_auth_method'] !== 'none') {
        return mcp_oauth_register_error(400, 'invalid_request', 'public clients only');
    }
    if (mcp_oauth_dcr_count($ip) >= 20) {
        return mcp_oauth_register_error(429, 'invalid_request', 'Too many registrations');
    }
    $client_id = 'mcp_' . bin2hex(random_bytes(16));
    $client_name = is_string($body['client_name'] ?? null) ? $body['client_name'] : '';
    mcp_oauth_insert_client($client_id, $client_name, json_encode(array_values($uris)));
    mcp_oauth_dcr_hit($ip);
    if (function_exists('log_activity')) {
        log_activity('MCP OAuth DCR');
    }
    return [
        'http' => 201,
        'body' => [
            'client_id' => $client_id,
            'client_name' => $client_name,
            'redirect_uris' => array_values($uris),
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
        ],
    ];
}

function mcp_oauth_is_anonymous_user(): bool
{
    global $username, $anonymous_login;
    return isset($anonymous_login) && $anonymous_login !== '' && $username === $anonymous_login;
}

function mcp_oauth_plugin_enabled(): bool
{
    global $plugins, $magnolia_mcp_enable, $enable_remote_apis;
    return is_array($plugins ?? null)
        && in_array('magnolia_mcp', $plugins, true)
        && !empty($magnolia_mcp_enable)
        && !empty($enable_remote_apis);
}

function mcp_oauth_client_ip(array $server, bool $trust_proxy): string
{
    if ($trust_proxy) {
        return (string) get_ip();
    }
    return (string) ($server['REMOTE_ADDR'] ?? '');
}

function mcp_oauth_posted_csrf_ok(): bool
{
    global $CSRF_token_identifier, $usersession;
    $id = (string) ($CSRF_token_identifier ?? '');
    $token = $id !== '' ? (string) ($_POST[$id] ?? '') : '';
    return isValidCSRFToken($token, $usersession);
}

function mcp_oauth_return_path_ok(string $uri): bool
{
    if ($uri === '' || str_contains($uri, "\n") || str_contains($uri, "\r")) {
        return false;
    }
    if (str_starts_with($uri, '//') || preg_match('#^[a-z][a-z0-9+.-]*:#i', $uri) === 1) {
        return false;
    }
    $parts = parse_url($uri);
    if (!is_array($parts) || isset($parts['scheme']) || isset($parts['host'])) {
        return false;
    }
    $path = (string) ($parts['path'] ?? '');
    if ($path === '' || str_contains($path, '..')) {
        return false;
    }
    return str_ends_with($path, '/plugins/magnolia_mcp/pages/oauth_authorize.php');
}

function mcp_oauth_set_return_cookie(string $uri, int $expires): void
{
    setcookie('magnolia_mcp_oauth_return', $uri, [
        'expires' => $expires,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function mcp_oauth_remember_return(string $uri): void
{
    if (!mcp_oauth_return_path_ok($uri)) {
        return;
    }
    mcp_oauth_set_return_cookie($uri, time() + 600);
}

function mcp_oauth_consume_return(): ?string
{
    $uri = (string) ($_COOKIE['magnolia_mcp_oauth_return'] ?? '');
    mcp_oauth_set_return_cookie('', time() - 3600);
    if (!mcp_oauth_return_path_ok($uri)) {
        return null;
    }
    return $uri;
}

function mcp_oauth_append_query(string $redirect_uri, array $params): string
{
    $parts = parse_url($redirect_uri);
    $base = $redirect_uri;
    $existing = [];
    if (isset($parts['query'])) {
        parse_str($parts['query'], $existing);
        $base = substr($redirect_uri, 0, -strlen($parts['query']) - 1);
    }
    $query = http_build_query(array_merge($existing, $params));
    $sep = str_contains($base, '?') ? '&' : '?';
    return $base . $sep . $query;
}

function mcp_oauth_grant_location(string $redirect_uri, string $code, string $state): string
{
    $params = ['code' => $code, 'iss' => mcp_oauth_issuer()];
    if ($state !== '') {
        $params['state'] = $state;
    }
    return mcp_oauth_append_query($redirect_uri, $params);
}

function mcp_oauth_deny_location(string $redirect_uri, string $state): string
{
    $params = ['error' => 'access_denied', 'iss' => mcp_oauth_issuer()];
    if ($state !== '') {
        $params['state'] = $state;
    }
    return mcp_oauth_append_query($redirect_uri, $params);
}

function mcp_oauth_authorize_fail(string $error, bool $html, string $redirect_uri, string $state): array
{
    $redirect = '';
    if (!$html && $redirect_uri !== '') {
        $params = ['error' => $error, 'iss' => mcp_oauth_issuer()];
        if ($state !== '') {
            $params['state'] = $state;
        }
        $redirect = mcp_oauth_append_query($redirect_uri, $params);
    }
    return [
        'ok' => false,
        'error' => $error,
        'redirect' => $redirect,
        'html' => $html || $redirect === '',
        'client' => null,
        'client_id' => '',
        'redirect_uri' => $redirect_uri,
        'state' => $state,
        'code_challenge' => '',
        'resource' => '',
        'scope' => '',
    ];
}

function mcp_oauth_request_string(array $src, string $key): string
{
    return is_string($src[$key] ?? null) ? $src[$key] : '';
}

function mcp_oauth_parse_query_string(string $query_string): array
{
    $parsed = [];
    parse_str($query_string, $parsed);
    if (!is_array($parsed)) {
        return [];
    }
    $out = [];
    foreach ($parsed as $k => $v) {
        $nk = (string) $k;
        while (str_starts_with($nk, 'amp;')) {
            $nk = substr($nk, 4);
        }
        $out[$nk] = $v;
    }
    return $out;
}

function mcp_oauth_authorize_params(array $get, array $post, string $query_string): array
{
    $from_qs = mcp_oauth_parse_query_string($query_string);
    if (mcp_oauth_request_string($from_qs, 'client_id') !== '') {
        return array_merge($from_qs, $post);
    }
    return array_merge($get, $post);
}

function mcp_oauth_validate_authorize_request(array $query): array
{
    $client_id = mcp_oauth_request_string($query, 'client_id');
    $redirect_uri = mcp_oauth_request_string($query, 'redirect_uri');
    $state = mcp_oauth_request_string($query, 'state');
    $response_type = mcp_oauth_request_string($query, 'response_type');
    $code_challenge = mcp_oauth_request_string($query, 'code_challenge');
    $code_challenge_method = mcp_oauth_request_string($query, 'code_challenge_method');
    $scope_in = is_string($query['scope'] ?? null) ? $query['scope'] : null;
    $resource_in = is_string($query['resource'] ?? null) ? $query['resource'] : null;

    $client = null;
    $can_redirect = false;
    $load_error = '';
    if ($client_id !== '' && $redirect_uri !== '') {
        $loaded = mcp_oauth_load_client($client_id, $redirect_uri);
        if ($loaded['ok']) {
            $client = $loaded;
            $can_redirect = true;
        } else {
            $load_error = (string) $loaded['error'];
        }
    }

    if (!$can_redirect) {
        if ($client_id === '' || $redirect_uri === '' || str_contains($load_error, 'redirect')) {
            return mcp_oauth_authorize_fail('invalid_request', true, $redirect_uri, $state);
        }
        return mcp_oauth_authorize_fail('invalid_client', true, $redirect_uri, $state);
    }

    if ($response_type !== 'code') {
        return mcp_oauth_authorize_fail('unsupported_response_type', false, $redirect_uri, $state);
    }
    if ($code_challenge_method !== 'S256' || $code_challenge === '') {
        return mcp_oauth_authorize_fail('invalid_request', false, $redirect_uri, $state);
    }
    $resource = mcp_oauth_effective_resource($resource_in);
    if ($resource === null) {
        return mcp_oauth_authorize_fail('invalid_target', false, $redirect_uri, $state);
    }

    return [
        'ok' => true,
        'error' => '',
        'redirect' => '',
        'html' => false,
        'client' => $client,
        'client_id' => (string) $client['client_id'],
        'redirect_uri' => $redirect_uri,
        'state' => $state,
        'code_challenge' => $code_challenge,
        'resource' => $resource,
        'scope' => mcp_oauth_normalize_scope($scope_in),
    ];
}

function mcp_oauth_token_error(string $error, string $description): array
{
    return [
        'http' => 400,
        'body' => ['error' => $error, 'error_description' => $description],
    ];
}

function mcp_oauth_issue_tokens(int $userref, string $client_id, string $resource, string $family = ''): array
{
    if ($family === '') {
        $family = mcp_oauth_random();
    }
    $access = mcp_oauth_random();
    $refresh = mcp_oauth_random();
    $now = time();
    mcp_oauth_insert_token([
        'token_hash' => mcp_oauth_hash($access),
        'token_type' => 'access',
        'userref' => $userref,
        'client_id' => $client_id,
        'resource' => $resource,
        'scope' => 'mcp',
        'expires' => date('Y-m-d H:i:s', $now + 3600),
        'family' => $family,
    ]);
    mcp_oauth_insert_token([
        'token_hash' => mcp_oauth_hash($refresh),
        'token_type' => 'refresh',
        'userref' => $userref,
        'client_id' => $client_id,
        'resource' => $resource,
        'scope' => 'mcp',
        'expires' => date('Y-m-d H:i:s', $now + 86400 * 30),
        'family' => $family,
    ]);
    return [
        'http' => 200,
        'body' => [
            'access_token' => $access,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => $refresh,
            'scope' => 'mcp',
        ],
    ];
}

function mcp_oauth_request_resource(array $post): ?string
{
    $raw = $post['resource'] ?? null;
    if ($raw === null) {
        return mcp_oauth_effective_resource(null);
    }
    if (!is_string($raw)) {
        return null;
    }
    return mcp_oauth_effective_resource($raw);
}

function mcp_oauth_token_request(array $post): array
{
    $grant = mcp_oauth_request_string($post, 'grant_type');
    if ($grant === '') {
        return mcp_oauth_token_error('invalid_request', 'grant_type required');
    }
    if ($grant === 'authorization_code') {
        return mcp_oauth_token_authorization_code($post);
    }
    if ($grant === 'refresh_token') {
        return mcp_oauth_token_refresh($post);
    }
    return mcp_oauth_token_error('unsupported_grant_type', 'unsupported grant_type');
}

function mcp_oauth_token_authorization_code(array $post): array
{
    $code = mcp_oauth_request_string($post, 'code');
    $redirect_uri = mcp_oauth_request_string($post, 'redirect_uri');
    $client_id = mcp_oauth_request_string($post, 'client_id');
    $code_verifier = mcp_oauth_request_string($post, 'code_verifier');
    if ($code === '' || $redirect_uri === '' || $client_id === '' || $code_verifier === '') {
        return mcp_oauth_token_error('invalid_request', 'code, redirect_uri, code_verifier, and client_id required');
    }

    $row = mcp_oauth_get_code(mcp_oauth_hash($code));
    if ($row !== null && (int) $row['used'] !== 0) {
        if (function_exists('log_activity')) {
            log_activity('MCP OAuth authorization code reuse');
        }
        mcp_oauth_revoke_user_client((int) $row['userref'], (string) $row['client_id']);
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    $now = date('Y-m-d H:i:s');
    if ($row === null || !($row['expires'] > $now)) {
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    if (!hash_equals((string) $row['redirect_uri'], $redirect_uri) || !hash_equals((string) $row['client_id'], $client_id)) {
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    $resource = mcp_oauth_request_resource($post);
    $stored_resource = mcp_oauth_effective_resource((string) $row['resource']);
    if ($resource === null || $stored_resource === null || !hash_equals($stored_resource, $resource)) {
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    if (!hash_equals((string) $row['code_challenge'], mcp_oauth_pkce_s256($code_verifier))) {
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    if (!mcp_oauth_consume_code((string) $row['code_hash'])) {
        // Lost CAS: the concurrent winner already consumed this code and must keep its tokens.
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
    try {
        return mcp_oauth_issue_tokens((int) $row['userref'], (string) $row['client_id'], $stored_resource);
    } catch (Throwable $e) {
        return mcp_oauth_token_error('invalid_grant', 'invalid authorization code');
    }
}

function mcp_oauth_token_refresh(array $post): array
{
    $refresh = mcp_oauth_request_string($post, 'refresh_token');
    $client_id = mcp_oauth_request_string($post, 'client_id');
    if ($refresh === '' || $client_id === '') {
        return mcp_oauth_token_error('invalid_request', 'refresh_token and client_id required');
    }

    $row = mcp_oauth_get_token(mcp_oauth_hash($refresh), 'refresh');
    if ($row === null) {
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    if (!hash_equals((string) $row['client_id'], $client_id)) {
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    $resource = mcp_oauth_request_resource($post);
    $stored_resource = mcp_oauth_effective_resource((string) $row['resource']);
    if ($resource === null || $stored_resource === null || !hash_equals($stored_resource, $resource)) {
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    if ((int) $row['revoked'] === 1) {
        mcp_oauth_revoke_family((string) $row['family']);
        if (function_exists('log_activity')) {
            log_activity('MCP OAuth refresh reuse');
        }
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    if (!((string) $row['expires'] > date('Y-m-d H:i:s'))) {
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    if (!mcp_oauth_revoke_refresh((string) $row['token_hash'])) {
        mcp_oauth_revoke_family((string) $row['family']);
        if (function_exists('log_activity')) {
            log_activity('MCP OAuth refresh reuse');
        }
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
    try {
        return mcp_oauth_issue_tokens((int) $row['userref'], (string) $row['client_id'], $stored_resource, (string) $row['family']);
    } catch (Throwable $e) {
        return mcp_oauth_token_error('invalid_grant', 'invalid refresh token');
    }
}

<?php

$failures = 0;

function mcp_test_expect($cond, string $msg): void
{
    global $failures;
    if ($cond) {
        echo "ok - {$msg}\n";
        return;
    }
    $failures++;
    fwrite(STDERR, "FAIL - {$msg}\n");
}

function mcp_test_expect_eq($got, $want, string $msg): void
{
    mcp_test_expect($got === $want, $msg . ' (got ' . var_export($got, true) . ', want ' . var_export($want, true) . ')');
}

function mcp_test_expect_log_redacted(string $key, string $label): void
{
    mcp_test_expect(!empty($GLOBALS['mcp_test_log']), $label . ' logged');
    foreach ($GLOBALS['mcp_test_log'] as $log_note) {
        mcp_test_expect(!str_contains((string) $log_note, 'Bearer'), $label . ' log has no Bearer');
        mcp_test_expect(!str_contains((string) $log_note, $key), $label . ' log has no api key');
    }
}

function mcp_test_reset_auth_state(): void
{
    $GLOBALS['mcp_test_users'] = [
        'alice' => ['ref' => 7, 'username' => 'alice'],
    ];
    $GLOBALS['mcp_test_scramble'] = 'scrambled';
    $GLOBALS['mcp_test_setup_user_called'] = false;
    $GLOBALS['mcp_test_setup_user_return'] = true;
    $GLOBALS['mcp_test_api_call_defined_at_setup'] = false;
    $GLOBALS['mcp_test_update_user_access_called'] = false;
    $GLOBALS['mcp_test_sysvar'] = null;
}

if (!function_exists('get_user_by_username')) {
    function get_user_by_username($username)
    {
        return $GLOBALS['mcp_test_users'][$username]['ref'] ?? false;
    }
}
if (!function_exists('get_user')) {
    function get_user($ref)
    {
        foreach ($GLOBALS['mcp_test_users'] as $row) {
            if ($row['ref'] === $ref) {
                return $row;
            }
        }
        return false;
    }
}
if (!function_exists('get_api_key')) {
    function get_api_key($user)
    {
        return hash('sha256', $user . $GLOBALS['mcp_test_scramble']);
    }
}
if (!function_exists('setup_user')) {
    function setup_user(array $userdata)
    {
        $GLOBALS['mcp_test_setup_user_called'] = true;
        $GLOBALS['mcp_test_api_call_defined_at_setup'] = defined('API_CALL');
        return $GLOBALS['mcp_test_setup_user_return'];
    }
}
if (!function_exists('update_user_access')) {
    function update_user_access(int $user = 0, array $set_values = []): bool
    {
        $GLOBALS['mcp_test_update_user_access_called'] = true;
        return true;
    }
}
if (!function_exists('set_sysvar')) {
    function set_sysvar($name, $value, $nocache = true)
    {
        $GLOBALS['mcp_test_sysvar'] = [$name, $value];
        return true;
    }
}

if (!function_exists('get_temp_dir')) {
    function get_temp_dir($user = false, $folder = '')
    {
        $base = sys_get_temp_dir() . '/magnolia_mcp_test_cache';
        if (is_string($folder) && $folder !== '') {
            $base .= '/' . $folder;
        }
        if (!is_dir($base)) {
            mkdir($base, 0777, true);
        }
        return $base;
    }
}

if (!function_exists('mcp_resolve_ips')) {
    function mcp_resolve_ips(string $host): array
    {
        if (
            strcasecmp($host, 'localhost') === 0
            || $host === '2130706433'
            || $host === '127.1'
            || strcasecmp($host, '0x7f000001') === 0
        ) {
            return ['127.0.0.1'];
        }
        return ['8.8.8.8'];
    }
}

if (!function_exists('mcp_http_get')) {
    function mcp_http_get(string $url, int $timeout, int $max_bytes, int $max_redirects): array
    {
        if (isset($GLOBALS['mcp_test_http'][$url])) {
            return $GLOBALS['mcp_test_http'][$url];
        }
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'not stubbed'];
    }
}

if (!function_exists('execute_api_call')) {
    function execute_api_call($query, $pretty = false)
    {
        parse_str($query, $params);
        $GLOBALS['mcp_test_last_query'] = $params;
        $fn = $params['function'] ?? '';
        if (isset($GLOBALS['mcp_test_execute_map']) && is_array($GLOBALS['mcp_test_execute_map']) && array_key_exists($fn, $GLOBALS['mcp_test_execute_map'])) {
            $mapped = $GLOBALS['mcp_test_execute_map'][$fn];
            if (is_array($mapped) && array_key_exists('http', $mapped)) {
                if (!headers_sent()) {
                    http_response_code((int) $mapped['http']);
                }
                return $mapped['body'];
            }
            return $mapped;
        }
        if (!empty($GLOBALS['mcp_test_execute_throw'])) {
            throw new RuntimeException('boom');
        }
        if (!empty($GLOBALS['mcp_test_execute_http']) && !headers_sent()) {
            http_response_code((int) $GLOBALS['mcp_test_execute_http']);
        }
        if (array_key_exists('mcp_test_execute_return', $GLOBALS)) {
            return $GLOBALS['mcp_test_execute_return'];
        }
        return json_encode(['ok' => true, 'function' => $params['function'] ?? null, 'search' => $params['search'] ?? null]);
    }
}

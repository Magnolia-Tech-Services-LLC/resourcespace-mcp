<?php

include_once __DIR__ . '/mcp_oauth_store.php';

function mcp_authorization_header(array $server, array $headers = []): ?string
{
    foreach (
        [
            $server['HTTP_AUTHORIZATION'] ?? null,
            $server['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
        ] as $value
    ) {
        if (is_string($value) && $value !== '') {
            return $value;
        }
    }
    foreach ($headers as $name => $value) {
        if (is_string($value) && $value !== '' && strcasecmp((string) $name, 'Authorization') === 0) {
            return $value;
        }
    }
    return null;
}

function mcp_bearer_raw(?string $header): ?string
{
    if ($header === null || $header === '') {
        return null;
    }
    if (stripos($header, 'Bearer ') !== 0) {
        return null;
    }
    $token = substr($header, 7);
    return $token === '' ? null : $token;
}

function mcp_parse_bearer(?string $header): ?array
{
    if ($header === null || $header === '') {
        return null;
    }
    if (stripos($header, 'Bearer ') !== 0) {
        return null;
    }
    $token = substr($header, 7);
    $pos = strpos($token, ':');
    if ($pos === false || $pos === 0 || $pos === strlen($token) - 1) {
        return null;
    }
    return [
        'username' => substr($token, 0, $pos),
        'key' => substr($token, $pos + 1),
    ];
}

function mcp_setup_api_user($userref): array
{
    $fail = ['ok' => false, 'http' => 401, 'error' => 'Unauthorized'];
    $userdata = get_user($userref);
    if (!is_array($userdata)) {
        return $fail;
    }
    if (!defined('API_CALL')) {
        define('API_CALL', true);
    }
    $valid = setup_user($userdata);
    if ($valid !== true) {
        return $fail;
    }
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 250) : 'MCP';
    update_user_access(0, ['last_browser' => $ua]);
    set_sysvar('last_api_access', date('Y-m-d H:i'), false);
    return ['ok' => true, 'http' => 200, 'error' => null, 'userref' => (int) $userref];
}

function mcp_authenticate(string $username, string $key): array
{
    $fail = ['ok' => false, 'http' => 401, 'error' => 'Unauthorized'];
    $userref = get_user_by_username($username);
    if ($userref === false) {
        return $fail;
    }
    $expected = get_api_key($userref);
    if (!is_string($expected) || !hash_equals($expected, $key)) {
        return $fail;
    }
    return mcp_setup_api_user($userref);
}

function mcp_authenticate_oauth(string $access_token): array
{
    $fail = ['ok' => false, 'http' => 401, 'error' => 'Unauthorized'];
    if (str_contains($access_token, ':')) {
        return $fail;
    }
    $row = mcp_oauth_lookup_access(mcp_oauth_hash($access_token));
    if ($row === null) {
        return $fail;
    }
    return mcp_setup_api_user((int) $row['userref']);
}

function mcp_authenticate_bearer(?string $header): array
{
    $fail = ['ok' => false, 'http' => 401, 'error' => 'Unauthorized'];
    $token = mcp_bearer_raw($header);
    if ($token === null) {
        return $fail;
    }
    if (str_contains($token, ':')) {
        $parsed = mcp_parse_bearer($header);
        if ($parsed === null) {
            return $fail;
        }
        return mcp_authenticate($parsed['username'], $parsed['key']);
    }
    return mcp_authenticate_oauth($token);
}

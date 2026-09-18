<?php

const MCP_PROTOCOL_VERSION = '2025-03-26';

function mcp_jsonrpc_error($id, int $code, string $message): array
{
    return [
        'jsonrpc' => '2.0',
        'error' => ['code' => $code, 'message' => $message],
        'id' => $id,
    ];
}

function mcp_jsonrpc_result($id, $result): array
{
    return [
        'jsonrpc' => '2.0',
        'id' => $id,
        'result' => $result,
    ];
}

function mcp_jsonrpc_decode(string $raw): array
{
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return ['ok' => false, 'http' => 400, 'code' => -32700, 'message' => 'Parse error', 'request' => null];
    }
    if (array_is_list($decoded)) {
        return ['ok' => false, 'http' => 400, 'code' => -32600, 'message' => 'Batch not supported', 'request' => null];
    }
    if (($decoded['jsonrpc'] ?? '') !== '2.0' || !isset($decoded['method']) || !is_string($decoded['method'])) {
        return ['ok' => false, 'http' => 400, 'code' => -32600, 'message' => 'Invalid request', 'request' => null];
    }
    return ['ok' => true, 'http' => 200, 'code' => null, 'message' => null, 'request' => $decoded];
}

function mcp_accept_allows_json(?string $accept): bool
{
    if ($accept === null || $accept === '') {
        return false;
    }
    return stripos($accept, 'application/json') !== false;
}

function mcp_https_ok(array $server, string $baseurl, bool $trust_proxy): bool
{
    $scheme = parse_url($baseurl, PHP_URL_SCHEME);
    if ($scheme !== 'https') {
        return false;
    }
    $https = $server['HTTPS'] ?? '';
    if ($https !== '' && strtolower((string) $https) !== 'off') {
        return true;
    }
    if ($trust_proxy && strtolower((string) ($server['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return false;
}

function mcp_oauth_machine_json(): void
{
    global $baseurl, $resourcespace_mcp_trust_proxy;
    header('Content-Type: application/json');
    if (!mcp_https_ok($_SERVER, (string) $baseurl, !empty($resourcespace_mcp_trust_proxy))) {
        http_response_code(403);
        echo json_encode(['error' => 'HTTPS required']);
        exit;
    }
    if (!mcp_oauth_plugin_enabled()) {
        http_response_code(403);
        echo json_encode(['error' => 'disabled']);
        exit;
    }
    mcp_oauth_purge_expired();
}

function mcp_origin_ok(?string $origin, string $baseurl): bool
{
    if ($origin === null || $origin === '') {
        return true;
    }
    $want_host = parse_url($baseurl, PHP_URL_HOST);
    $got_host = parse_url($origin, PHP_URL_HOST);
    return is_string($want_host) && is_string($got_host) && strcasecmp($want_host, $got_host) === 0;
}

function mcp_protocol_version_ok(?string $header): array
{
    if ($header === null || $header === '' || $header === MCP_PROTOCOL_VERSION) {
        return ['ok' => true, 'http' => 200];
    }
    return ['ok' => false, 'http' => 400];
}

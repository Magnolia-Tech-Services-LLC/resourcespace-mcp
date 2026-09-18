<?php
$disable_browser_check = true;
$rs_include = dirname(__DIR__, 3) . '/include';
include $rs_include . '/boot.php';
include_once $rs_include . '/image_processing.php';
include_once $rs_include . '/api_functions.php';
include_once $rs_include . '/ajax_functions.php';
include_once $rs_include . '/api_bindings.php';
include_once $rs_include . '/login_functions.php';
include_once $rs_include . '/dash_functions.php';
include_once __DIR__ . '/../include/mcp_jsonrpc.php';
include_once __DIR__ . '/../include/mcp_auth.php';
include_once __DIR__ . '/../include/mcp_dispatch.php';
include_once __DIR__ . '/../include/mcp_catalog.php';
include_once __DIR__ . '/../include/mcp_tools.php';

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'] ?? '';
$authorization = mcp_authorization_header(
    $_SERVER,
    function_exists('getallheaders') ? getallheaders() : []
);
if ($method === 'GET' || $method === 'HEAD') {
    if ($authorization === null || $authorization === '') {
        global $plugins, $enable_remote_apis, $baseurl, $resourcespace_mcp_enable, $resourcespace_mcp_trust_proxy;
        if (!mcp_https_ok($_SERVER, (string) $baseurl, !empty($resourcespace_mcp_trust_proxy))) {
            http_response_code(403);
            echo json_encode(mcp_jsonrpc_error(null, -32600, 'HTTPS required'));
            exit;
        }
        if (
            !in_array('resourcespace_mcp', $plugins, true)
            || empty($resourcespace_mcp_enable)
            || empty($enable_remote_apis)
        ) {
            http_response_code(403);
            echo json_encode(mcp_jsonrpc_error(null, -32001, 'Plugin not enabled'));
            exit;
        }
        header('WWW-Authenticate: ' . mcp_oauth_www_authenticate());
        http_response_code(401);
        echo json_encode(mcp_jsonrpc_error(null, -32001, 'Unauthorized'));
        exit;
    }
    http_response_code(405);
    echo json_encode(mcp_jsonrpc_error(null, -32600, 'Method Not Allowed'));
    exit;
}
if ($method === 'DELETE') {
    http_response_code(405);
    echo json_encode(mcp_jsonrpc_error(null, -32600, 'Method Not Allowed'));
    exit;
}
if (!mcp_accept_allows_json($_SERVER['HTTP_ACCEPT'] ?? null)) {
    http_response_code(406);
    echo json_encode(mcp_jsonrpc_error(null, -32600, 'Not Acceptable'));
    exit;
}

$raw = file_get_contents('php://input');
$decoded = mcp_jsonrpc_decode((string) $raw);
if (!$decoded['ok']) {
    http_response_code($decoded['http']);
    echo json_encode(mcp_jsonrpc_error(null, $decoded['code'], $decoded['message']));
    exit;
}

global $plugins, $enable_remote_apis, $baseurl, $resourcespace_mcp_enable, $resourcespace_mcp_trust_proxy;

if (!in_array('resourcespace_mcp', $plugins, true)) {
    http_response_code(403);
    echo json_encode(mcp_jsonrpc_error($decoded['request']['id'] ?? null, -32001, 'Plugin not enabled'));
    exit;
}

$state = [
    'plugins' => $plugins,
    'enable' => !empty($resourcespace_mcp_enable),
    'enable_remote_apis' => !empty($enable_remote_apis),
    'trust_proxy' => !empty($resourcespace_mcp_trust_proxy),
    'baseurl' => $baseurl,
    'allowlist' => mcp_current_allowlist(),
];

$server = $_SERVER;
if ($authorization !== null) {
    $server['HTTP_AUTHORIZATION'] = $authorization;
}
$result = mcp_handle_message($decoded['request'], $server, $state);
http_response_code($result['http']);
if (!empty($result['headers']) && is_array($result['headers'])) {
    foreach ($result['headers'] as $extra_header) {
        header($extra_header);
    }
}
if (!empty($result['empty'])) {
    exit;
}
echo json_encode($result['body']);

<?php
$disable_browser_check = true;
require_once __DIR__ . '/../include/mcp_rs_path.php';
$rs_include = mcp_rs_include_dir(__DIR__);
include $rs_include . '/boot.php';
include_once __DIR__ . '/../include/mcp_jsonrpc.php';
include_once __DIR__ . '/../include/mcp_oauth.php';

mcp_oauth_machine_json();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'invalid_request', 'error_description' => 'POST required']);
    exit;
}
$decoded = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($decoded)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request']);
    exit;
}
global $resourcespace_mcp_trust_proxy;
$result = mcp_oauth_register(
    $decoded,
    mcp_oauth_client_ip($_SERVER, !empty($resourcespace_mcp_trust_proxy))
);
http_response_code($result['http']);
echo json_encode($result['body']);

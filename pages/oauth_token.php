<?php
$disable_browser_check = true;
require_once __DIR__ . '/../include/mcp_rs_path.php';
$rs_include = mcp_rs_include_dir(__DIR__);
include $rs_include . '/boot.php';
include_once __DIR__ . '/../include/mcp_jsonrpc.php';
include_once __DIR__ . '/../include/mcp_oauth.php';

header('Cache-Control: no-store');
mcp_oauth_machine_json();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'invalid_request', 'error_description' => 'POST required']);
    exit;
}
$ct = (string) ($_SERVER['CONTENT_TYPE'] ?? '');
if (stripos($ct, 'application/x-www-form-urlencoded') === false) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request', 'error_description' => 'form-urlencoded required']);
    exit;
}
$result = mcp_oauth_token_request($_POST);
http_response_code($result['http']);
echo json_encode($result['body']);

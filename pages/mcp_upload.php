<?php
$disable_browser_check = true;
require_once __DIR__ . '/../include/mcp_rs_path.php';
$rs_include = mcp_rs_include_dir(__DIR__);
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
include_once __DIR__ . '/../include/mcp_oauth.php';
include_once __DIR__ . '/../include/mcp_upload.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$authorization = mcp_authorization_header(
    $_SERVER,
    function_exists('getallheaders') ? getallheaders() : []
);
$server = $_SERVER;
if ($authorization !== null) {
    $server['HTTP_AUTHORIZATION'] = $authorization;
}

global $plugins, $enable_remote_apis, $baseurl, $resourcespace_mcp_enable, $resourcespace_mcp_trust_proxy;

$state = [
    'plugins' => $plugins,
    'enable' => !empty($resourcespace_mcp_enable),
    'enable_remote_apis' => !empty($enable_remote_apis),
    'trust_proxy' => !empty($resourcespace_mcp_trust_proxy),
    'baseurl' => $baseurl,
    'allowlist' => mcp_current_allowlist(),
];

$result = mcp_upload_handle($server, $_POST, $_FILES, $_COOKIE, $state);
http_response_code($result['http']);
if (!empty($result['www_authenticate'])) {
    header('WWW-Authenticate: ' . mcp_oauth_www_authenticate());
}
echo json_encode($result['body']);

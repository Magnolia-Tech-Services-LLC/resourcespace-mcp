<?php
$disable_browser_check = true;
include '../../../include/boot.php';
include_once __DIR__ . '/../include/mcp_jsonrpc.php';
include_once __DIR__ . '/../include/mcp_oauth.php';

mcp_oauth_machine_json();
echo json_encode([
    'resource' => mcp_oauth_canonical_resource(),
    'authorization_servers' => [mcp_oauth_issuer()],
    'scopes_supported' => ['mcp'],
    'bearer_methods_supported' => ['header'],
    'resource_documentation' => mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/setup.php',
]);

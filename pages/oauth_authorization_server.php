<?php
$disable_browser_check = true;
include '../../../include/boot.php';
include_once __DIR__ . '/../include/mcp_jsonrpc.php';
include_once __DIR__ . '/../include/mcp_oauth.php';

mcp_oauth_machine_json();
echo json_encode([
    'issuer' => mcp_oauth_issuer(),
    'authorization_endpoint' => mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/oauth_authorize.php',
    'token_endpoint' => mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/oauth_token.php',
    'registration_endpoint' => mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/oauth_register.php',
    'scopes_supported' => ['mcp'],
    'response_types_supported' => ['code'],
    'grant_types_supported' => ['authorization_code', 'refresh_token'],
    'code_challenge_methods_supported' => ['S256'],
    'token_endpoint_auth_methods_supported' => ["none"],
    'client_id_metadata_document_supported' => true,
    'authorization_response_iss_parameter_supported' => true,
]);

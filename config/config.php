<?php

$resourcespace_mcp_enable = true;
$resourcespace_mcp_trust_proxy = false;
$resourcespace_mcp_allow_resources = true;
$resourcespace_mcp_allow_search = true;
$resourcespace_mcp_allow_collections = true;
$resourcespace_mcp_allow_metadata = true;
$resourcespace_mcp_allow_users = true;
$resourcespace_mcp_allow_system = true;
$resourcespace_mcp_allow_plugins = true;
$resourcespace_mcp_allow_uncurated = false;

// include_plugin_config() copies locals onto $GLOBALS. Append so core 'login' is not wiped.
global $CSRF_exempt_pages;
if (!isset($CSRF_exempt_pages) || !is_array($CSRF_exempt_pages)) {
    $CSRF_exempt_pages = ['login'];
}
foreach (
    [
        'mcp',
        'oauth_token',
        'oauth_register',
        'oauth_protected_resource',
        'oauth_authorization_server',
        'oauth-authorization-server',
        'oauth-protected-resource',
        'oauth_authorize',
        'mcp_upload',
    ] as $mcp_csrf_page
) {
    if (!in_array($mcp_csrf_page, $CSRF_exempt_pages, true)) {
        $CSRF_exempt_pages[] = $mcp_csrf_page;
    }
}
unset($mcp_csrf_page);

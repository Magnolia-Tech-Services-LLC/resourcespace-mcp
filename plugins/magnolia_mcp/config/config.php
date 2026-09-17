<?php

$magnolia_mcp_enable = true;
$magnolia_mcp_trust_proxy = false;
$magnolia_mcp_allow_resources = true;
$magnolia_mcp_allow_search = true;
$magnolia_mcp_allow_collections = true;
$magnolia_mcp_allow_metadata = true;
$magnolia_mcp_allow_users = true;
$magnolia_mcp_allow_system = true;
$magnolia_mcp_allow_plugins = true;
$magnolia_mcp_allow_uncurated = false;

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

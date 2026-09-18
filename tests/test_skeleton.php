<?php

$root = dirname(__DIR__);
$yaml = file_get_contents($root . '/resourcespace_mcp.yaml');
mcp_test_expect($yaml !== false, 'yaml exists');
mcp_test_expect((bool) preg_match('/^name: resourcespace_mcp\s*$/m', $yaml), 'yaml name unquoted resourcespace_mcp');
mcp_test_expect((bool) preg_match('/^title: MCP Server\s*$/m', $yaml), 'yaml title is MCP Server');
mcp_test_expect((bool) preg_match('/^category: API\s*$/m', $yaml), 'yaml category is API');
mcp_test_expect((bool) preg_match('/^disable_group_select: 1\s*$/m', $yaml), 'disable_group_select is 1');
mcp_test_expect((bool) preg_match('/^info_url: \/plugins\/resourcespace_mcp\/pages\/help\.php\s*$/m', $yaml), 'yaml info_url is help page');
mcp_test_expect(!str_contains($yaml, "name: '"), 'yaml values are unquoted');

require $root . '/config/config.php';
mcp_test_expect_eq($resourcespace_mcp_enable ?? null, true, 'enable default true');
mcp_test_expect_eq($resourcespace_mcp_trust_proxy ?? null, false, 'trust proxy default off');
mcp_test_expect_eq($resourcespace_mcp_allow_uncurated ?? null, false, 'uncurated default off');

require $root . '/languages/en.php';
mcp_test_expect_eq($lang['resourcespace_mcp_title'] ?? null, 'MCP Server', 'lang title is MCP Server');

$hook = $root . '/hooks/all.php';
mcp_test_expect(file_exists($hook), 'hooks/all.php exists');
require_once $hook;
mcp_test_expect(function_exists('HookResourcespace_mcpAllExtra_checks'), 'extra_checks hook defined');
mcp_test_expect(function_exists('HookResourcespace_mcpAllUser_home_additional_links'), 'user home help link hook defined');
mcp_test_expect(function_exists('HookResourcespace_mcpAllCustomteamfunction'), 'team centre tile hook defined');
mcp_test_expect(function_exists('HookResourcespace_mcpAllPreheaderoutput'), 'totp return hook defined');
mcp_test_expect(isset($lang['resourcespace_mcp_help_title']), 'help title lang set');
mcp_test_expect(isset($lang['resourcespace_mcp_help_step2']), 'help step2 lang set');

$ann = $root . '/config/catalog_annotations.php';
require $ann;
foreach (['do_search', 'create_resource', 'upload_file_by_url', 'update_field', 'create_collection', 'checkperm', 'get_system_status'] as $id) {
    mcp_test_expect(isset($resourcespace_mcp_annotations[$id]), 'annotation ' . $id);
}
mcp_test_expect_eq($resourcespace_mcp_annotations['do_search']['category'], 'search', 'do_search category');

$setup = $root . '/pages/setup.php';
mcp_test_expect(file_exists($setup), 'pages/setup.php exists');
$setup_src = (string) file_get_contents($setup);
mcp_test_expect(str_contains($setup_src, 'authenticate.php'), 'setup includes authenticate');
mcp_test_expect(str_contains($setup_src, "checkperm('a')"), 'setup requires admin');
mcp_test_expect(str_contains($setup_src, 'plugin_activate_for_setup'), 'setup activates plugin for setup');
mcp_test_expect(str_contains($setup_src, 'config_gen_setup_post'), 'setup CSRF via config_gen_setup_post');
mcp_test_expect(str_contains($setup_src, 'config_add_boolean_select'), 'setup uses boolean selects');
mcp_test_expect(str_contains($setup_src, "'resourcespace_mcp_allow_' . \$cat"), 'setup allowlist per category');
mcp_test_expect(!str_contains($setup_src, 'refresh_catalog'), 'setup has no catalog refresh');
mcp_test_expect(!str_contains($setup_src, 'set_plugin_config'), 'setup does not write catalog cache via set_plugin_config');
mcp_test_expect(str_contains($setup_src, 'mcp_oauth_canonical_resource'), 'setup shows connector URL');
mcp_test_expect(!str_contains($setup_src, 'mcp_oauth_prm_url'), 'setup does not dump PRM URL');
mcp_test_expect(str_contains($setup_src, 'enable_remote_apis'), 'setup shows remote APIs status');
mcp_test_expect(str_contains($setup_src, 'parse_url'), 'setup rewrite uses $baseurl path');
mcp_test_expect(str_contains($setup_src, 'REQUEST_URI'), 'setup Apache snippet works in vhost and .htaccess');
mcp_test_expect(str_contains($setup_src, 'oauth-authorization-server'), 'setup shows oauth Apache snippet');
mcp_test_expect(str_contains($setup_src, "oauth-authorization-server$'"), 'setup Apache AS rewrite is origin-exact');
mcp_test_expect(str_contains($setup_src, 'CGIPassAuth On'), 'setup Apache passes Authorization');
mcp_test_expect(str_contains($setup_src, 'location = /.well-known/oauth-authorization-server'), 'setup nginx AS location is exact');
mcp_test_expect(str_contains($setup_src, 'oauth-protected-resource'), 'setup shows well-known rewrite');
mcp_test_expect(str_contains($setup_src, 'drop_oauth'), 'setup can drop OAuth tables');
mcp_test_expect(str_contains($setup_src, 'resourcespace_mcp_oauth_nginx'), 'setup shows nginx snippet');
mcp_test_expect(str_contains($setup_src, 'revoke_oauth'), 'setup has oauth revoke');
mcp_test_expect(str_contains($setup_src, 'mcp_oauth_revoke_all'), 'setup calls mcp_oauth_revoke_all');
mcp_test_expect(str_contains($setup_src, 'resourcespace_mcp_oauth_revoke_confirm'), 'setup confirms before revoke');
mcp_test_expect(str_contains($setup_src, 'pages/help.php'), 'setup links to help page');
mcp_test_expect(str_contains($setup_src, 'resourcespace_mcp_trust_proxy_needed'), 'setup warns when proxy HTTPS is untrusted');
mcp_test_expect(!str_contains($setup_src, '[R=301,L]'), 'setup Apache does not 301 /mcp/');
mcp_test_expect(str_contains($setup_src, '$mcp_pub . \'$\'') && str_contains($setup_src, '$mcp_page . \' [L]\''), 'setup Apache rewrites /mcp to plugin mcp.php');
mcp_test_expect(!str_contains($setup_src, '$mcp_pub . \'/ {\''), 'setup nginx has no /mcp/ location');
mcp_test_expect(!str_contains($setup_src, 'upload_max_filesize'), 'setup does not show upload_max_filesize');
mcp_test_expect(!str_contains($setup_src, 'post_max_size'), 'setup does not show post_max_size');
mcp_test_expect(!str_contains($setup_src, 'api_upload_urls'), 'setup does not show URL upload hosts');
mcp_test_expect(!str_contains($setup_src, 'mcp_ssrf_range_label'), 'setup does not show SSRF ranges');

$help = $root . '/pages/help.php';
mcp_test_expect(file_exists($help), 'pages/help.php exists');
$help_src = (string) file_get_contents($help);
mcp_test_expect(str_contains($help_src, 'authenticate.php'), 'help includes authenticate');
mcp_test_expect(!str_contains($help_src, "checkperm('a')"), 'help is not admin-only');
mcp_test_expect(str_contains($help_src, 'mcp_oauth_canonical_resource'), 'help shows paste URL');
mcp_test_expect(str_contains($help_src, 'mcp_oauth_is_anonymous_user'), 'help uses OAuth anonymous gate');
mcp_test_expect(str_contains($help_src, '<ol>'), 'help has numbered steps');
mcp_test_expect(str_contains($help_src, 'readonly'), 'help paste URL is copyable');
mcp_test_expect(str_contains($help_src, 'resourcespace_mcp_help_prereq'), 'help mentions admin prerequisites');
mcp_test_expect(str_contains($lang['resourcespace_mcp_help_prereq'] ?? '', '/mcp'), 'help prereq names the /mcp rewrite');
mcp_test_expect(str_contains($lang['resourcespace_mcp_oauth_discovery_help'] ?? '', '/mcp'), 'discovery help names the /mcp rewrite');
mcp_test_expect(str_contains($help_src, 'mcp_oauth_plugin_resource'), 'help shows plugin-root fallback URL');
mcp_test_expect(str_contains($help_src, 'mcp_upload.php'), 'help documents upload URL');
mcp_test_expect(str_contains($help_src, 'resourcespace_mcp_help_bearer'), 'help documents API-key Bearer');
mcp_test_expect(str_contains($help_src, 'revoke_mine'), 'help can revoke this user');
mcp_test_expect(!str_contains($help_src, 'FormData'), 'help has no upload FormData');
mcp_test_expect(!str_contains($help_src, 'webkitdirectory'), 'help has no folder picker');
mcp_test_expect(!str_contains($help_src, 'action="') || !str_contains($help_src, 'mcp_upload.php"'), 'help has no upload form action');
mcp_test_expect(!str_contains($help_src, 'get_resource_types'), 'help does not list resource types');
mcp_test_expect(!str_contains($lang['resourcespace_mcp_oauth_discovery_help'] ?? '', 'Not required'), 'discovery help does not call origin well-known optional');

$expected_ann = [
    'search' => ['do_search', 'search_get_previews', 'get_dash_search_data'],
    'resources' => [
        'create_resource', 'get_resource_data', 'get_resource_field_data', 'put_resource_data',
        'delete_resource', 'copy_resource', 'upload_file', 'upload_file_by_url', 'upload_multipart',
        'replace_resource_file', 'add_alternative_file', 'delete_alternative_file', 'get_alternative_files',
        'get_related_resources', 'update_related_resource', 'relate_all_resources', 'get_resource_log',
        'resource_log_last_rows', 'get_resource_path', 'get_resource_all_image_sizes', 'get_data_by_field',
        'update_resource_type', 'get_resource_types', 'resource_file_readonly', 'get_edit_access',
        'get_resource_access', 'delete_resources_in_collection', 'get_processing_message', 'delete_access_keys',
    ],
    'collections' => [
        'create_collection', 'delete_collection', 'add_resource_to_collection', 'collection_add_resources',
        'remove_resource_from_collection', 'collection_remove_resources', 'get_user_collections',
        'search_public_collections', 'get_resource_collections', 'get_collection', 'save_collection',
        'get_featured_collections', 'reorder_featured_collections', 'show_hide_collection',
        'send_collection_to_admin', 'get_collections_resource_count',
    ],
    'metadata' => [
        'get_field_options', 'update_field', 'get_nodes', 'set_node', 'add_resource_nodes',
        'add_resource_nodes_multi', 'get_node_id', 'toggle_active_state_for_nodes', 'get_resource_type_fields',
        'create_resource_type_field', 'save_tab', 'reorder_tabs', 'delete_tabs',
    ],
    'users' => [
        'checkperm', 'get_users', 'new_user', 'save_user', 'get_users_by_permission',
        'send_user_message', 'get_user_message', 'get_profile_image', 'mark_email_as_invalid',
    ],
    'system' => ['get_system_status', 'get_daily_stat_summary'],
];
foreach ($expected_ann as $category => $ids) {
    foreach ($ids as $id) {
        mcp_test_expect(isset($resourcespace_mcp_annotations[$id]), 'annotation ' . $id);
        mcp_test_expect_eq($resourcespace_mcp_annotations[$id]['category'] ?? null, $category, $id . ' category');
        $row = $resourcespace_mcp_annotations[$id];
        mcp_test_expect(is_string($row['description'] ?? null) && $row['description'] !== '', $id . ' description');
        $syn = $row['synonyms'] ?? [];
        mcp_test_expect(is_array($syn) && count($syn) >= 2 && count($syn) <= 5, $id . ' synonyms 2-5');
        mcp_test_expect(array_key_exists('readOnlyHint', $row), $id . ' readOnlyHint');
        mcp_test_expect(array_key_exists('destructiveHint', $row), $id . ' destructiveHint');
    }
}
mcp_test_expect(!isset($resourcespace_mcp_annotations['login']), 'login not annotated');
mcp_test_expect(!isset($resourcespace_mcp_annotations['validate_upload_url']), 'validate_upload_url not annotated');
mcp_test_expect(!isset($resourcespace_mcp_annotations['do_report']), 'do_report not annotated');
mcp_test_expect_eq($resourcespace_mcp_annotations['get_resource_access']['category'], 'resources', 'get_resource_access in resources');
mcp_test_expect_eq($resourcespace_mcp_annotations['get_edit_access']['category'], 'resources', 'get_edit_access in resources');
mcp_test_expect_eq($resourcespace_mcp_annotations['delete_resource']['destructiveHint'], true, 'delete_resource destructive');
mcp_test_expect_eq($resourcespace_mcp_annotations['create_resource']['destructiveHint'], false, 'create_resource not destructive');
mcp_test_expect_eq($resourcespace_mcp_annotations['new_user']['destructiveHint'], true, 'new_user destructive');
mcp_test_expect_eq($resourcespace_mcp_annotations['save_user']['destructiveHint'], true, 'save_user destructive');

$prev_https = $_SERVER['HTTPS'] ?? null;
$prev_remote = $GLOBALS['enable_remote_apis'] ?? null;
$prev_enable = $GLOBALS['resourcespace_mcp_enable'] ?? null;
$prev_base = $GLOBALS['baseurl'] ?? null;
$prev_trust = $GLOBALS['resourcespace_mcp_trust_proxy'] ?? null;
$GLOBALS['enable_remote_apis'] = false;
$GLOBALS['resourcespace_mcp_enable'] = true;
$GLOBALS['baseurl'] = 'https://dam.example';
$GLOBALS['resourcespace_mcp_trust_proxy'] = false;
unset($_SERVER['HTTPS']);
$fail_checks = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($fail_checks['resourcespace_mcp']['status'] ?? null, 'FAIL', 'extra_checks fails when remote apis off');
$GLOBALS['enable_remote_apis'] = true;
$GLOBALS['CSRF_exempt_pages'] = array_values(array_unique(array_merge(
    is_array($GLOBALS['CSRF_exempt_pages'] ?? null) ? $GLOBALS['CSRF_exempt_pages'] : [],
    ['mcp_upload']
)));
$ok_checks = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($ok_checks['resourcespace_mcp']['status'] ?? null, 'OK', 'extra_checks ok on CLI when baseurl is https');
$GLOBALS['baseurl'] = 'http://dam.example';
$_SERVER['HTTPS'] = 'on';
$http_checks = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($http_checks['resourcespace_mcp']['status'] ?? null, 'FAIL', 'extra_checks fails when baseurl is http');
$hook_src = (string) file_get_contents($hook);
mcp_test_expect(!str_contains($hook_src, 'mcp_https_ok'), 'extra_checks does not call mcp_https_ok');
if ($prev_https === null) {
    unset($_SERVER['HTTPS']);
} else {
    $_SERVER['HTTPS'] = $prev_https;
}
$GLOBALS['enable_remote_apis'] = $prev_remote;
$GLOBALS['resourcespace_mcp_enable'] = $prev_enable;
$GLOBALS['baseurl'] = $prev_base;
$GLOBALS['resourcespace_mcp_trust_proxy'] = $prev_trust;

$prev_csrf = $GLOBALS['CSRF_exempt_pages'] ?? null;
$prev_csrf_remote = $GLOBALS['enable_remote_apis'] ?? null;
$prev_csrf_enable = $GLOBALS['resourcespace_mcp_enable'] ?? null;
$prev_csrf_base = $GLOBALS['baseurl'] ?? null;
$GLOBALS['enable_remote_apis'] = true;
$GLOBALS['resourcespace_mcp_enable'] = true;
$GLOBALS['baseurl'] = 'https://dam.example';
$GLOBALS['CSRF_exempt_pages'] = ['login', 'mcp'];
$csrf_fail = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($csrf_fail['resourcespace_mcp']['status'] ?? null, 'FAIL', 'extra_checks fails when mcp_upload not CSRF-exempt');
mcp_test_expect(str_contains((string) ($csrf_fail['resourcespace_mcp']['info'] ?? ''), 'mcp_upload'), 'extra_checks names mcp_upload');
$GLOBALS['CSRF_exempt_pages'] = ['login', 'mcp', 'mcp_upload'];
$csrf_ok = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($csrf_ok['resourcespace_mcp']['status'] ?? null, 'OK', 'extra_checks ok when mcp_upload exempt');
$GLOBALS['CSRF_exempt_pages'] = ['mcp', 'mcp_upload'];
$login_fail = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($login_fail['resourcespace_mcp']['status'] ?? null, 'FAIL', 'extra_checks fails when login dropped from CSRF exempt');
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
unset($_SERVER['HTTPS']);
$GLOBALS['CSRF_exempt_pages'] = ['login', 'mcp', 'mcp_upload'];
$GLOBALS['resourcespace_mcp_trust_proxy'] = false;
$GLOBALS['baseurl'] = 'https://dam.example';
$proxy_fail = HookResourcespace_mcpAllExtra_checks();
mcp_test_expect_eq($proxy_fail['resourcespace_mcp']['status'] ?? null, 'FAIL', 'extra_checks fails when proxy HTTPS is untrusted');
unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
if ($prev_https === null) {
    unset($_SERVER['HTTPS']);
} else {
    $_SERVER['HTTPS'] = $prev_https;
}
$cfg_src = (string) file_get_contents($root . '/config/config.php');
mcp_test_expect(str_contains($cfg_src, 'global $CSRF_exempt_pages'), 'config.php uses global CSRF list');
mcp_test_expect(str_contains($cfg_src, "['login']"), 'config.php seeds login if unset');
mcp_test_expect(str_contains($cfg_src, 'unset($mcp_csrf_page)'), 'config.php unsets CSRF loop variable');
$GLOBALS['CSRF_exempt_pages'] = ['login', 'other_plugin'];
(static function () use ($root): void {
    include $root . '/config/config.php';
})();
mcp_test_expect(in_array('login', $GLOBALS['CSRF_exempt_pages'], true), 'function-scope include keeps login');
mcp_test_expect(in_array('other_plugin', $GLOBALS['CSRF_exempt_pages'], true), 'function-scope include keeps other plugin');
mcp_test_expect(in_array('mcp', $GLOBALS['CSRF_exempt_pages'], true), 'function-scope include appends mcp');
mcp_test_expect(!isset($lang['resourcespace_mcp_php_upload_max']), 'php upload_max lang not set');
mcp_test_expect(!isset($lang['resourcespace_mcp_help_upload_title']), 'help upload title lang not set');
mcp_test_expect(!isset($lang['resourcespace_mcp_upload_hosts']), 'upload hosts lang not set');
if ($prev_csrf === null) {
    unset($GLOBALS['CSRF_exempt_pages']);
} else {
    $GLOBALS['CSRF_exempt_pages'] = $prev_csrf;
}
$GLOBALS['enable_remote_apis'] = $prev_csrf_remote;
$GLOBALS['resourcespace_mcp_enable'] = $prev_csrf_enable;
$GLOBALS['baseurl'] = $prev_csrf_base;

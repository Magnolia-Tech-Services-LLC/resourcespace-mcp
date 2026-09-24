<?php

require dirname(__DIR__) . '/include/mcp_catalog.php';
require_once dirname(__DIR__) . '/include/mcp_tools.php';

mcp_test_expect_eq(mcp_catalog_id('api_do_search'), 'do_search', 'strip prefix');
mcp_test_expect_eq(mcp_catalog_id('do_search'), null, 'non-api ignored');
mcp_test_expect(in_array('login', mcp_deny_list(), true), 'login denied');
mcp_test_expect(in_array('validate_upload_url', mcp_deny_list(), true), 'validate_upload_url denied');
mcp_test_expect(in_array('do_report', mcp_deny_list(), true), 'do_report denied');
mcp_test_expect(in_array('upload_file', mcp_deny_list(), true), 'upload_file denied');

$php = ['api_do_search', 'api_login', 'api_validate_upload_url', 'api_upload_file', 'api_new_user', 'api_get_resource_data', 'api_mystery_new'];
require dirname(__DIR__) . '/config/catalog_annotations.php';
$cat = mcp_catalog_from_functions($php, $resourcespace_mcp_annotations);

mcp_test_expect(!isset($cat['login']), 'login not in catalog');
mcp_test_expect(!isset($cat['validate_upload_url']), 'validate_upload_url not in catalog');
mcp_test_expect(!isset($cat['upload_file']), 'upload_file not in catalog');
mcp_test_expect_eq($cat['mystery_new']['unannotated'], true, 'unknown is uncurated');
mcp_test_expect_eq($cat['mystery_new']['category'], 'uncurated', 'uncurated category');
mcp_test_expect_eq($cat['mystery_new']['destructiveHint'], true, 'uncurated destructive');
mcp_test_expect_eq($cat['do_search']['category'], 'search', 'curated category');

$allow = [
    'resources' => true, 'search' => true, 'collections' => true, 'metadata' => true,
    'users' => true, 'system' => true, 'plugins' => true, 'uncurated' => false,
];
mcp_test_expect_eq(mcp_action_permitted('do_search', $cat, $allow), true, 'search allowed');
mcp_test_expect_eq(mcp_action_permitted('mystery_new', $cat, $allow), false, 'uncurated default off');
mcp_test_expect_eq(mcp_action_permitted('login', $cat, $allow), false, 'deny-list not permitted');

$allow['users'] = false;
mcp_test_expect_eq(mcp_action_permitted('new_user', $cat, $allow), false, 'disabled category');

$allow['users'] = true;
$hits = mcp_search_actions('find resources', null, 10, $cat, $allow);
$names = array_column($hits, 'name');
mcp_test_expect(in_array('do_search', $names, true), 'search finds do_search');

$empty = mcp_search_actions('zzzz-no-match', null, 10, $cat, $allow);
mcp_test_expect(isset($empty['categories']), 'no match returns categories');

$tools = mcp_tool_list();
mcp_test_expect_eq(count($tools), 9, 'nine tools');
$tnames = array_column($tools, 'name');
mcp_test_expect(in_array('rs_execute_action', $tnames, true), 'execute present');
$exec = null;
foreach ($tools as $t) {
    if ($t['name'] === 'rs_execute_action') {
        $exec = $t;
    }
}
mcp_test_expect_eq($exec['annotations']['destructiveHint'] ?? false, true, 'execute destructiveHint true');

$by_name = [];
foreach ($tools as $t) {
    $by_name[$t['name']] = $t;
    mcp_test_expect(isset($t['inputSchema']['type']) && $t['inputSchema']['type'] === 'object', $t['name'] . ' inputSchema object');
    mcp_test_expect(isset($t['inputSchema']['properties']) && is_array($t['inputSchema']['properties']), $t['name'] . ' inputSchema properties');
}
$schema_props = [
    'rs_search_actions' => ['intent', 'category', 'limit'],
    'rs_execute_action' => ['action', 'params'],
    'rs_search' => ['query', 'resource_type', 'limit', 'offset'],
    'rs_get_resource' => ['ref'],
    'rs_create_resource' => ['resource_type', 'url', 'initial_metadata'],
    'rs_upload_resource' => ['ref', 'url'],
    'rs_update_metadata' => ['ref', 'field', 'value'],
    'rs_manage_collection' => ['action', 'name', 'collection_ref', 'resource_refs'],
    'rs_check_permissions' => ['permission_code', 'resource_ref'],
];
foreach ($schema_props as $name => $keys) {
    foreach ($keys as $key) {
        mcp_test_expect(isset($by_name[$name]['inputSchema']['properties'][$key]), $name . ' ' . $key);
    }
}
mcp_test_expect_eq(
    $by_name['rs_manage_collection']['inputSchema']['properties']['action']['enum'] ?? null,
    ['create', 'add', 'remove', 'add_resources', 'remove_resources'],
    'collection action enum'
);

$GLOBALS['resourcespace_mcp_allow_resources'] = true;
$GLOBALS['resourcespace_mcp_allow_search'] = true;
$GLOBALS['resourcespace_mcp_allow_collections'] = true;
$GLOBALS['resourcespace_mcp_allow_metadata'] = true;
$GLOBALS['resourcespace_mcp_allow_users'] = true;
$GLOBALS['resourcespace_mcp_allow_system'] = true;
$GLOBALS['resourcespace_mcp_allow_plugins'] = true;
$GLOBALS['resourcespace_mcp_allow_uncurated'] = false;
$from_globals = mcp_current_allowlist();
mcp_test_expect_eq($from_globals['uncurated'], false, 'allowlist uncurated from global');
mcp_test_expect_eq($from_globals['search'], true, 'allowlist search from global');
mcp_test_expect(function_exists('mcp_build_catalog'), 'mcp_build_catalog exists');
$built = mcp_build_catalog();
mcp_test_expect(is_array($built), 'build catalog returns array');
mcp_test_expect(!isset($built['login']), 'build catalog excludes deny-list');

$catalog_src = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_catalog.php');
mcp_test_expect(str_contains($catalog_src, 'api_bindings.php'), 'cache key includes api_bindings mtime');
mcp_test_expect(function_exists('mcp_catalog_cache_path'), 'cache path helper exists');
mcp_test_expect(function_exists('mcp_catalog_load_cached'), 'cache load helper exists');
mcp_test_expect(function_exists('mcp_catalog_save_cached'), 'cache save helper exists');
mcp_test_expect(str_ends_with(mcp_catalog_cache_path(), '/resourcespace_mcp_catalog.json'), 'cache lives in temp dir json');

$GLOBALS['productversion'] = '10.7';
$GLOBALS['plugins'] = ['resourcespace_mcp'];
$cache_path = mcp_catalog_cache_path();
if (is_file($cache_path)) {
    unlink($cache_path);
}
mcp_test_expect_eq(mcp_catalog_load_cached(), null, 'missing cache is null');
$sample = ['do_search' => ['name' => 'do_search', 'category' => 'search']];
mcp_catalog_save_cached($sample);
$loaded = mcp_catalog_load_cached();
mcp_test_expect_eq($loaded, $sample, 'cache roundtrip');
$GLOBALS['productversion'] = '11.0';
mcp_test_expect_eq(mcp_catalog_load_cached(), null, 'version change invalidates cache');
$GLOBALS['productversion'] = '10.7';
if (is_file($cache_path)) {
    unlink($cache_path);
}

$tools_src = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_tools.php');
mcp_test_expect(str_contains($tools_src, 'mcp_catalog_load_cached'), 'tools load catalog cache after auth');
mcp_test_expect(str_contains($tools_src, 'mcp_catalog_save_cached'), 'tools save catalog cache after auth');
$mcp_src = (string) file_get_contents(dirname(__DIR__) . '/pages/mcp.php');
mcp_test_expect(!str_contains($mcp_src, 'set_plugin_config'), 'mcp.php does not store catalog in plugin config');

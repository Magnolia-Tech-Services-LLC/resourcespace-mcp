<?php

require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_jsonrpc.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_auth.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_dispatch.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_catalog.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_tools.php';

if (!function_exists('log_activity')) {
    function log_activity($note = null, $log_code = null, $value_new = null, $remote_table = null, $remote_column = null, $remote_ref = null, $ref_column = null, $value_old = null, $user = null, $generate_diff = false)
    {
        $GLOBALS['mcp_test_log'][] = $note;
        return true;
    }
}

require dirname(__DIR__) . '/plugins/magnolia_mcp/config/catalog_annotations.php';
$php = ['api_do_search', 'api_get_resource_data', 'api_get_resource_field_data', 'api_create_resource', 'api_upload_file_by_url', 'api_update_field', 'api_create_collection', 'api_checkperm', 'api_new_user'];
$cat = mcp_catalog_from_functions($php, $magnolia_mcp_annotations);
$allow = [
    'resources' => true, 'search' => true, 'collections' => true, 'metadata' => true,
    'users' => false, 'system' => true, 'plugins' => true, 'uncurated' => false,
];

unset($GLOBALS['mcp_test_execute_throw'], $GLOBALS['mcp_test_execute_http'], $GLOBALS['mcp_test_execute_return']);
unset($GLOBALS['api_upload_urls']);
$GLOBALS['mcp_test_log'] = [];

$r = mcp_handle_tool('rs_search', ['query' => 'cat'], $cat, $allow);
mcp_test_expect_eq($r['isError'], false, 'search runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'do_search', 'search uses do_search');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['search'] ?? null, 'cat', 'search maps query to search');
mcp_test_expect_eq((int) ($GLOBALS['mcp_test_last_query']['fetchrows'] ?? 0), 50, 'search always passes fetchrows');

$r2 = mcp_handle_tool('rs_check_permissions', ['permission_code' => 's'], $cat, $allow);
mcp_test_expect_eq($r2['isError'], true, 'users category off blocks promoted tool');

$r3 = mcp_handle_tool('rs_execute_action', ['action' => 'login', 'params' => []], $cat, $allow);
mcp_test_expect_eq($r3['isError'], true, 'deny-list execute refused');

$r4 = mcp_handle_tool('rs_upload_resource', ['ref' => 1, 'url' => 'http://127.0.0.1/x'], $cat, $allow);
mcp_test_expect_eq($r4['isError'], true, 'ssrf blocks upload tool');

mcp_test_reset_auth_state();
$key = get_api_key(7);
$state = [
    'plugins' => ['magnolia_mcp'],
    'enable' => true,
    'enable_remote_apis' => true,
    'trust_proxy' => false,
    'baseurl' => 'https://dam.example',
    'allowlist' => $allow,
    'catalog' => $cat,
];
$server = [
    'REQUEST_METHOD' => 'POST',
    'HTTPS' => 'on',
    'HTTP_ACCEPT' => 'application/json, text/event-stream',
    'HTTP_AUTHORIZATION' => 'Bearer alice:' . $key,
];
$init = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $server,
    $state
);
mcp_test_expect_eq($init['http'], 200, 'initialize 200');
mcp_test_expect_eq($init['body']['result']['protocolVersion'] ?? '', MCP_PROTOCOL_VERSION, 'protocol pinned');

$note = mcp_handle_message(
    ['jsonrpc' => '2.0', 'method' => 'notifications/initialized'],
    $server,
    $state
);
mcp_test_expect_eq($note['http'], 202, 'initialized 202');
mcp_test_expect_eq($note['empty'], true, 'initialized empty body');

$noauth = $server;
unset($noauth['HTTP_AUTHORIZATION']);
$GLOBALS['mcp_test_log'] = [];
$denied = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $noauth,
    $state
);
mcp_test_expect_eq($denied['http'], 401, 'initialize requires bearer');
mcp_test_expect_log_redacted($key, '401');

$from_redirect = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $noauth + ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer alice:' . $key],
    $state
);
mcp_test_expect_eq($from_redirect['http'], 200, 'initialize via REDIRECT_HTTP_AUTHORIZATION');

// Unauthenticated GET is 401 in pages/mcp.php (OAuth discovery). handle_message still accepts GET.
$get_server = $server;
$get_server['REQUEST_METHOD'] = 'GET';
$from_get = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $get_server,
    $state
);
mcp_test_expect_eq($from_get['http'], 200, 'handle_message does not 405 GET');

$root_mcp = file_get_contents(dirname(__DIR__) . '/plugins/magnolia_mcp/mcp.php');
mcp_test_expect($root_mcp !== false, 'plugin-root mcp.php exists');
mcp_test_expect(str_contains((string) $root_mcp, "/pages/mcp.php"), 'plugin-root mcp.php includes pages/mcp.php');
mcp_test_expect(!str_contains((string) $root_mcp, 'boot.php'), 'plugin-root mcp.php does not boot itself');
$mcp_src = file_get_contents(dirname(__DIR__) . '/plugins/magnolia_mcp/pages/mcp.php');
mcp_test_expect($mcp_src !== false, 'pages/mcp.php exists');
$disable_pos = strpos((string) $mcp_src, '$disable_browser_check = true');
$boot_pos = strpos((string) $mcp_src, 'boot.php');
$decode_pos = strpos((string) $mcp_src, 'mcp_jsonrpc_decode');
$get_pos = strpos((string) $mcp_src, "=== 'GET'");
$delete_pos = strpos((string) $mcp_src, "=== 'DELETE'");
$accept_pos = strpos((string) $mcp_src, 'mcp_accept_allows_json');
$plugin_pos = strpos((string) $mcp_src, "in_array('magnolia_mcp'");
$handle_pos = strpos((string) $mcp_src, 'mcp_handle_message');
mcp_test_expect($disable_pos !== false && $boot_pos !== false && $disable_pos < $boot_pos, 'disable_browser_check before boot.php');
mcp_test_expect(str_contains((string) $mcp_src, 'dirname(__DIR__, 3)'), 'pages/mcp.php uses __DIR__ for RS include');
mcp_test_expect($get_pos !== false && $decode_pos !== false && $get_pos < $decode_pos, 'GET branch before decode');
mcp_test_expect(str_contains((string) $mcp_src, 'mcp_oauth_www_authenticate'), 'GET 401 sends WWW-Authenticate');
$https_pos = strpos((string) $mcp_src, 'mcp_https_ok');
$www_pos = strpos((string) $mcp_src, 'mcp_oauth_www_authenticate');
mcp_test_expect(
    $get_pos !== false && $https_pos !== false && $www_pos !== false && $get_pos < $https_pos && $https_pos < $www_pos,
    'GET HTTPS fail 403 before WWW-Authenticate'
);
mcp_test_expect($delete_pos !== false && $delete_pos < $decode_pos, 'DELETE 405 before decode');
mcp_test_expect($accept_pos !== false && $accept_pos < $decode_pos, 'Accept 406 before decode');
mcp_test_expect($plugin_pos !== false && $handle_pos !== false && $plugin_pos < $handle_pos, 'plugin enabled check before handle_message');
mcp_test_expect(str_contains((string) $mcp_src, 'mcp_authorization_header'), 'mcp.php resolves Authorization');
mcp_test_expect(str_contains((string) $mcp_src, 'getallheaders'), 'mcp.php reads getallheaders');
$auth_pos = strpos((string) $mcp_src, 'mcp_authorization_header');
mcp_test_expect($auth_pos !== false && $handle_pos !== false && $auth_pos < $handle_pos, 'mcp.php resolves Authorization before handle_message');
mcp_test_expect(str_contains((string) $mcp_src, 'mcp_current_allowlist'), 'mcp.php uses mcp_current_allowlist');
mcp_test_expect(!str_contains((string) $mcp_src, '$magnolia_mcp_allowlist'), 'mcp.php does not use $magnolia_mcp_allowlist');
mcp_test_expect(!str_contains((string) $mcp_src, 'authenticate.php'), 'mcp.php does not include authenticate.php');


mcp_test_expect_eq($cat['do_search']['unannotated'], false, 'do_search curated');
mcp_test_expect_eq($cat['create_resource']['unannotated'], false, 'create_resource curated');
mcp_test_expect_eq($cat['upload_file_by_url']['unannotated'], false, 'upload_file_by_url curated');
mcp_test_expect_eq($cat['update_field']['unannotated'], false, 'update_field curated');
mcp_test_expect_eq($cat['create_collection']['unannotated'], false, 'create_collection curated');
mcp_test_expect_eq($cat['checkperm']['unannotated'], false, 'checkperm curated');
mcp_test_expect_eq($cat['get_resource_field_data']['unannotated'], false, 'get_resource_field_data curated');
mcp_test_expect_eq($cat['checkperm']['category'], 'users', 'checkperm users category');
mcp_test_expect_eq($cat['upload_file_by_url']['category'], 'resources', 'upload_file_by_url resources category');

$GLOBALS['mcp_test_log'] = [];
mcp_handle_tool('rs_check_permissions', ['permission_code' => 's'], $cat, $allow);
mcp_test_expect_log_redacted($key, 'disabled category');

$GLOBALS['mcp_test_log'] = [];
mcp_handle_tool('rs_execute_action', ['action' => 'login', 'params' => []], $cat, $allow);
mcp_test_expect_log_redacted($key, 'deny-list');

$GLOBALS['mcp_test_log'] = [];
$bad_key_server = $server;
$bad_key_server['HTTP_AUTHORIZATION'] = 'Bearer nosuch:' . $key;
$bad_key = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $bad_key_server,
    $state
);
mcp_test_expect_eq($bad_key['http'], 401, 'invalid bearer 401');
mcp_test_expect_log_redacted($key, 'invalid bearer');

$search_args = mcp_handle_tool('rs_search_actions', ['intent' => 'find resources'], $cat, $allow);
mcp_test_expect_eq($search_args['isError'], false, 'search_actions runs');
$search_decoded = json_decode($search_args['text'], true);
mcp_test_expect(is_array($search_decoded), 'search_actions json');
mcp_test_expect(in_array('do_search', array_column($search_decoded, 'name'), true), 'search_actions finds do_search');

$got = mcp_handle_tool('rs_get_resource', ['ref' => 12], $cat, $allow);
mcp_test_expect_eq($got['isError'], false, 'get_resource runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'get_resource_field_data', 'get_resource ends on field data');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['resource'] ?? null, '12', 'get_resource maps ref to resource');
$got_decoded = json_decode($got['text'], true);
mcp_test_expect(is_array($got_decoded), 'get_resource combined json');

$created = mcp_handle_tool('rs_create_resource', ['resource_type' => '1'], $cat, $allow);
mcp_test_expect_eq($created['isError'], false, 'create_resource without url runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'create_resource', 'create uses create_resource');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['resource_type'] ?? null, '1', 'create maps resource_type');

$create_ssrf = mcp_handle_tool('rs_create_resource', ['resource_type' => '1', 'url' => 'http://127.0.0.1/x'], $cat, $allow);
mcp_test_expect_eq($create_ssrf['isError'], true, 'ssrf blocks create_resource url');

$meta = mcp_handle_tool('rs_update_metadata', ['ref' => 12, 'field' => 8, 'value' => 'x'], $cat, $allow);
mcp_test_expect_eq($meta['isError'], false, 'update_metadata runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'update_field', 'update uses update_field');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['resource'] ?? null, '12', 'update maps ref to resource');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['field'] ?? null, '8', 'update maps field');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['value'] ?? null, 'x', 'update maps value');

$coll_unknown = mcp_handle_tool('rs_manage_collection', ['action' => 'explode'], $cat, $allow);
mcp_test_expect_eq($coll_unknown['isError'], true, 'unknown collection action isError');

$coll_no_name = mcp_handle_tool('rs_manage_collection', ['action' => 'create'], $cat, $allow);
mcp_test_expect_eq($coll_no_name['isError'], true, 'collection create without name isError');

$coll = mcp_handle_tool('rs_manage_collection', ['action' => 'create', 'name' => 'Spring'], $cat, $allow);
mcp_test_expect_eq($coll['isError'], false, 'collection create runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'create_collection', 'collection create maps action');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['name'] ?? null, 'Spring', 'collection create maps name');

$php_coll = array_merge($php, [
    'api_add_resource_to_collection',
    'api_remove_resource_from_collection',
    'api_collection_add_resources',
    'api_collection_remove_resources',
]);
$cat_coll = mcp_catalog_from_functions($php_coll, $magnolia_mcp_annotations);
$coll_add = mcp_handle_tool('rs_manage_collection', ['action' => 'add', 'collection_ref' => 3, 'resource_refs' => [12]], $cat_coll, $allow);
mcp_test_expect_eq($coll_add['isError'], false, 'collection add runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'add_resource_to_collection', 'collection add maps action');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['resource'] ?? null, '12', 'collection add maps resource');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['collection'] ?? null, '3', 'collection add maps collection');
$coll_bulk = mcp_handle_tool('rs_manage_collection', ['action' => 'add_resources', 'collection_ref' => 3, 'resource_refs' => [12, 13]], $cat_coll, $allow);
mcp_test_expect_eq($coll_bulk['isError'], false, 'collection add_resources runs');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'collection_add_resources', 'collection add_resources maps action');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['resources'] ?? null, '12,13', 'collection add_resources csv');

$exec_ok = mcp_handle_tool('rs_execute_action', ['action' => 'do_search', 'params' => ['search' => 'dog']], $cat, $allow);
mcp_test_expect_eq($exec_ok['isError'], false, 'execute permitted action');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'do_search', 'execute uses action id');

$exec_ssrf = mcp_handle_tool('rs_execute_action', ['action' => 'upload_file_by_url', 'params' => ['ref' => 1, 'url' => 'http://127.0.0.1/x']], $cat, $allow);
mcp_test_expect_eq($exec_ssrf['isError'], true, 'execute ssrf on upload url');

$php_replace = array_merge($php, ['api_replace_resource_file']);
$cat_replace = mcp_catalog_from_functions($php_replace, $magnolia_mcp_annotations);
$exec_replace = mcp_handle_tool(
    'rs_execute_action',
    ['action' => 'replace_resource_file', 'params' => ['ref' => 1, 'file_location' => 'http://127.0.0.1/x']],
    $cat_replace,
    $allow
);
mcp_test_expect_eq($exec_replace['isError'], true, 'execute ssrf on replace_resource_file file_location');

$php_alt = array_merge($php, ['api_add_alternative_file']);
$cat_alt = mcp_catalog_from_functions($php_alt, $magnolia_mcp_annotations);
$exec_alt = mcp_handle_tool(
    'rs_execute_action',
    ['action' => 'add_alternative_file', 'params' => ['resource' => 1, 'name' => 'x', 'file' => 'http://127.0.0.1/x']],
    $cat_alt,
    $allow
);
mcp_test_expect_eq($exec_alt['isError'], true, 'execute ssrf on add_alternative_file file');

$php_perm = array_merge($php, ['api_get_resource_access', 'api_get_edit_access']);
$cat_perm = mcp_catalog_from_functions($php_perm, $magnolia_mcp_annotations);
$allow_users = $allow;
$allow_users['users'] = true;
$perm_ok = mcp_handle_tool('rs_check_permissions', ['permission_code' => 's', 'resource_ref' => 12], $cat_perm, $allow_users);
mcp_test_expect_eq($perm_ok['isError'], false, 'check_permissions runs when users on');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'get_edit_access', 'check_permissions ends on edit access');

$allow_users_no_resources = $allow_users;
$allow_users_no_resources['resources'] = false;
$perm_blocked = mcp_handle_tool('rs_check_permissions', ['permission_code' => 's', 'resource_ref' => 12], $cat_perm, $allow_users_no_resources);
mcp_test_expect_eq($perm_blocked['isError'], true, 'check_permissions resource access follows resources allowlist');

$ping = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 3, 'method' => 'ping'],
    $server,
    $state
);
mcp_test_expect_eq($ping['http'], 200, 'ping 200');
mcp_test_expect_eq(json_encode($ping['body']['result'] ?? null), '{}', 'ping empty object');

$note_id = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'notifications/initialized'],
    $server,
    $state
);
mcp_test_expect_eq($note_id['http'], 200, 'initialized with id 200');
mcp_test_expect_eq(json_encode($note_id['body']['result'] ?? null), '{}', 'initialized with id empty object');
mcp_test_expect_eq($note_id['empty'] ?? false, false, 'initialized with id not empty');

$list = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 4, 'method' => 'tools/list'],
    $server,
    $state
);
mcp_test_expect_eq($list['http'], 200, 'tools/list 200');
mcp_test_expect_eq(count($list['body']['result']['tools'] ?? []), 9, 'tools/list nine tools');

$call = mcp_handle_message(
    [
        'jsonrpc' => '2.0',
        'id' => 5,
        'method' => 'tools/call',
        'params' => ['name' => 'rs_search', 'arguments' => ['query' => 'cat']],
    ],
    $server,
    $state
);
mcp_test_expect_eq($call['http'], 200, 'tools/call 200');
mcp_test_expect_eq($call['body']['result']['isError'] ?? true, false, 'tools/call search not error');
mcp_test_expect_eq($call['body']['result']['content'][0]['type'] ?? '', 'text', 'tools/call text content');

$call_denied = mcp_handle_message(
    [
        'jsonrpc' => '2.0',
        'id' => 6,
        'method' => 'tools/call',
        'params' => ['name' => 'rs_execute_action', 'arguments' => ['action' => 'login', 'params' => []]],
    ],
    $server,
    $state
);
mcp_test_expect_eq($call_denied['http'], 200, 'tools/call deny-list stays HTTP 200');
mcp_test_expect_eq($call_denied['body']['result']['isError'] ?? false, true, 'tools/call deny-list isError');

$unk = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 9, 'method' => 'no_such_method'],
    $server,
    $state
);
mcp_test_expect_eq($unk['http'], 200, 'unknown method HTTP 200');
mcp_test_expect_eq($unk['body']['error']['code'] ?? 0, -32601, 'unknown method -32601');

$off = $state;
$off['enable'] = false;
$disabled = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $server,
    $off
);
mcp_test_expect_eq($disabled['http'], 403, 'plugin disable 403');

$no_remote = $state;
$no_remote['enable_remote_apis'] = false;
$remote_off = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $server,
    $no_remote
);
mcp_test_expect_eq($remote_off['http'], 403, 'remote apis off 403');

$plain = $server;
unset($plain['HTTPS']);
$http_denied = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $plain,
    $state
);
mcp_test_expect_eq($http_denied['http'], 403, 'plain HTTP 403');

$evil = $server;
$evil['HTTP_ORIGIN'] = 'https://claude.ai';
$origin_ok = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $evil,
    $state
);
mcp_test_expect_eq($origin_ok['http'], 200, 'connector Origin is not 403');

$ver = $server;
$ver['HTTP_MCP_PROTOCOL_VERSION'] = '1999-01-01';
$ver_denied = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'],
    $ver,
    $state
);
mcp_test_expect_eq($ver_denied['http'], 400, 'unsupported protocol HTTP 400');

mcp_test_expect_eq($init['body']['result']['serverInfo']['name'] ?? '', 'ResourceSpace', 'serverInfo name');
mcp_test_expect(isset($init['body']['result']['capabilities']['tools']), 'initialize tools capability');

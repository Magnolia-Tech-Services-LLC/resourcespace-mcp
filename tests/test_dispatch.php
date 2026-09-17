<?php

require dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_dispatch.php';

$q = mcp_build_query('update_field', ['resource' => 12, 'field' => 8, 'value' => 'x']);
parse_str($q, $p);
mcp_test_expect_eq($p['function'], 'update_field', 'named function');
mcp_test_expect_eq($p['resource'], '12', 'named resource');
mcp_test_expect(!isset($p['param1']), 'no param1');

$q2 = mcp_build_query('put_resource_data', ['resource' => 1, 'data' => ['a' => 1]]);
parse_str($q2, $p2);
mcp_test_expect_eq(json_decode($p2['data'], true), ['a' => 1], 'array json-encoded');

$lim = mcp_inject_limits('do_search', ['search' => 'cat']);
mcp_test_expect_eq($lim['fetchrows'], 50, 'default fetchrows');
$lim2 = mcp_inject_limits('do_search', ['search' => 'cat', 'fetchrows' => 10]);
mcp_test_expect_eq($lim2['fetchrows'], 10, 'caller fetchrows kept');
$lim3 = mcp_inject_limits('checkperm', ['perm' => 's']);
mcp_test_expect(!isset($lim3['fetchrows']), 'no fetchrows on checkperm');
$lim_neg = mcp_inject_limits('do_search', ['search' => 'cat', 'fetchrows' => -1]);
mcp_test_expect_eq($lim_neg['fetchrows'], 50, 'negative fetchrows clamped');
$lim_zero = mcp_inject_limits('do_search', ['search' => 'cat', 'fetchrows' => 0]);
mcp_test_expect_eq($lim_zero['fetchrows'], 50, 'zero fetchrows clamped');
$lim_log = mcp_inject_limits('resource_log_last_rows', []);
mcp_test_expect_eq($lim_log['maxrecords'], 50, 'resource_log_last_rows uses maxrecords');
mcp_test_expect(!isset($lim_log['fetchrows']), 'resource_log_last_rows has no fetchrows');

$big = [];
for ($i = 0; $i < 5000; $i++) {
    $big[] = ['n' => $i, 'pad' => str_repeat('x', 20)];
}
$trunc = mcp_truncate_decoded($big, 2000);
mcp_test_expect_eq($trunc['truncated'], true, 'truncated flag');
mcp_test_expect(strlen($trunc['text']) <= 2500, 'truncated size bounded');
json_decode($trunc['text'], true);
mcp_test_expect_eq(json_last_error(), JSON_ERROR_NONE, 'truncated output is json');

$obj = ['keep' => str_repeat('k', 40), 'drop' => str_repeat('d', 400)];
$trunc_obj = mcp_truncate_decoded($obj, 200);
mcp_test_expect_eq($trunc_obj['truncated'], true, 'object truncated flag');
$obj_decoded = json_decode($trunc_obj['text'], true);
mcp_test_expect(is_array($obj_decoded) && isset($obj_decoded['_notice']), 'object truncation keeps structure');
mcp_test_expect(isset($obj_decoded['keep']), 'object truncation keeps earlier keys');

$GLOBALS['mcp_test_execute_http'] = 403;
$GLOBALS['mcp_test_execute_return'] = json_encode(['status' => 'fail']);
unset($GLOBALS['mcp_test_execute_throw']);
$r = mcp_execute('new_user', ['username' => 'bob']);
mcp_test_expect_eq($r['http'], 200, 'http status restored');
mcp_test_expect_eq($r['isError'], true, 'fail payload isError');

$GLOBALS['mcp_test_execute_http'] = 0;
$GLOBALS['mcp_test_execute_return'] = false;
$r2 = mcp_execute('missing_fn', []);
mcp_test_expect_eq($r2['isError'], true, 'bool false isError');

$GLOBALS['mcp_test_execute_return'] = json_encode(false);
$r_false = mcp_execute('get_resource_data', ['resource' => 12]);
mcp_test_expect_eq($r_false['isError'], true, 'json false isError');

$GLOBALS['mcp_test_execute_return'] = json_encode(null);
$r_null = mcp_execute('get_resource_data', ['resource' => 12]);
mcp_test_expect_eq($r_null['isError'], true, 'json null isError');

$GLOBALS['mcp_test_execute_return'] = json_encode('FAILED: Resource created, but the file was not uploaded');
$r_failed = mcp_execute('create_resource', ['resource_type' => '1']);
mcp_test_expect_eq($r_failed['isError'], true, 'FAILED string isError');

$GLOBALS['mcp_test_execute_throw'] = true;
unset($GLOBALS['mcp_test_execute_return']);
$r3 = mcp_execute('do_search', ['search' => 'x']);
mcp_test_expect_eq($r3['isError'], true, 'throwable isError');
mcp_test_expect_eq($r3['http'], 200, 'throwable http 200');

unset($GLOBALS['mcp_test_execute_throw'], $GLOBALS['mcp_test_execute_http'], $GLOBALS['mcp_test_execute_return']);
$r4 = mcp_execute('do_search', ['search' => 'cat']);
mcp_test_expect_eq($r4['isError'], false, 'success not error');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['function'], 'do_search', 'dispatched function');
mcp_test_expect_eq($GLOBALS['mcp_test_last_query']['search'], 'cat', 'named search param');
mcp_test_expect_eq((int) $GLOBALS['mcp_test_last_query']['fetchrows'], 50, 'injected fetchrows on execute');

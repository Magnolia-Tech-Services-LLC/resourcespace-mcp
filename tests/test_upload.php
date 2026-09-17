<?php

require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_jsonrpc.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_dispatch.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_catalog.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_auth.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_oauth.php';
require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_upload.php';

if (!function_exists('isValidCSRFToken')) {
    function isValidCSRFToken($token_data, $session_id)
    {
        return ($GLOBALS['mcp_test_csrf_ok'] ?? false)
            && (string) $token_data === 'good-token'
            && (string) $session_id === 'sess-alice';
    }
}
if (!function_exists('is_int_loose')) {
    function is_int_loose($value): bool
    {
        return is_numeric($value) && (string) (int) $value === (string) $value;
    }
}

mcp_test_expect_eq(mcp_upload_parse_ref(''), null, 'empty ref is absent');
mcp_test_expect_eq(mcp_upload_parse_ref('0'), null, 'zero ref is absent');
mcp_test_expect_eq(mcp_upload_parse_ref('12'), 12, 'digit ref');
mcp_test_expect_eq(mcp_upload_parse_bool('false'), false, 'string false is false');
mcp_test_expect_eq(mcp_upload_parse_bool('0'), false, '0 is false');
mcp_test_expect_eq(mcp_upload_parse_bool('1'), true, '1 is true');
mcp_test_expect_eq(mcp_upload_forbidden_present(['url' => 'https://x']), ['url'], 'url forbidden');
mcp_test_expect_eq(mcp_upload_forbidden_present(['file_path' => '/etc/passwd']), ['file_path'], 'file_path forbidden');

mcp_test_expect(mcp_upload_post_too_large(
    ['CONTENT_LENGTH' => (string) (2 * 1024 * 1024), 'CONTENT_TYPE' => 'multipart/form-data; boundary=x'],
    [],
    []
), 'empty POST+FILES with large CONTENT_LENGTH is too large');

$ini = mcp_upload_file_problem(['file' => ['error' => 1, 'name' => 'a.jpg']]);
mcp_test_expect_eq($ini['http'] ?? 0, 413, 'INI_SIZE is 413');

mcp_test_reset_auth_state();
$GLOBALS['mcp_test_csrf_ok'] = true;
$GLOBALS['anonymous_login'] = '';
$GLOBALS['session_autologout'] = true;
$GLOBALS['session_length'] = 300;
$GLOBALS['CSRF_token_identifier'] = 'CSRFToken';
$GLOBALS['mcp_test_session_row'] = [
    'ref' => 7,
    'username' => 'alice',
    'approved' => 1,
    'idle_seconds' => 10,
    'session' => 'sess-alice',
];
$sess = mcp_upload_authenticate(null, ['user' => 'sess-alice'], ['CSRFToken' => 'good-token']);
mcp_test_expect_eq($sess['ok'] ?? false, true, 'session+token authenticates');

$no_tok = mcp_upload_authenticate(null, ['user' => 'sess-alice'], []);
mcp_test_expect_eq($no_tok['http'] ?? 0, 403, 'session without token is 403');

$bad_bearer = mcp_upload_authenticate('Bearer not-a-token', ['user' => 'sess-alice'], ['CSRFToken' => 'good-token']);
mcp_test_expect_eq($bad_bearer['http'] ?? 0, 401, 'invalid Bearer does not fall through');

$get_user = mcp_upload_authenticate(null, [], []);
mcp_test_expect_eq($get_user['http'] ?? 0, 401, 'no cookie is 401');

$GLOBALS['mcp_test_session_row']['idle_seconds'] = 99999;
$idle = mcp_upload_authenticate(null, ['user' => 'sess-alice'], ['CSRFToken' => 'good-token']);
mcp_test_expect_eq($idle['http'] ?? 0, 401, 'idle session is 401');
$GLOBALS['mcp_test_session_row']['idle_seconds'] = 10;

$GLOBALS['anonymous_login'] = 'alice';
$GLOBALS['username'] = 'alice';
$anon = mcp_upload_authenticate(null, ['user' => 'sess-alice'], ['CSRFToken' => 'good-token']);
mcp_test_expect_eq($anon['ok'] ?? true, false, 'anonymous rejected');
$GLOBALS['anonymous_login'] = '';

$state = [
    'plugins' => ['magnolia_mcp'],
    'enable' => true,
    'enable_remote_apis' => true,
    'trust_proxy' => false,
    'baseurl' => 'https://dam.example',
    'allowlist' => mcp_current_allowlist(),
    'catalog' => [
        'create_resource' => ['category' => 'resources'],
        'upload_multipart' => ['category' => 'resources'],
    ],
];
$GLOBALS['magnolia_mcp_allow_resources'] = true;
$https = ['HTTPS' => 'on', 'REQUEST_METHOD' => 'POST', 'CONTENT_TYPE' => 'multipart/form-data; boundary=x'];
$key = hash('sha256', '7' . $GLOBALS['mcp_test_scramble']);
$auth = 'Bearer alice:' . $key;

foreach (['url' => 'https://x', 'file_path' => '/etc/passwd', 'previewonly' => '1', 'alternative' => '3', 'autorotate' => '1'] as $bad_key => $bad_val) {
    $unauth = mcp_upload_handle($https, ['resource_type' => '1', $bad_key => $bad_val], [
        'file' => ['error' => 0, 'name' => 'a.jpg', 'tmp_name' => '/tmp/x'],
    ], [], $state);
    mcp_test_expect_eq($unauth['http'], 401, $bad_key . ' field unauthenticated is 401');

    $forbidden = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => $auth], ['resource_type' => '1', $bad_key => $bad_val], [
        'file' => ['error' => 0, 'name' => 'a.jpg', 'tmp_name' => '/tmp/x'],
    ], [], $state);
    mcp_test_expect_eq($forbidden['http'], 400, $bad_key . ' field is 400');
}

$bad_bearer_url = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => 'Bearer not-a-token'], ['resource_type' => '1', 'url' => 'https://x'], [
    'file' => ['error' => 0, 'name' => 'a.jpg', 'tmp_name' => '/tmp/x'],
], [], $state);
mcp_test_expect_eq($bad_bearer_url['http'], 401, 'invalid Bearer with url is 401');

$get_ignored = mcp_upload_authenticate(null, [], []);
mcp_test_expect_eq($get_ignored['http'] ?? 0, 401, 'no cookie is 401 even if GET user would exist');
$_GET['user'] = 'sess-alice';
$get_user_ignored = mcp_upload_authenticate(null, [], ['CSRFToken' => 'good-token']);
mcp_test_expect_eq($get_user_ignored['http'] ?? 0, 401, '$_GET[user] is ignored');
unset($_GET['user']);

$GLOBALS['mcp_test_execute_map'] = [
    'create_resource' => json_encode(42),
    'upload_multipart' => ['http' => 204, 'body' => json_encode(['status' => 'success', 'data' => null])],
];
$GLOBALS['mcp_test_originals'] = [42 => ''];
$ok = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => $auth], ['resource_type' => '1'], [
    'file' => ['error' => 0, 'name' => 'a.jpg', 'tmp_name' => '/tmp/x'],
], [], $state);
mcp_test_expect_eq($ok['http'], 200, 'create+upload 200');
mcp_test_expect_eq($ok['body']['ref'] ?? null, 42, 'ref 42');
mcp_test_expect_eq($ok['body']['created'] ?? null, true, 'created true');
mcp_test_expect_eq($ok['body']['file_uploaded'] ?? null, true, 'file uploaded');

$GLOBALS['mcp_test_originals'] = [9 => '/tmp/exists'];
$GLOBALS['mcp_test_execute_map'] = [];
$repl = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => $auth], ['ref' => '9'], [
    'file' => ['error' => 0, 'name' => 'b.jpg', 'tmp_name' => '/tmp/x'],
], [], $state);
mcp_test_expect_eq($repl['http'], 409, 'existing original without replace is 409');
mcp_test_expect_eq($repl['body']['error'] ?? '', 'replace_required', 'replace_required');

$GLOBALS['mcp_test_originals'] = [55 => ['error' => 'denied']];
$inacc = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => $auth], ['ref' => '55'], [
    'file' => ['error' => 0, 'name' => 'c.jpg', 'tmp_name' => '/tmp/x'],
], [], $state);
mcp_test_expect_eq($inacc['http'], 403, 'inaccessible resource is 403');
mcp_test_expect_eq($inacc['body']['error_description'] ?? '', 'Resource is not accessible', 'inaccessible description');

unset($GLOBALS['mcp_test_originals']);
$GLOBALS['mcp_test_execute_map'] = [
    'get_resource_data' => ['error' => 'FALSE'],
];
$api_fail = mcp_upload_handle($https + ['HTTP_AUTHORIZATION' => $auth], ['ref' => '56'], [
    'file' => ['error' => 0, 'name' => 'd.jpg', 'tmp_name' => '/tmp/x'],
], [], $state);
mcp_test_expect_eq($api_fail['http'], 403, 'get_resource_data error array is 403');

$src = (string) file_get_contents(dirname(__DIR__) . '/plugins/magnolia_mcp/pages/mcp_upload.php');
mcp_test_expect(str_contains($src, '$disable_browser_check = true'), 'upload page disables browser check');
$boot = strpos($src, 'boot.php');
$flag = strpos($src, '$disable_browser_check');
mcp_test_expect($flag !== false && $boot !== false && $flag < $boot, 'disable_browser_check before boot.php');
mcp_test_expect(!str_contains($src, 'authenticate.php'), 'upload page does not include authenticate.php');
mcp_test_expect(!str_contains($src, 'generateFormToken'), 'upload page does not generateFormToken');
mcp_test_expect(str_contains($src, 'mcp_upload_handle'), 'upload page calls mcp_upload_handle');
mcp_test_expect(str_contains($src, 'mcp_jsonrpc.php'), 'upload page includes mcp_jsonrpc.php');
mcp_test_expect(str_contains($src, 'WWW-Authenticate') || str_contains($src, 'mcp_oauth_www_authenticate'), '401 can send WWW-Authenticate');
mcp_test_expect(!str_contains($src, 'mcp_execute('), 'upload page does not call mcp_execute');

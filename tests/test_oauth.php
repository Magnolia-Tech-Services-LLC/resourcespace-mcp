<?php

require_once __DIR__ . '/oauth_store_stub.php';
require_once dirname(__DIR__) . '/include/mcp_dispatch.php';
require_once dirname(__DIR__) . '/include/mcp_oauth.php';

$GLOBALS['baseurl'] = 'https://dam.example';
mcp_oauth_test_reset_store();

mcp_test_expect(strlen(mcp_oauth_random()) >= 40, 'random token length');
mcp_test_expect(!str_contains(mcp_oauth_random(), ':'), 'random token has no colon');
mcp_test_expect_eq(strlen(mcp_oauth_hash('abc')), 64, 'sha256 hex length');

$verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
$want = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
mcp_test_expect_eq(mcp_oauth_pkce_s256($verifier), $want, 'RFC 7636 S256 appendix B');

mcp_test_expect_eq(mcp_oauth_issuer(), 'https://dam.example', 'issuer is origin');
mcp_test_expect_eq(
    mcp_oauth_canonical_resource(),
    'https://dam.example/mcp',
    'canonical resource is the install /mcp URL'
);
mcp_test_expect_eq(mcp_oauth_effective_resource(null), mcp_oauth_canonical_resource(), 'omitted resource defaults');
mcp_test_expect_eq(mcp_oauth_effective_resource(''), mcp_oauth_canonical_resource(), 'empty resource defaults');
mcp_test_expect_eq(
    mcp_oauth_effective_resource('https://dam.example/plugins/resourcespace_mcp/pages/mcp.php'),
    mcp_oauth_canonical_resource(),
    'pages/ path is a resource alias'
);
mcp_test_expect_eq(
    mcp_oauth_effective_resource('https://dam.example/plugins/resourcespace_mcp/mcp.php'),
    mcp_oauth_canonical_resource(),
    'plugin-root mcp.php is a resource alias'
);
mcp_test_expect_eq(
    mcp_oauth_effective_resource('https://dam.example/mcp/'),
    mcp_oauth_canonical_resource(),
    'trailing slash /mcp/ is a resource alias'
);
$legacy_client = mcp_oauth_register(
    ['client_name' => 'Grok', 'redirect_uris' => ['https://example.com/cb'], 'token_endpoint_auth_method' => 'none'],
    '203.0.113.80'
);
$legacy_code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($legacy_code),
    'userref' => 7,
    'client_id' => $legacy_client['body']['client_id'],
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => 'https://dam.example/plugins/resourcespace_mcp/pages/mcp.php',
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$legacy_grant = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $legacy_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $legacy_client['body']['client_id'],
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($legacy_grant['http'], 200, 'legacy pages/ resource on code still grants');
$alias_req_code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($alias_req_code),
    'userref' => 7,
    'client_id' => $legacy_client['body']['client_id'],
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$alias_req_grant = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $alias_req_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $legacy_client['body']['client_id'],
    'code_verifier' => $verifier,
    'resource' => 'https://dam.example/plugins/resourcespace_mcp/pages/mcp.php',
]);
mcp_test_expect_eq($alias_req_grant['http'], 200, 'token request pages/ resource matches stored canonical');
mcp_test_expect_eq(mcp_oauth_effective_resource('https://evil.example/mcp'), null, 'resource mismatch rejected');
mcp_test_expect_eq(mcp_oauth_normalize_scope(null), 'mcp', 'null scope is mcp');
mcp_test_expect_eq(mcp_oauth_normalize_scope('openid profile email'), 'mcp', 'OIDC-only scope is mcp');
mcp_test_expect_eq(mcp_oauth_normalize_scope('openid mcp extra'), 'mcp', 'mcp plus junk is mcp');

$www = mcp_oauth_www_authenticate();
mcp_test_expect(str_contains($www, 'error="invalid_token"'), 'www-authenticate error');
mcp_test_expect(str_contains($www, 'resource_metadata="https://dam.example/plugins/resourcespace_mcp/pages/oauth_protected_resource.php"'), 'www-authenticate prm');
mcp_test_expect(str_contains($www, 'scope="mcp"'), 'www-authenticate scope');

$code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($code),
    'userref' => 7,
    'client_id' => 'mcp_abc',
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
mcp_test_expect_eq(mcp_oauth_consume_code(mcp_oauth_hash($code)), true, 'first consume ok');
mcp_test_expect_eq(mcp_oauth_consume_code(mcp_oauth_hash($code)), false, 'second consume CAS fails');

$root = dirname(__DIR__) . '/dbstruct';
foreach (
    [
        'table_resourcespace_mcp_oauth_client.txt',
        'index_resourcespace_mcp_oauth_client.txt',
        'table_resourcespace_mcp_oauth_code.txt',
        'index_resourcespace_mcp_oauth_code.txt',
        'table_resourcespace_mcp_oauth_token.txt',
        'index_resourcespace_mcp_oauth_token.txt',
        'table_resourcespace_mcp_oauth_dcr.txt',
        'index_resourcespace_mcp_oauth_dcr.txt',
    ] as $f
) {
    mcp_test_expect(is_file($root . '/' . $f), $f . ' exists');
}
$client_tbl = (string) file_get_contents($root . '/table_resourcespace_mcp_oauth_client.txt');
mcp_test_expect(str_contains($client_tbl, "client_name,varchar(255),NO,,'',"), 'client_name quoted default');
$code_tbl = (string) file_get_contents($root . '/table_resourcespace_mcp_oauth_code.txt');
mcp_test_expect(str_contains($code_tbl, "scope,varchar(64),NO,,'mcp',"), 'code scope quoted default');
mcp_test_expect(str_contains($code_tbl, 'used,tinyint(1),NO,,0,'), 'used default 0');
$token_tbl = (string) file_get_contents($root . '/table_resourcespace_mcp_oauth_token.txt');
mcp_test_expect(str_contains($token_tbl, 'revoked,tinyint(1),NO,,0,'), 'revoked default 0');
$idx = (string) file_get_contents($root . '/index_resourcespace_mcp_oauth_client.txt');
mcp_test_expect(str_contains($idx, ',0,client_id,1,client_id,'), 'unique client_id index');

$cfg = (string) file_get_contents(dirname(__DIR__) . '/config/config.php');
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
    ] as $page
) {
    mcp_test_expect(str_contains($cfg, "'" . $page . "'") || str_contains($cfg, '"' . $page . '"'), 'CSRF exempt ' . $page);
}

$amp_qs = 'response_type=code&amp%3Bclient_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata&amp%3Bredirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&amp%3Bcode_challenge=abc&amp%3Bcode_challenge_method=S256&amp%3Bstate=st&amp%3Bscope=mcp&amp%3Bresource=https%3A%2F%2Fdam.example%2Fplugins%2Fresourcespace_mcp%2Fmcp.php';
$amp_parsed = mcp_oauth_parse_query_string($amp_qs);
mcp_test_expect_eq($amp_parsed['client_id'] ?? null, 'https://claude.ai/oauth/mcp-oauth-client-metadata', 'login htmlspecialchars ampersands recover client_id');
mcp_test_expect_eq($amp_parsed['redirect_uri'] ?? null, 'https://claude.ai/api/mcp/auth_callback', 'login htmlspecialchars ampersands recover redirect_uri');
mcp_test_expect_eq($amp_parsed['code_challenge_method'] ?? null, 'S256', 'login htmlspecialchars ampersands recover PKCE method');
mcp_test_expect(!isset($amp_parsed['amp;client_id']), 'amp; prefix stripped from keys');
$clean_qs = 'response_type=code&client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata';
$clean_parsed = mcp_oauth_parse_query_string($clean_qs);
mcp_test_expect_eq($clean_parsed['client_id'] ?? null, 'https://claude.ai/oauth/mcp-oauth-client-metadata', 'normal authorize query still parses');
$amp_params = mcp_oauth_authorize_params(['response_type' => 'code'], [], $amp_qs);
mcp_test_expect_eq($amp_params['client_id'] ?? null, 'https://claude.ai/oauth/mcp-oauth-client-metadata', 'authorize params prefer repaired QUERY_STRING');

require_once dirname(__DIR__) . '/hooks/all.php';
mcp_test_expect_eq(HookResourcespace_mcpAllBeforetermsredirect(), ['oauth_authorize'], 'terms skip authorize');

require_once dirname(__DIR__) . '/include/mcp_jsonrpc.php';
require_once dirname(__DIR__) . '/include/mcp_auth.php';
require_once dirname(__DIR__) . '/include/mcp_catalog.php';
require_once dirname(__DIR__) . '/include/mcp_tools.php';

mcp_test_reset_auth_state();
$state = [
    'plugins' => ['resourcespace_mcp'],
    'enable' => true,
    'enable_remote_apis' => true,
    'trust_proxy' => false,
    'baseurl' => 'https://dam.example',
    'allowlist' => [],
    'catalog' => [],
];
$noauth = [
    'REQUEST_METHOD' => 'POST',
    'HTTPS' => 'on',
    'HTTP_ACCEPT' => 'application/json',
];
$denied = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $noauth,
    $state
);
mcp_test_expect_eq($denied['http'], 401, 'missing token 401');
mcp_test_expect(isset($denied['headers'][0]), '401 carries WWW-Authenticate header');
mcp_test_expect(str_contains((string) $denied['headers'][0], 'resource_metadata='), '401 resource_metadata');
mcp_test_expect(str_contains((string) $denied['headers'][0], 'error="invalid_token"'), '401 invalid_token');

$https_fail = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    ['REQUEST_METHOD' => 'POST', 'HTTP_ACCEPT' => 'application/json'],
    $state
);
mcp_test_expect_eq($https_fail['http'], 403, 'https fail 403');
mcp_test_expect(($https_fail['headers'] ?? []) === [], '403 has no WWW-Authenticate');

$prm = dirname(__DIR__) . '/pages/oauth_protected_resource.php';
$as = dirname(__DIR__) . '/pages/oauth_authorization_server.php';
mcp_test_expect(is_file($prm), 'PRM page exists');
mcp_test_expect(is_file($as), 'AS metadata page exists');
$prm_src = (string) file_get_contents($prm);
$as_src = (string) file_get_contents($as);
mcp_test_expect(str_contains($prm_src, '$disable_browser_check = true'), 'PRM disables browser check');
mcp_test_expect(str_contains($as_src, '$disable_browser_check = true'), 'AS disables browser check');
mcp_test_expect(!str_contains($prm_src, 'authenticate.php'), 'PRM no authenticate');
mcp_test_expect(!str_contains($as_src, 'authenticate.php'), 'AS no authenticate');
mcp_test_expect(str_contains($as_src, 'client_id_metadata_document_supported'), 'AS advertises CIMD');
mcp_test_expect(str_contains($as_src, '"none"'), 'AS advertises token auth none');
mcp_test_expect(!str_contains($prm_src, 'offline_access'), 'PRM does not list offline_access');

$mcp_src = (string) file_get_contents(dirname(__DIR__) . '/pages/mcp.php');
mcp_test_expect(str_contains($mcp_src, "=== 'HEAD'"), 'mcp.php handles HEAD');
mcp_test_expect(str_contains($mcp_src, 'mcp_oauth_www_authenticate'), 'mcp.php sets WWW-Authenticate');
mcp_test_expect(preg_match("/GET.*401|401.*GET/s", $mcp_src) === 1 || str_contains($mcp_src, 'invalid_token'), 'unauthenticated GET is 401 path');
$get_pos = strpos($mcp_src, "=== 'GET'");
$https_pos = strpos($mcp_src, 'mcp_https_ok');
$www_pos = strpos($mcp_src, 'mcp_oauth_www_authenticate');
mcp_test_expect(
    $get_pos !== false && $https_pos !== false && $www_pos !== false && $get_pos < $https_pos && $https_pos < $www_pos,
    'GET HTTPS 403 before WWW-Authenticate 401'
);
mcp_test_expect(str_contains($mcp_src, '$baseurl') && str_contains($mcp_src, '$resourcespace_mcp_trust_proxy'), 'GET HTTPS uses same baseurl/trust_proxy as POST');

mcp_test_reset_auth_state();
mcp_oauth_test_reset_store();
$access = mcp_oauth_random();
mcp_test_expect(!str_contains($access, ':'), 'access token has no colon');
mcp_oauth_insert_token([
    'token_hash' => mcp_oauth_hash($access),
    'token_type' => 'access',
    'userref' => 7,
    'client_id' => 'mcp_abc',
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 3600),
    'family' => 'fam1',
]);

$key = get_api_key(7);
$colon_server = [
    'REQUEST_METHOD' => 'POST',
    'HTTPS' => 'on',
    'HTTP_ACCEPT' => 'application/json',
    'HTTP_AUTHORIZATION' => 'Bearer alice:' . $key,
];
$colon = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $colon_server,
    $state
);
mcp_test_expect_eq($colon['http'], 200, 'colon Bearer still API-key path');

$oauth_server = $colon_server;
$oauth_server['HTTP_AUTHORIZATION'] = 'Bearer ' . $access;
$oauth_ok = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $oauth_server,
    $state
);
mcp_test_expect_eq($oauth_ok['http'], 200, 'opaque Bearer uses hashed access token');
mcp_test_expect_eq($GLOBALS['mcp_test_setup_user_called'], true, 'oauth setup_user called');

$bad_oauth = $colon_server;
$bad_oauth['HTTP_AUTHORIZATION'] = 'Bearer ' . mcp_oauth_random();
$oauth_bad = mcp_handle_message(
    ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []],
    $bad_oauth,
    $state
);
mcp_test_expect_eq($oauth_bad['http'], 401, 'unknown opaque token 401');
mcp_test_expect(str_contains((string) ($oauth_bad['headers'][0] ?? ''), 'invalid_token'), 'unknown opaque WWW-Authenticate');

mcp_test_expect_eq(mcp_cimd_url_allowed('https://127.0.0.1/meta.json')['ok'], false, 'CIMD loopback rejected');
mcp_test_expect_eq(mcp_cimd_url_allowed('https://10.0.0.5/meta.json')['ok'], false, 'CIMD private IP rejected');
mcp_test_expect_eq(mcp_cimd_url_allowed('http://claude.ai/meta.json')['ok'], false, 'CIMD http rejected');
mcp_test_expect_eq(mcp_cimd_url_allowed('https://claude.ai/meta.json')['ok'], true, 'CIMD public hostname allowed without live DNS');

$auth_src = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_auth.php');
mcp_test_expect(str_contains($auth_src, 'mcp_oauth_store.php'), 'auth includes oauth store');
mcp_test_expect(!str_contains($auth_src, 'mcp_oauth.php'), 'auth does not include oauth protocol');
$oauth_src = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_oauth.php');
mcp_test_expect(!str_contains($oauth_src, 'mcp_jsonrpc.php'), 'oauth protocol does not include jsonrpc');
mcp_test_expect(str_contains($oauth_src, 'mcp_oauth_store.php'), 'oauth protocol includes store');
mcp_test_expect(str_contains($oauth_src, 'mcp_dispatch.php'), 'oauth protocol includes dispatch');

mcp_test_expect_eq(mcp_oauth_is_loopback_host('localhost'), true, 'localhost loopback');
mcp_test_expect_eq(mcp_oauth_is_loopback_host('127.0.0.1'), true, '127.0.0.1 loopback');
mcp_test_expect_eq(mcp_oauth_is_loopback_host('::1'), true, 'ipv6 loopback');
mcp_test_expect_eq(mcp_oauth_is_loopback_host('localhost.evil.com'), false, 'localhost suffix rejected');

$registered = ['http://127.0.0.1/callback', 'http://localhost/callback'];
mcp_test_expect_eq(
    mcp_oauth_redirect_uri_matches('http://127.0.0.1:54321/callback', $registered),
    true,
    'loopback port ignored'
);
mcp_test_expect_eq(
    mcp_oauth_redirect_uri_matches('http://127.0.0.1:54321/other', $registered),
    false,
    'loopback path must match'
);
mcp_test_expect_eq(
    mcp_oauth_redirect_uri_matches('https://claude.ai/api/mcp/auth_callback', ['https://claude.ai/api/mcp/auth_callback']),
    true,
    'exact https match'
);

$cimd_url = 'https://claude.ai/api/mcp/auth_callback.json';
$GLOBALS['mcp_test_http'][$cimd_url] = [
    'ok' => true,
    'status' => 200,
    'body' => json_encode([
        'client_id' => $cimd_url,
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        'token_endpoint_auth_method' => 'none',
    ]),
    'error' => null,
];
$loaded = mcp_oauth_load_client($cimd_url, 'https://claude.ai/api/mcp/auth_callback');
mcp_test_expect_eq($loaded['ok'], true, 'CIMD client loads');
mcp_test_expect_eq($loaded['display'], 'claude.ai', 'CIMD display is client_id host');
mcp_test_expect_eq(mcp_oauth_get_client($cimd_url), null, 'CIMD is not persisted');

mcp_oauth_test_reset_store();
$reg = mcp_oauth_register(
    [
        'client_name' => 'Grok',
        'redirect_uris' => ['https://grok.x.ai/cb'],
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code', 'refresh_token'],
    ],
    '203.0.113.9'
);
mcp_test_expect_eq($reg['http'], 201, 'DCR 201');
mcp_test_expect(str_starts_with((string) ($reg['body']['client_id'] ?? ''), 'mcp_'), 'DCR client_id prefix');
$dcr_id = $reg['body']['client_id'];
$dcr_ok = mcp_oauth_load_client($dcr_id, 'https://grok.x.ai/cb');
mcp_test_expect_eq($dcr_ok['ok'], true, 'DCR client authorizes registered redirect');
$dcr_bad = mcp_oauth_load_client($dcr_id, 'https://evil.example/cb');
mcp_test_expect_eq($dcr_bad['ok'], false, 'DCR client rejects other redirect');

$secret = mcp_oauth_register(
    [
        'redirect_uris' => ['https://grok.x.ai/cb'],
        'token_endpoint_auth_method' => 'client_secret_basic',
    ],
    '203.0.113.9'
);
mcp_test_expect_eq($secret['http'] >= 400, true, 'confidential DCR rejected');

mcp_oauth_test_reset_store();
for ($i = 0; $i < 20; $i++) {
    mcp_oauth_register(['redirect_uris' => ['https://grok.x.ai/cb'], 'token_endpoint_auth_method' => 'none'], '198.51.100.2');
}
$limited = mcp_oauth_register(['redirect_uris' => ['https://grok.x.ai/cb'], 'token_endpoint_auth_method' => 'none'], '198.51.100.2');
mcp_test_expect_eq($limited['http'], 429, 'DCR rate limit 20/ip/hour');

$reg_src = (string) file_get_contents(dirname(__DIR__) . '/pages/oauth_register.php');
mcp_test_expect(str_contains($reg_src, '$disable_browser_check = true'), 'register disables browser check');
mcp_test_expect(!str_contains($reg_src, 'authenticate.php'), 'register no authenticate');

$GLOBALS['username'] = 'alice';
$GLOBALS['anonymous_login'] = 'guest';
mcp_test_expect_eq(mcp_oauth_is_anonymous_user(), false, 'alice is not anonymous');
$GLOBALS['username'] = 'guest';
mcp_test_expect_eq(mcp_oauth_is_anonymous_user(), true, 'guest is anonymous');

$loc = mcp_oauth_grant_location('https://example.com/cb', 'abc', 'st');
mcp_test_expect(str_starts_with($loc, 'https://example.com/cb?'), 'grant Location keeps client host');
mcp_test_expect(str_contains($loc, 'code=abc'), 'grant has code');
mcp_test_expect(str_contains($loc, 'state=st'), 'grant has state');
mcp_test_expect(str_contains($loc, 'iss=' . rawurlencode('https://dam.example')), 'grant has iss');
mcp_test_expect(!str_contains($loc, 'https://dam.example/https://'), 'grant is not RS-prefixed');

$deny = mcp_oauth_deny_location('https://example.com/cb', 'st');
mcp_test_expect(str_contains($deny, 'error=access_denied'), 'deny error');

$authz_src = (string) file_get_contents(dirname(__DIR__) . '/pages/oauth_authorize.php');
mcp_test_expect(str_contains($authz_src, 'authenticate.php'), 'authorize includes authenticate');
mcp_test_expect(!str_contains($authz_src, 'CentralSpacePost'), 'authorize is not CentralSpace AJAX');
mcp_test_expect(!str_contains($authz_src, 'onsubmit'), 'authorize has no onsubmit');
mcp_test_expect(!preg_match('/\bredirect\s*\(/', $authz_src), 'authorize does not call redirect()');
mcp_test_expect(str_contains($authz_src, "header('Location:"), 'authorize uses raw Location');
mcp_test_expect(str_contains($authz_src, 'generateFormToken("mcp_oauth_authorize")') || str_contains($authz_src, "generateFormToken('mcp_oauth_authorize')"), 'authorize CSRF token');
mcp_test_expect(str_contains($authz_src, 'mcp_oauth_posted_csrf_ok'), 'authorize validates CSRF token');
mcp_test_expect(str_contains($oauth_src, 'isValidCSRFToken'), 'consent CSRF uses isValidCSRFToken');
mcp_test_expect(str_contains($authz_src, 'mcp_oauth_plugin_enabled'), 'authorize requires plugin enable');
mcp_test_expect(str_contains($authz_src, 'resourcespace_mcp_oauth_redirect'), 'authorize shows redirect host');
mcp_test_expect(str_contains($authz_src, 'mcp_oauth_remember_return'), 'authorize remembers TOTP return');
mcp_test_expect(str_contains($authz_src, 'enforcePostRequest'), 'authorize POST enforced');
mcp_test_expect(!str_contains($authz_src, '$disable_browser_check'), 'authorize is a browser page');
mcp_test_expect(str_contains($authz_src, "str_replace"), 'authorize fills consent placeholders');
mcp_test_expect(!str_contains($authz_src, 'echo escape((string) $username)'), 'authorize does not dump username alone');
$en = (string) file_get_contents(dirname(__DIR__) . '/languages/en.php');
mcp_test_expect(str_contains($en, "'Grant access'"), 'consent title is Grant access');
mcp_test_expect(str_contains($en, "'MCP Server'"), 'plugin display name is MCP Server');
mcp_test_expect(str_contains($en, '[client]'), 'consent text has client placeholder');
mcp_test_expect(str_contains($en, '[username]'), 'consent text has username placeholder');

mcp_oauth_test_reset_store();
$reg = mcp_oauth_register(
    ['client_name' => 'Grok', 'redirect_uris' => ['https://example.com/cb'], 'token_endpoint_auth_method' => 'none'],
    '203.0.113.9'
);
$q = mcp_oauth_validate_authorize_request([
    'response_type' => 'code',
    'client_id' => $reg['body']['client_id'],
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012'),
    'code_challenge_method' => 'S256',
    'state' => 'st',
    'scope' => 'openid profile email',
]);
mcp_test_expect_eq($q['ok'], true, 'OIDC-only scope still valid');
mcp_test_expect_eq($q['scope'], 'mcp', 'granted scope is mcp');
$q_pages = mcp_oauth_validate_authorize_request([
    'response_type' => 'code',
    'client_id' => $reg['body']['client_id'],
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012'),
    'code_challenge_method' => 'S256',
    'state' => 'st',
    'resource' => 'https://dam.example/plugins/resourcespace_mcp/pages/mcp.php',
]);
mcp_test_expect_eq($q_pages['ok'], true, 'authorize accepts pages/ resource alias');
mcp_test_expect_eq($q_pages['resource'], mcp_oauth_canonical_resource(), 'authorize stores canonical resource');

mcp_oauth_test_reset_store();
$verifier = str_repeat('a', 64);
$client = mcp_oauth_register(
    ['client_name' => 'Grok', 'redirect_uris' => ['https://example.com/cb'], 'token_endpoint_auth_method' => 'none'],
    '203.0.113.10'
);
$client_id = $client['body']['client_id'];
$code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($code),
    'userref' => 7,
    'client_id' => $client_id,
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);

$wrong = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $client_id,
    'code_verifier' => str_repeat('b', 64),
]);
mcp_test_expect_eq($wrong['http'], 400, 'bad PKCE HTTP 400');
mcp_test_expect_eq($wrong['body']['error'] ?? '', 'invalid_grant', 'bad PKCE invalid_grant');
mcp_test_expect(!isset($wrong['body']['jsonrpc']), 'token error is not JSON-RPC');

$ok = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($ok['http'], 200, 'code grant 200');
mcp_test_expect_eq($ok['body']['token_type'] ?? '', 'Bearer', 'token_type Bearer');
mcp_test_expect_eq($ok['body']['expires_in'] ?? 0, 3600, 'access TTL 3600');
mcp_test_expect_eq($ok['body']['scope'] ?? '', 'mcp', 'token scope mcp');
mcp_test_expect(!str_contains((string) $ok['body']['access_token'], ':'), 'access token no colon');
$refresh = $ok['body']['refresh_token'];

$ref_ok = mcp_oauth_token_request([
    'grant_type' => 'refresh_token',
    'refresh_token' => $refresh,
    'client_id' => $client_id,
]);
mcp_test_expect_eq($ref_ok['http'], 200, 'refresh 200');
$refresh2 = $ref_ok['body']['refresh_token'];
mcp_test_expect($refresh2 !== $refresh, 'refresh rotated');

mcp_oauth_purge_expired();
$revoked_refresh = mcp_oauth_get_token(mcp_oauth_hash($refresh), 'refresh');
mcp_test_expect(
    $revoked_refresh !== null && (int) $revoked_refresh['revoked'] === 1,
    'purge keeps revoked refresh'
);

$reuse_refresh = mcp_oauth_token_request([
    'grant_type' => 'refresh_token',
    'refresh_token' => $refresh,
    'client_id' => $client_id,
]);
mcp_test_expect_eq($reuse_refresh['body']['error'] ?? '', 'invalid_grant', 'refresh reuse invalid_grant');
$reuse_new = mcp_oauth_token_request([
    'grant_type' => 'refresh_token',
    'refresh_token' => $refresh2,
    'client_id' => $client_id,
]);
mcp_test_expect_eq($reuse_new['body']['error'] ?? '', 'invalid_grant', 'family revoked after reuse');

$other_client = mcp_oauth_token_request([
    'grant_type' => 'refresh_token',
    'refresh_token' => $refresh2,
    'client_id' => 'mcp_other',
]);
mcp_test_expect_eq($other_client['body']['error'] ?? '', 'invalid_grant', 'wrong client_id invalid_grant');

$mismatch = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => 'nope',
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $client_id,
    'code_verifier' => $verifier,
    'resource' => 'https://evil.example/mcp',
]);
mcp_test_expect_eq($mismatch['body']['error'] ?? '', 'invalid_grant', 'resource mismatch invalid_grant');

mcp_oauth_test_reset_store();
$reuse_client = mcp_oauth_register(
    ['client_name' => 'Grok', 'redirect_uris' => ['https://example.com/cb'], 'token_endpoint_auth_method' => 'none'],
    '203.0.113.11'
);
$reuse_client_id = $reuse_client['body']['client_id'];
$reuse_code_plain = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($reuse_code_plain),
    'userref' => 7,
    'client_id' => $reuse_client_id,
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$first_redeem = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $reuse_code_plain,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $reuse_client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($first_redeem['http'], 200, 'code reuse first redeem 200');
mcp_oauth_purge_expired();
mcp_test_expect(
    mcp_oauth_get_code(mcp_oauth_hash($reuse_code_plain)) !== null,
    'purge keeps used authorization code'
);
$second_redeem = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $reuse_code_plain,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $reuse_client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($second_redeem['body']['error'] ?? '', 'invalid_grant', 'second code redeem invalid_grant');
mcp_test_expect_eq(
    mcp_oauth_lookup_access(mcp_oauth_hash((string) $first_redeem['body']['access_token'])),
    null,
    'code reuse revokes issued access'
);

mcp_oauth_test_reset_store();
$ttl_client = mcp_oauth_register(
    ['client_name' => 'Grok', 'redirect_uris' => ['https://example.com/cb'], 'token_endpoint_auth_method' => 'none'],
    '203.0.113.12'
);
$ttl_client_id = $ttl_client['body']['client_id'];
$ttl_code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($ttl_code),
    'userref' => 7,
    'client_id' => $ttl_client_id,
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$ttl_first = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $ttl_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $ttl_client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($ttl_first['http'], 200, 'used-after-ttl first redeem 200');
$ttl_hash = mcp_oauth_hash($ttl_code);
foreach ($GLOBALS['mcp_oauth_test_db']['resourcespace_mcp_oauth_code'] as &$ttl_row) {
    if ($ttl_row['code_hash'] === $ttl_hash) {
        $ttl_row['expires'] = date('Y-m-d H:i:s', time() - 60);
    }
}
unset($ttl_row);
mcp_oauth_purge_expired();
mcp_test_expect(
    mcp_oauth_get_code($ttl_hash) !== null,
    'purge keeps expired used authorization code'
);
$ttl_second = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $ttl_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $ttl_client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($ttl_second['body']['error'] ?? '', 'invalid_grant', 'expired used code invalid_grant');
mcp_test_expect_eq(
    mcp_oauth_lookup_access(mcp_oauth_hash((string) $ttl_first['body']['access_token'])),
    null,
    'expired used code still revokes access'
);

$token_src = (string) file_get_contents(dirname(__DIR__) . '/pages/oauth_token.php');
mcp_test_expect(str_contains($token_src, '$disable_browser_check = true'), 'token disables browser check');
mcp_test_expect(!str_contains($token_src, 'authenticate.php'), 'token no authenticate');
mcp_test_expect(str_contains($token_src, 'mcp_oauth_machine_json'), 'token uses machine json helper');
mcp_test_expect(!str_contains($token_src, 'mcp_jsonrpc_decode'), 'token page is not JSON-RPC');
mcp_test_expect(str_contains($token_src, 'no-store'), 'token Cache-Control no-store');

$code_omit = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($code_omit),
    'userref' => 7,
    'client_id' => $client_id,
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$omit = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $code_omit,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => $client_id,
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($omit['http'], 200, 'omitted resource grant 200');

$setup_src = (string) file_get_contents(dirname(__DIR__) . '/pages/setup.php');
mcp_test_expect(str_contains($setup_src, 'mcp_oauth_canonical_resource'), 'setup shows resource URL');
mcp_test_expect(str_contains($setup_src, 'oauth-authorization-server'), 'setup shows Apache rewrite snippet');
mcp_test_expect(!str_contains($setup_src, '[R=301,L]'), 'setup Apache snippet does not 301 /mcp/');
mcp_test_expect(str_contains($setup_src, 'location = '), 'setup nginx snippet has exact /mcp location');
mcp_test_expect(str_contains($setup_src, 'revoke'), 'setup has revoke');
mcp_test_expect(str_contains($setup_src, 'enforcePostRequest'), 'revoke is POST');
$en = (string) file_get_contents(dirname(__DIR__) . '/languages/en.php');
mcp_test_expect(str_contains($en, 'TOTP') || str_contains($en, 'Authenticator'), 'TOTP return documented');

mcp_oauth_test_reset_store();
mcp_oauth_insert_token([
    'token_hash' => mcp_oauth_hash('keep-me-out'),
    'token_type' => 'access',
    'userref' => 7,
    'client_id' => 'mcp_abc',
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 3600),
    'family' => 'fam-rev',
]);
$leftover_code = 'unused-after-revoke-all';
$unused_code_hash = mcp_oauth_hash($leftover_code);
mcp_oauth_insert_code([
    'code_hash' => $unused_code_hash,
    'userref' => 7,
    'client_id' => 'mcp_abc',
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
mcp_oauth_revoke_all();
mcp_test_expect_eq(mcp_oauth_lookup_access(mcp_oauth_hash('keep-me-out')), null, 'revoke all invalidates access');
mcp_test_expect_eq(mcp_oauth_consume_code($unused_code_hash), false, 'revoke all invalidates unused codes');

$fresh_code = mcp_oauth_random();
mcp_oauth_insert_code([
    'code_hash' => mcp_oauth_hash($fresh_code),
    'userref' => 7,
    'client_id' => 'mcp_abc',
    'redirect_uri' => 'https://example.com/cb',
    'code_challenge' => mcp_oauth_pkce_s256($verifier),
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => date('Y-m-d H:i:s', time() + 300),
]);
$fresh_grant = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $fresh_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => 'mcp_abc',
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($fresh_grant['http'], 200, 'fresh grant after revoke_all 200');
$leftover_present = mcp_oauth_token_request([
    'grant_type' => 'authorization_code',
    'code' => $leftover_code,
    'redirect_uri' => 'https://example.com/cb',
    'client_id' => 'mcp_abc',
    'code_verifier' => $verifier,
]);
mcp_test_expect_eq($leftover_present['body']['error'] ?? '', 'invalid_grant', 'expired leftover code invalid_grant');
mcp_test_expect(
    mcp_oauth_lookup_access(mcp_oauth_hash((string) $fresh_grant['body']['access_token'])) !== null,
    'leftover expired code does not revoke later grant'
);

$deny = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_catalog.php');
mcp_test_expect(str_contains($deny, "'login'"), 'login remains deny-listed');
mcp_test_expect(str_contains($deny, 'rename($tmp, $path)'), 'catalog cache write is atomic');

mcp_test_expect_eq(
    mcp_oauth_plugin_resource(),
    'https://dam.example/plugins/resourcespace_mcp/mcp.php',
    'plugin-root resource URL'
);
mcp_test_expect_eq(mcp_oauth_plugin_enabled(), false, 'plugin_enabled false without globals');
$GLOBALS['plugins'] = ['resourcespace_mcp'];
$GLOBALS['resourcespace_mcp_enable'] = true;
$GLOBALS['enable_remote_apis'] = true;
mcp_test_expect_eq(mcp_oauth_plugin_enabled(), true, 'plugin_enabled true when toggles on');
mcp_test_expect_eq(mcp_oauth_client_ip(['REMOTE_ADDR' => '203.0.113.9'], false), '203.0.113.9', 'DCR IP uses REMOTE_ADDR when trust-proxy off');
mcp_test_expect_eq(mcp_oauth_return_path_ok('/plugins/resourcespace_mcp/pages/oauth_authorize.php?x=1'), true, 'authorize return path ok');
mcp_test_expect_eq(mcp_oauth_return_path_ok('/rs/plugins/resourcespace_mcp/pages/oauth_authorize.php'), true, 'subdirectory authorize return ok');
mcp_test_expect_eq(mcp_oauth_return_path_ok('https://evil.example/'), false, 'absolute return URL rejected');
mcp_test_expect_eq(
    mcp_oauth_return_path_ok('//evil.example/plugins/resourcespace_mcp/pages/oauth_authorize.php'),
    false,
    'protocol-relative return rejected'
);
mcp_test_expect_eq(mcp_oauth_return_path_ok('/plugins/resourcespace_mcp/pages/home.php'), false, 'non-authorize return rejected');
mcp_test_expect_eq(
    mcp_oauth_return_path_ok('/plugins/resourcespace_mcp/pages/oauth_authorize.php/../evil'),
    false,
    'dot-dot return rejected'
);

$reg_src = (string) file_get_contents(dirname(__DIR__) . '/pages/oauth_register.php');
mcp_test_expect(str_contains($reg_src, 'mcp_oauth_client_ip'), 'register uses trust-proxy-aware IP');
mcp_test_expect(!str_contains($reg_src, 'get_ip()'), 'register does not call get_ip when trust-proxy off');

mcp_oauth_test_reset_store();
mcp_oauth_insert_token([
    'token_hash' => mcp_oauth_hash('oldtok'),
    'token_type' => 'access',
    'userref' => 7,
    'client_id' => 'mcp_x',
    'resource' => mcp_oauth_canonical_resource(),
    'scope' => 'mcp',
    'expires' => '2000-01-01 00:00:00',
    'family' => 'fam',
    'revoked' => 0,
]);
mcp_oauth_purge_expired();
mcp_test_expect_eq(mcp_oauth_lookup_access(mcp_oauth_hash('oldtok')), null, 'purge removes expired access token');

$up_src = (string) file_get_contents(dirname(__DIR__) . '/include/mcp_upload.php');
mcp_test_expect(str_contains($up_src, "mcp_upload_api('get_resource_data'"), 'upload uses API get_resource_data');
mcp_test_expect(!preg_match('/get_resource_data\(\$ref\)/', $up_src), 'upload does not call core get_resource_data');



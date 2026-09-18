<?php

require dirname(__DIR__) . '/include/mcp_auth.php';

mcp_test_reset_auth_state();
$from_headers = ['authorization' => 'Bearer alice:from-headers'];
mcp_test_expect_eq(mcp_authorization_header([]), null, 'no authorization sources');
mcp_test_expect_eq(
    mcp_authorization_header(['HTTP_AUTHORIZATION' => 'Bearer alice:from-server']),
    'Bearer alice:from-server',
    'HTTP_AUTHORIZATION used'
);
mcp_test_expect_eq(
    mcp_authorization_header(['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer alice:from-redirect']),
    'Bearer alice:from-redirect',
    'REDIRECT_HTTP_AUTHORIZATION used'
);
mcp_test_expect_eq(
    mcp_authorization_header([
        'HTTP_AUTHORIZATION' => 'Bearer alice:first',
        'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer alice:second',
    ]),
    'Bearer alice:first',
    'HTTP_AUTHORIZATION beats REDIRECT_HTTP_AUTHORIZATION'
);
mcp_test_expect_eq(
    mcp_authorization_header(['HTTP_AUTHORIZATION' => '']),
    null,
    'empty HTTP_AUTHORIZATION ignored'
);
mcp_test_expect_eq(
    mcp_authorization_header([
        'HTTP_AUTHORIZATION' => '',
        'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer alice:from-redirect',
    ]),
    'Bearer alice:from-redirect',
    'empty HTTP_AUTHORIZATION falls through to REDIRECT'
);
mcp_test_expect_eq(
    mcp_authorization_header([], $from_headers),
    'Bearer alice:from-headers',
    'headers Authorization is case-insensitive'
);
mcp_test_expect_eq(
    mcp_authorization_header(['HTTP_AUTHORIZATION' => ''], $from_headers),
    'Bearer alice:from-headers',
    'empty HTTP_AUTHORIZATION falls through to headers'
);
mcp_test_expect_eq(
    mcp_authorization_header(
        ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer alice:from-redirect'],
        $from_headers
    ),
    'Bearer alice:from-redirect',
    'REDIRECT_HTTP_AUTHORIZATION beats headers'
);
mcp_test_expect_eq(
    mcp_authorization_header(['HTTP_AUTHORIZATION' => 'Bearer alice:first'], $from_headers),
    'Bearer alice:first',
    'HTTP_AUTHORIZATION beats headers'
);

mcp_test_reset_auth_state();
mcp_test_expect_eq(mcp_parse_bearer(null), null, 'missing header');
mcp_test_expect_eq(mcp_parse_bearer('Basic abc'), null, 'non-bearer');
mcp_test_expect_eq(mcp_parse_bearer('Bearer onlyuser'), null, 'no colon');
$parsed = mcp_parse_bearer('Bearer alice:secret:with:colons');
mcp_test_expect_eq($parsed['username'], 'alice', 'split on first colon username');
mcp_test_expect_eq($parsed['key'], 'secret:with:colons', 'split on first colon key');

mcp_test_reset_auth_state();
$key = get_api_key(7);
$ok = mcp_authenticate('alice', $key);
mcp_test_expect_eq($ok['ok'], true, 'displayed key accepted');
mcp_test_expect_eq($GLOBALS['mcp_test_setup_user_called'], true, 'setup_user called');
mcp_test_expect_eq($GLOBALS['mcp_test_api_call_defined_at_setup'], true, 'API_CALL defined before setup_user');
mcp_test_expect_eq($GLOBALS['mcp_test_update_user_access_called'], true, 'update_user_access called');
mcp_test_expect_eq($GLOBALS['mcp_test_sysvar'][0], 'last_api_access', 'last_api_access set');

mcp_test_reset_auth_state();
$username_key = get_api_key('alice');
$no = mcp_authenticate('alice', $username_key);
mcp_test_expect_eq($no['ok'], false, 'username-derived key rejected');
mcp_test_expect_eq($no['http'], 401, 'username-derived 401');

mcp_test_reset_auth_state();
$no2 = mcp_authenticate('nosuch', $key);
mcp_test_expect_eq($no2['ok'], false, 'unknown user 401');

mcp_test_reset_auth_state();
$GLOBALS['mcp_test_setup_user_return'] = false;
$no3 = mcp_authenticate('alice', get_api_key(7));
mcp_test_expect_eq($no3['ok'], false, 'setup_user false 401');

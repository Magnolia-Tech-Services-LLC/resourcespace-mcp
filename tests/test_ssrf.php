<?php

require_once dirname(__DIR__) . '/plugins/magnolia_mcp/include/mcp_dispatch.php';

unset($GLOBALS['api_upload_urls']);

$a = mcp_url_allowed('https://8.8.8.8/file.jpg');
mcp_test_expect_eq($a['ok'], true, 'public https ok when allowlist unset');

$b = mcp_url_allowed('file:///etc/passwd');
mcp_test_expect_eq($b['ok'], false, 'file scheme rejected');

$c = mcp_url_allowed('http://127.0.0.1/x');
mcp_test_expect_eq($c['ok'], false, 'loopback rejected');

$d = mcp_url_allowed('http://10.0.0.5/x');
mcp_test_expect_eq($d['ok'], false, 'private ipv4 rejected');

$e = mcp_url_allowed('http://169.254.169.254/latest/meta-data');
mcp_test_expect_eq($e['ok'], false, 'metadata ip rejected');

$GLOBALS['api_upload_urls'] = [];
$f = mcp_url_allowed('https://8.8.8.8/file.jpg');
mcp_test_expect_eq($f['ok'], false, 'empty allowlist rejects');
mcp_test_expect(str_contains((string) $f['error'], 'api_upload_urls'), 'empty allowlist names config');

$GLOBALS['api_upload_urls'] = ['8.8.8.8'];
$g = mcp_url_allowed('https://8.8.8.8/a.jpg');
mcp_test_expect_eq($g['ok'], true, 'allowlisted host ok');
$h = mcp_url_allowed('https://1.1.1.1/a.jpg');
mcp_test_expect_eq($h['ok'], false, 'non-allowlisted host rejected');

unset($GLOBALS['api_upload_urls']);
mcp_test_expect_eq(mcp_ip_blocked('::ffff:127.0.0.1'), true, 'ipv4-mapped loopback blocked');
mcp_test_expect_eq(mcp_ip_blocked('::ffff:169.254.169.254'), true, 'ipv4-mapped metadata blocked');
mcp_test_expect_eq(mcp_ip_blocked('0:0:0:0:0:0:0:1'), true, 'expanded ipv6 loopback blocked');
mcp_test_expect_eq(mcp_ip_blocked('::1'), true, 'ipv6 loopback blocked');

$mapped_loop = mcp_url_allowed('http://[::ffff:127.0.0.1]/x');
mcp_test_expect_eq($mapped_loop['ok'], false, 'ipv4-mapped loopback url rejected');
$mapped_meta = mcp_url_allowed('http://[::ffff:169.254.169.254]/latest/meta-data');
mcp_test_expect_eq($mapped_meta['ok'], false, 'ipv4-mapped metadata url rejected');
$bracket_loop = mcp_url_allowed('http://[::1]/x');
mcp_test_expect_eq($bracket_loop['ok'], false, 'bracketed ipv6 loopback rejected');
$expanded_loop = mcp_url_allowed('http://[0:0:0:0:0:0:0:1]/x');
mcp_test_expect_eq($expanded_loop['ok'], false, 'expanded ipv6 loopback url rejected');

$localhost = mcp_url_allowed('http://localhost/x');
mcp_test_expect_eq($localhost['ok'], false, 'localhost rejected');
$decimal = mcp_url_allowed('http://2130706433/x');
mcp_test_expect_eq($decimal['ok'], false, 'decimal loopback rejected');
$short = mcp_url_allowed('http://127.1/x');
mcp_test_expect_eq($short['ok'], false, 'short loopback rejected');
$hex = mcp_url_allowed('http://0x7f000001/x');
mcp_test_expect_eq($hex['ok'], false, 'hex loopback rejected');
$compat = mcp_url_allowed('http://[::10.0.0.1]/x');
mcp_test_expect_eq($compat['ok'], false, 'ipv4-compatible private rejected');
$unspec = mcp_url_allowed('http://[::]/x');
mcp_test_expect_eq($unspec['ok'], false, 'ipv6 unspecified rejected');
mcp_test_expect_eq(mcp_ip_blocked('::'), true, 'ipv6 unspecified blocked');
mcp_test_expect_eq(mcp_ip_blocked('::a00:1'), true, 'ipv4-compatible 10.0.0.1 blocked');

mcp_test_expect(function_exists('mcp_ssrf_range_label'), 'ssrf range label exists');
mcp_test_expect(str_contains(mcp_ssrf_range_label(), '10.0.0.0-10.255.255.255'), 'ssrf label includes rfc1918');
mcp_test_expect(str_contains(mcp_ssrf_range_label(), '::1'), 'ssrf label includes ipv6 loopback');

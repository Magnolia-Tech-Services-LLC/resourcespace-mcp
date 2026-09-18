<?php

require_once dirname(__DIR__) . '/include/mcp_jsonrpc.php';

$batch = mcp_jsonrpc_decode('[{"jsonrpc":"2.0","method":"ping","id":1}]');
mcp_test_expect_eq($batch['ok'], false, 'batch rejected');
mcp_test_expect_eq($batch['http'], 400, 'batch HTTP 400');
mcp_test_expect_eq($batch['code'], -32600, 'batch code -32600');

$bad = mcp_jsonrpc_decode('{');
mcp_test_expect_eq($bad['ok'], false, 'parse error');
mcp_test_expect_eq($bad['http'], 400, 'parse HTTP 400');
mcp_test_expect_eq($bad['code'], -32700, 'parse code -32700');

$ok = mcp_jsonrpc_decode('{"jsonrpc":"2.0","method":"ping","id":1}');
mcp_test_expect_eq($ok['ok'], true, 'single request ok');
mcp_test_expect_eq($ok['request']['method'], 'ping', 'method ping');

$note = mcp_jsonrpc_decode('{"jsonrpc":"2.0","method":"notifications/initialized"}');
mcp_test_expect_eq($note['ok'], true, 'notification ok');
mcp_test_expect(!isset($note['request']['id']), 'notification has no id');

mcp_test_expect_eq(mcp_accept_allows_json('application/json, text/event-stream'), true, 'accept both');
mcp_test_expect_eq(mcp_accept_allows_json('text/event-stream'), false, 'sse-only rejected');
mcp_test_expect_eq(mcp_accept_allows_json(null), false, 'missing accept rejected');

mcp_test_expect_eq(mcp_https_ok(['HTTPS' => 'on'], 'https://dam.example', false), true, 'https on');
mcp_test_expect_eq(mcp_https_ok([], 'https://dam.example', false), false, 'plain request refused even if baseurl https');
mcp_test_expect_eq(mcp_https_ok(['HTTP_X_FORWARDED_PROTO' => 'https'], 'https://dam.example', false), false, 'forwarded ignored without toggle');
mcp_test_expect_eq(mcp_https_ok(['HTTP_X_FORWARDED_PROTO' => 'https'], 'https://dam.example', true), true, 'forwarded trusted');
mcp_test_expect_eq(mcp_https_ok(['HTTPS' => 'on'], 'http://dam.example', false), false, 'http baseurl refused');

mcp_test_expect_eq(mcp_origin_ok(null, 'https://dam.example'), true, 'missing origin allowed');
mcp_test_expect_eq(mcp_origin_ok('https://dam.example', 'https://dam.example'), true, 'matching origin');
mcp_test_expect_eq(mcp_origin_ok('https://evil.example', 'https://dam.example'), false, 'mismatch origin');

$init = mcp_protocol_version_ok(null);
mcp_test_expect_eq($init['ok'], true, 'initialize without header ok');
$later = mcp_protocol_version_ok('');
mcp_test_expect_eq($later['ok'], true, 'missing later header defaults');
$badver = mcp_protocol_version_ok('1999-01-01');
mcp_test_expect_eq($badver['ok'], false, 'unsupported version');
mcp_test_expect_eq($badver['http'], 400, 'unsupported HTTP 400');

$err = mcp_jsonrpc_error(null, -32001, 'Unauthorized');
mcp_test_expect_eq($err['error']['code'], -32001, 'unauth code');
mcp_test_expect_eq($err['id'], null, 'unauth id null');

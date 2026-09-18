<?php

function mcp_upload_ini_bytes(string $ini): int
{
    $ini = trim($ini);
    if ($ini === '') {
        return 0;
    }
    $unit = strtolower(substr($ini, -1));
    $mult = 1;
    if ($unit === 'g') {
        $mult = 1024 * 1024 * 1024;
        $ini = substr($ini, 0, -1);
    } elseif ($unit === 'm') {
        $mult = 1024 * 1024;
        $ini = substr($ini, 0, -1);
    } elseif ($unit === 'k') {
        $mult = 1024;
        $ini = substr($ini, 0, -1);
    }
    return (int) ((float) $ini * $mult);
}

function mcp_upload_post_too_large(array $server, array $post, array $files): bool
{
    $type = (string) ($server['CONTENT_TYPE'] ?? '');
    if (strncasecmp($type, 'multipart/form-data', 19) !== 0) {
        return false;
    }
    $length = (int) ($server['CONTENT_LENGTH'] ?? 0);
    $max = mcp_upload_ini_bytes((string) ini_get('post_max_size'));
    if ($max === 0) {
        return false;
    }
    if ($length > $max) {
        return true;
    }
    return $length > 0 && $post === [] && $files === [];
}

function mcp_upload_parse_ref($raw): ?int
{
    if (!is_int_loose($raw) || (int) $raw <= 0) {
        return null;
    }
    return (int) $raw;
}

function mcp_upload_parse_bool($raw): bool
{
    if ($raw === null) {
        return false;
    }
    if (!is_string($raw) && !is_int($raw) && !is_bool($raw)) {
        return false;
    }
    return (bool) filter_var($raw, FILTER_VALIDATE_BOOLEAN);
}

function mcp_upload_forbidden_present(array $post): array
{
    $found = [];
    foreach (['previewonly', 'alternative', 'file_path', 'url', 'autorotate'] as $key) {
        if (array_key_exists($key, $post)) {
            $found[] = $key;
        }
    }
    return $found;
}

function mcp_upload_filename(array $files): string
{
    $name = $files['file']['name'] ?? '';
    if (!is_string($name) || $name === '') {
        return '';
    }
    return basename($name);
}

function mcp_upload_json(int $http, array $body): array
{
    $out = ['http' => $http, 'body' => $body];
    if ($http === 401) {
        $out['www_authenticate'] = true;
    }
    return $out;
}

function mcp_upload_file_problem(array $files): ?array
{
    if (!isset($files['file']) || !is_array($files['file'])) {
        return mcp_upload_json(400, [
            'error' => 'invalid_request',
            'error_description' => 'Missing file',
        ]);
    }
    $err = (int) ($files['file']['error'] ?? 0);
    if ($err === UPLOAD_ERR_OK) {
        return null;
    }
    if ($err === UPLOAD_ERR_INI_SIZE) {
        return mcp_upload_json(413, [
            'error' => 'too_large',
            'error_description' => 'File exceeds upload_max_filesize',
        ]);
    }
    return mcp_upload_json(500, [
        'error' => 'upload_failed',
        'error_description' => 'Upload failed',
    ]);
}

function mcp_upload_user_by_session(string $hash): ?array
{
    if (isset($GLOBALS['mcp_test_session_row'])) {
        $row = $GLOBALS['mcp_test_session_row'];
        if (is_array($row) && (string) ($row['session'] ?? '') === $hash) {
            return $row;
        }
        return null;
    }
    $rows = ps_query(
        "SELECT ref, username, approved, session, UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(last_active) AS idle_seconds FROM user WHERE session = ?",
        array("s", $hash)
    );
    if (!is_array($rows) || !isset($rows[0]) || !is_array($rows[0])) {
        return null;
    }
    return $rows[0];
}

function mcp_upload_session_user(array $cookie, array $post): array
{
    $fail = ['ok' => false, 'http' => 401, 'error' => 'unauthorized', 'userref' => null];
    $hash = $cookie['user'] ?? '';
    if (!is_string($hash) || $hash === '') {
        return $fail;
    }
    $row = mcp_upload_user_by_session($hash);
    if ($row === null) {
        return $fail;
    }
    if ((int) ($row['approved'] ?? 0) !== 1) {
        return $fail;
    }
    global $session_autologout, $session_length;
    $idle = (int) ($row['idle_seconds'] ?? 0);
    $limit = ((int) $session_length) * 60;
    if (!empty($session_autologout) && $idle > $limit) {
        if (!isset($GLOBALS['mcp_test_session_row'])) {
            ps_query("UPDATE user SET session = '', logged_in = 0 WHERE ref = ?", array("i", (int) $row['ref']));
        }
        return $fail;
    }
    $setup = mcp_setup_api_user((int) $row['ref']);
    if (!$setup['ok']) {
        return $fail;
    }
    if (mcp_oauth_is_anonymous_user()) {
        return $fail;
    }
    $id = $GLOBALS['CSRF_token_identifier'] ?? 'CSRFToken';
    if (!isValidCSRFToken((string) ($post[$id] ?? ''), $hash)) {
        return ['ok' => false, 'http' => 403, 'error' => 'forbidden', 'userref' => null];
    }
    return ['ok' => true, 'http' => 200, 'error' => null, 'userref' => (int) $row['ref']];
}

function mcp_upload_authenticate(?string $authorization, array $cookie, array $post): array
{
    if (is_string($authorization) && $authorization !== '') {
        $auth = mcp_authenticate_bearer($authorization);
        if (!$auth['ok']) {
            return ['ok' => false, 'http' => 401, 'error' => 'unauthorized', 'userref' => null];
        }
        $userref = isset($auth['userref']) ? (int) $auth['userref'] : null;
        return ['ok' => true, 'http' => 200, 'error' => null, 'userref' => $userref];
    }
    return mcp_upload_session_user($cookie, $post);
}

function mcp_upload_restore_status($prior): void
{
    $code = $prior === false ? 200 : (int) $prior;
    if (!headers_sent()) {
        http_response_code($code);
    }
}

function mcp_upload_decode_execute($raw)
{
    if (is_array($raw)) {
        return $raw;
    }
    if ($raw === false || $raw === null) {
        return false;
    }
    $decoded = json_decode((string) $raw, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        return $decoded;
    }
    return $raw;
}

function mcp_upload_api(string $function, array $params)
{
    $prior = http_response_code();
    $raw = execute_api_call(mcp_build_query($function, $params), false);
    mcp_upload_restore_status($prior);
    return mcp_upload_decode_execute($raw);
}

function mcp_upload_has_original(int $ref): ?bool
{
    if (array_key_exists('mcp_test_originals', $GLOBALS) && is_array($GLOBALS['mcp_test_originals'])) {
        if (!array_key_exists($ref, $GLOBALS['mcp_test_originals'])) {
            return null;
        }
        $mapped = $GLOBALS['mcp_test_originals'][$ref];
        if (!is_string($mapped)) {
            return null;
        }
        return $mapped !== '';
    }
    $decoded = mcp_upload_api('get_resource_data', ['resource' => $ref]);
    if (!is_array($decoded) || !isset($decoded['ref'])) {
        return null;
    }
    return trim((string) ($decoded['file_extension'] ?? '')) !== '';
}

function mcp_upload_classify_ajax($decoded): array
{
    if (!is_array($decoded)) {
        return ['http' => 500, 'error' => 'upload_failed'];
    }
    $status = (string) ($decoded['status'] ?? '');
    if ($status !== 'fail' && $status !== 'error') {
        return ['http' => 200, 'error' => ''];
    }
    $msg = (string) ($decoded['data']['message'] ?? '');
    $lang = is_array($GLOBALS['lang'] ?? null) ? $GLOBALS['lang'] : [];
    $dup = (string) ($lang['error_upload_duplicate_file'] ?? '');
    if ($dup !== '') {
        if (str_contains($dup, '[resources]')) {
            $prefix = (string) strstr($dup, '[resources]', true);
            if ($prefix !== '' && str_contains($msg, $prefix)) {
                return ['http' => 409, 'error' => 'duplicate'];
            }
        } elseif ($msg === $dup || str_contains($msg, $dup)) {
            return ['http' => 409, 'error' => 'duplicate'];
        }
    }
    $quota = (string) ($lang['disk_size_no_upload_explain'] ?? '');
    if ($quota !== '' && ($msg === $quota || str_contains($msg, $quota))) {
        return ['http' => 403, 'error' => 'forbidden'];
    }
    $perm = (string) ($lang['error-permissiondenied'] ?? '');
    if ($perm !== '' && ($msg === $perm || str_contains($msg, $perm))) {
        return ['http' => 403, 'error' => 'forbidden'];
    }
    return ['http' => 500, 'error' => 'upload_failed'];
}

function mcp_upload_handle(array $server, array $post, array $files, array $cookie, array $plugin_state): array
{
    $baseurl = (string) ($plugin_state['baseurl'] ?? '');
    $trust_proxy = !empty($plugin_state['trust_proxy']);
    if (!mcp_https_ok($server, $baseurl, $trust_proxy)) {
        return mcp_upload_json(403, [
            'error' => 'forbidden',
            'error_description' => 'HTTPS required',
        ]);
    }

    $plugins = $plugin_state['plugins'] ?? [];
    if (
        !is_array($plugins)
        || !in_array('resourcespace_mcp', $plugins, true)
        || empty($plugin_state['enable'])
        || empty($plugin_state['enable_remote_apis'])
    ) {
        return mcp_upload_json(403, [
            'error' => 'forbidden',
            'error_description' => 'Plugin not enabled',
        ]);
    }

    $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? ''));
    $authorization = $server['HTTP_AUTHORIZATION'] ?? null;
    if (!is_string($authorization) || $authorization === '') {
        $authorization = null;
    }

    if ($method === 'GET' || $method === 'HEAD') {
        if ($authorization === null) {
            return mcp_upload_json(401, [
                'error' => 'unauthorized',
                'error_description' => 'Unauthorized',
            ]);
        }
        return mcp_upload_json(405, [
            'error' => 'method_not_allowed',
            'error_description' => 'Method Not Allowed',
        ]);
    }
    if ($method !== 'POST') {
        return mcp_upload_json(405, [
            'error' => 'method_not_allowed',
            'error_description' => 'Method Not Allowed',
        ]);
    }

    $content_type = (string) ($server['CONTENT_TYPE'] ?? '');
    if (strncasecmp($content_type, 'multipart/form-data', 19) !== 0) {
        return mcp_upload_json(415, [
            'error' => 'unsupported_media_type',
            'error_description' => 'Content-Type must be multipart/form-data',
        ]);
    }

    if (mcp_upload_post_too_large($server, $post, $files)) {
        return mcp_upload_json(413, [
            'error' => 'too_large',
            'error_description' => 'Request exceeds post_max_size',
        ]);
    }

    $auth = mcp_upload_authenticate($authorization, $cookie, $post);
    if (!$auth['ok']) {
        return mcp_upload_json((int) $auth['http'], [
            'error' => (string) ($auth['error'] ?? 'unauthorized'),
            'error_description' => (string) ($auth['error'] ?? 'unauthorized'),
        ]);
    }

    $forbidden = mcp_upload_forbidden_present($post);
    if ($forbidden !== []) {
        return mcp_upload_json(400, [
            'error' => 'invalid_request',
            'error_description' => 'Forbidden field: ' . $forbidden[0],
        ]);
    }

    $problem = mcp_upload_file_problem($files);
    if ($problem !== null) {
        return $problem;
    }

    $catalog = (isset($plugin_state['catalog']) && is_array($plugin_state['catalog']))
        ? $plugin_state['catalog']
        : mcp_message_catalog($plugin_state);
    $allowlist = is_array($plugin_state['allowlist'] ?? null)
        ? $plugin_state['allowlist']
        : mcp_current_allowlist();

    $ref = mcp_upload_parse_ref($post['ref'] ?? null);
    $resource_type = $post['resource_type'] ?? null;
    $has_type = $resource_type !== null && $resource_type !== '';
    if ($ref === null && !$has_type) {
        return mcp_upload_json(400, [
            'error' => 'invalid_request',
            'error_description' => 'Missing ref and resource_type',
        ]);
    }

    $need_create = $ref === null;
    if ($need_create && !mcp_action_permitted('create_resource', $catalog, $allowlist)) {
        return mcp_upload_json(403, [
            'error' => 'forbidden',
            'error_description' => 'Action not permitted',
        ]);
    }
    if (!mcp_action_permitted('upload_multipart', $catalog, $allowlist)) {
        return mcp_upload_json(403, [
            'error' => 'forbidden',
            'error_description' => 'Action not permitted',
        ]);
    }

    $metadata = null;
    if ($need_create && array_key_exists('metadata', $post)) {
        $raw_meta = $post['metadata'];
        if (is_array($raw_meta)) {
            $encoded = json_encode($raw_meta);
            if ($encoded === false) {
                return mcp_upload_json(400, [
                    'error' => 'invalid_request',
                    'error_description' => 'Invalid metadata JSON',
                ]);
            }
            $metadata = $encoded;
        } elseif (is_string($raw_meta)) {
            $decoded_meta = json_decode($raw_meta, true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded_meta)) {
                return mcp_upload_json(400, [
                    'error' => 'invalid_request',
                    'error_description' => 'Invalid metadata JSON',
                ]);
            }
            $metadata = $raw_meta;
        } else {
            return mcp_upload_json(400, [
                'error' => 'invalid_request',
                'error_description' => 'Invalid metadata JSON',
            ]);
        }
    }

    $created = false;
    if ($need_create) {
        $create_params = ['resource_type' => $resource_type];
        if ($metadata !== null) {
            $create_params['metadata'] = $metadata;
        }
        $decoded = mcp_upload_api('create_resource', $create_params);
        if ($decoded === false || (is_string($decoded) && strncasecmp($decoded, 'FAILED', 6) === 0)) {
            return mcp_upload_json(403, [
                'error' => 'forbidden',
                'error_description' => 'create_resource failed',
            ]);
        }
        if (!is_int_loose($decoded) || (int) $decoded <= 0) {
            return mcp_upload_json(400, [
                'error' => 'invalid_request',
                'error_description' => 'create_resource did not return a ref',
            ]);
        }
        $ref = (int) $decoded;
        $created = true;
    }

    $no_exif = mcp_upload_parse_bool($post['no_exif'] ?? false);
    $replace = mcp_upload_parse_bool($post['replace'] ?? false);
    $has_original = mcp_upload_has_original($ref);
    if ($has_original === null) {
        return mcp_upload_json(403, [
            'error' => 'forbidden',
            'error_description' => 'Resource is not accessible',
            'ref' => $ref,
        ]);
    }
    if ($has_original && !$replace) {
        return mcp_upload_json(409, [
            'error' => 'replace_required',
            'error_description' => 'Resource already has an original file',
            'ref' => $ref,
        ]);
    }

    $decoded = mcp_upload_api('upload_multipart', [
        'ref' => $ref,
        'no_exif' => $no_exif ? '1' : '0',
        'revert' => '0',
    ]);
    $class = mcp_upload_classify_ajax($decoded);
    $filename = mcp_upload_filename($files);
    if ($class['http'] !== 200) {
        $body = [
            'error' => $class['error'],
            'error_description' => $class['error'],
            'ref' => $ref,
            'filename' => $filename,
            'created' => $created,
            'file_uploaded' => false,
        ];
        return mcp_upload_json($class['http'], $body);
    }

    return mcp_upload_json(200, [
        'ref' => $ref,
        'filename' => $filename,
        'created' => $created,
        'file_uploaded' => true,
    ]);
}

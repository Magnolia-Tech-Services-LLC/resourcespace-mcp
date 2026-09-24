<?php

function mcp_activity_note(string $note): void
{
    if (function_exists('log_activity')) {
        log_activity($note);
    }
}

function mcp_tool_decode_text(string $text)
{
    $decoded = json_decode($text, true);
    return json_last_error() === JSON_ERROR_NONE ? $decoded : $text;
}

function mcp_tool_json($data): array
{
    $json = json_encode($data);
    if ($json === false) {
        return ['isError' => true, 'text' => 'json_encode failed'];
    }
    return ['isError' => false, 'text' => $json];
}

function mcp_refuse_action(string $action, array $catalog, array $allowlist): ?array
{
    if (mcp_action_permitted($action, $catalog, $allowlist)) {
        return null;
    }
    $why = in_array($action, mcp_deny_list(), true) ? 'deny-list' : 'disabled category';
    mcp_activity_note('MCP ' . $why . ' refused action: ' . $action);
    return ['isError' => true, 'text' => 'Action is not permitted'];
}

function mcp_execute_permitted(string $action, array $params, array $catalog, array $allowlist): array
{
    $refused = mcp_refuse_action($action, $catalog, $allowlist);
    if ($refused !== null) {
        return $refused;
    }
    foreach (mcp_url_param_keys($action) as $key) {
        $url = isset($params[$key]) ? (string) $params[$key] : '';
        if ($url === '') {
            continue;
        }
        $allowed = mcp_url_allowed($url);
        if (!$allowed['ok']) {
            return ['isError' => true, 'text' => (string) $allowed['error']];
        }
    }
    $executed = mcp_execute($action, $params);
    return ['isError' => (bool) $executed['isError'], 'text' => (string) $executed['text']];
}

function mcp_collection_actions(): array
{
    return [
        'create' => 'create_collection',
        'add' => 'add_resource_to_collection',
        'remove' => 'remove_resource_from_collection',
        'add_resources' => 'collection_add_resources',
        'remove_resources' => 'collection_remove_resources',
    ];
}

function mcp_hint_read(): array
{
    return ['readOnlyHint' => true, 'destructiveHint' => false];
}

function mcp_hint_write(): array
{
    return ['readOnlyHint' => false, 'destructiveHint' => false];
}

function mcp_hint_destructive(): array
{
    return ['readOnlyHint' => false, 'destructiveHint' => true];
}

function mcp_tool_schema(array $properties, array $required): array
{
    return [
        'type' => 'object',
        'properties' => $properties,
        'required' => $required,
    ];
}

function mcp_tool_list(): array
{
    $tools = [];
    foreach (mcp_tool_defs() as $name => $def) {
        $tools[] = ['name' => $name] + $def;
    }
    return $tools;
}

function mcp_tool_defs(): array
{
    return [
        'rs_search_actions' => [
            'description' => 'Find ResourceSpace API actions by intent',
            'annotations' => mcp_hint_read(),
            'inputSchema' => mcp_tool_schema([
                'intent' => ['type' => 'string'],
                'category' => ['type' => 'string'],
                'limit' => ['type' => 'integer', 'default' => 10],
            ], ['intent']),
        ],
        'rs_execute_action' => [
            'description' => 'Run a catalog action via execute_api_call',
            'annotations' => mcp_hint_destructive(),
            'inputSchema' => mcp_tool_schema([
                'action' => ['type' => 'string'],
                'params' => ['type' => 'object'],
            ], ['action', 'params']),
        ],
        'rs_search' => [
            'description' => 'Search resources',
            'annotations' => mcp_hint_read(),
            'inputSchema' => mcp_tool_schema([
                'query' => ['type' => 'string'],
                'resource_type' => ['type' => 'string'],
                'limit' => ['type' => 'integer', 'default' => 50],
                'offset' => ['type' => 'integer'],
            ], ['query']),
        ],
        'rs_get_resource' => [
            'description' => 'Get resource data and field data',
            'annotations' => mcp_hint_read(),
            'inputSchema' => mcp_tool_schema([
                'ref' => ['type' => 'integer'],
            ], ['ref']),
        ],
        'rs_create_resource' => [
            'description' => 'Create a resource, optional URL and metadata',
            'annotations' => mcp_hint_write(),
            'inputSchema' => mcp_tool_schema([
                'resource_type' => ['type' => 'string'],
                'url' => ['type' => 'string'],
                'initial_metadata' => ['type' => 'object'],
            ], ['resource_type']),
        ],
        'rs_upload_resource' => [
            'description' => 'Attach a file to a resource by URL',
            'annotations' => mcp_hint_write(),
            'inputSchema' => mcp_tool_schema([
                'ref' => ['type' => 'integer'],
                'url' => ['type' => 'string'],
            ], ['ref', 'url']),
        ],
        'rs_update_metadata' => [
            'description' => 'Update one metadata field',
            'annotations' => mcp_hint_write(),
            'inputSchema' => mcp_tool_schema([
                'ref' => ['type' => 'integer'],
                'field' => ['type' => 'string'],
                'value' => ['type' => 'string'],
            ], ['ref', 'field', 'value']),
        ],
        'rs_manage_collection' => [
            'description' => 'Create or change collections',
            'annotations' => mcp_hint_destructive(),
            'inputSchema' => mcp_tool_schema([
                'action' => [
                    'type' => 'string',
                    'enum' => array_keys(mcp_collection_actions()),
                    'description' => 'create|add|remove|add_resources|remove_resources',
                ],
                'name' => ['type' => 'string', 'description' => 'Required when action is create'],
                'collection_ref' => ['type' => 'integer'],
                'resource_refs' => ['type' => 'array', 'items' => ['type' => 'integer']],
            ], ['action']),
        ],
        'rs_check_permissions' => [
            'description' => 'Check current user permissions',
            'annotations' => mcp_hint_read(),
            'inputSchema' => mcp_tool_schema([
                'permission_code' => ['type' => 'string'],
                'resource_ref' => ['type' => 'integer'],
            ], ['permission_code']),
        ],
    ];
}

function mcp_handle_tool(string $name, array $args, array $catalog, array $allowlist): array
{
    switch ($name) {
        case 'rs_search_actions':
            $category = $args['category'] ?? null;
            $category = ($category === null || $category === '') ? null : (string) $category;
            return mcp_tool_json(mcp_search_actions(
                (string) ($args['intent'] ?? ''),
                $category,
                (int) ($args['limit'] ?? 10),
                $catalog,
                $allowlist
            ));

        case 'rs_execute_action':
            $params = $args['params'] ?? [];
            if (!is_array($params)) {
                $params = [];
            }
            return mcp_execute_permitted((string) ($args['action'] ?? ''), $params, $catalog, $allowlist);

        case 'rs_search':
            $params = ['search' => (string) ($args['query'] ?? '')];
            if (array_key_exists('limit', $args)) {
                $params['fetchrows'] = $args['limit'];
            }
            if (array_key_exists('resource_type', $args)) {
                $params['restypes'] = $args['resource_type'];
            }
            if (array_key_exists('offset', $args)) {
                $params['offset'] = $args['offset'];
            }
            return mcp_execute_permitted('do_search', $params, $catalog, $allowlist);

        case 'rs_get_resource':
            $resource = $args['ref'] ?? '';
            $data = mcp_execute_permitted('get_resource_data', ['resource' => $resource], $catalog, $allowlist);
            if ($data['isError']) {
                return $data;
            }
            $fields = mcp_execute_permitted('get_resource_field_data', ['resource' => $resource], $catalog, $allowlist);
            if ($fields['isError']) {
                return $fields;
            }
            return mcp_tool_json([
                'resource' => mcp_tool_decode_text($data['text']),
                'field_data' => mcp_tool_decode_text($fields['text']),
            ]);

        case 'rs_create_resource':
            $params = ['resource_type' => $args['resource_type'] ?? ''];
            if (isset($args['url']) && $args['url'] !== '') {
                $params['url'] = $args['url'];
            }
            if (array_key_exists('initial_metadata', $args)) {
                $params['metadata'] = $args['initial_metadata'];
            }
            return mcp_execute_permitted('create_resource', $params, $catalog, $allowlist);

        case 'rs_upload_resource':
            return mcp_execute_permitted('upload_file_by_url', [
                'ref' => $args['ref'] ?? '',
                'url' => (string) ($args['url'] ?? ''),
            ], $catalog, $allowlist);

        case 'rs_update_metadata':
            return mcp_execute_permitted('update_field', [
                'resource' => $args['ref'] ?? '',
                'field' => $args['field'] ?? '',
                'value' => $args['value'] ?? '',
            ], $catalog, $allowlist);

        case 'rs_manage_collection':
            $action = (string) ($args['action'] ?? '');
            $catalog_id = mcp_collection_actions()[$action] ?? null;
            if ($catalog_id === null) {
                return ['isError' => true, 'text' => 'Unknown collection action'];
            }
            $refs = $args['resource_refs'] ?? [];
            if (!is_array($refs)) {
                $refs = [$refs];
            }
            $collection = $args['collection_ref'] ?? '';
            if ($catalog_id === 'create_collection') {
                if (!isset($args['name']) || $args['name'] === '') {
                    return ['isError' => true, 'text' => 'name is required when action=create'];
                }
                $params = ['name' => $args['name']];
            } elseif ($catalog_id === 'add_resource_to_collection' || $catalog_id === 'remove_resource_from_collection') {
                $params = [
                    'resource' => $refs[0] ?? '',
                    'collection' => $collection,
                ];
            } else {
                $params = [
                    'collection' => $collection,
                    'resources' => implode(',', array_map('strval', $refs)),
                ];
            }
            return mcp_execute_permitted($catalog_id, $params, $catalog, $allowlist);

        case 'rs_check_permissions':
            $perm = mcp_execute_permitted('checkperm', ['perm' => $args['permission_code'] ?? ''], $catalog, $allowlist);
            if ($perm['isError']) {
                return $perm;
            }
            $out = ['checkperm' => mcp_tool_decode_text($perm['text'])];
            if (isset($args['resource_ref']) && $args['resource_ref'] !== '') {
                $resource = $args['resource_ref'];
                $access = mcp_execute_permitted('get_resource_access', ['resource' => $resource], $catalog, $allowlist);
                if ($access['isError']) {
                    return $access;
                }
                $edit = mcp_execute_permitted('get_edit_access', ['resource' => $resource], $catalog, $allowlist);
                if ($edit['isError']) {
                    return $edit;
                }
                $out['get_resource_access'] = mcp_tool_decode_text($access['text']);
                $out['get_edit_access'] = mcp_tool_decode_text($edit['text']);
            }
            return mcp_tool_json($out);

        default:
            return ['isError' => true, 'text' => 'Unknown tool'];
    }
}

function mcp_message_result($id, $result, int $http = 200, array $headers = []): array
{
    return [
        'http' => $http,
        'body' => mcp_jsonrpc_result($id, $result),
        'empty' => false,
        'headers' => $headers,
    ];
}

function mcp_message_error($id, int $http, int $code, string $message, array $headers = []): array
{
    return [
        'http' => $http,
        'body' => mcp_jsonrpc_error($id, $code, $message),
        'empty' => false,
        'headers' => $headers,
    ];
}

function mcp_message_catalog(array $plugin_state): array
{
    if (isset($plugin_state['catalog']) && is_array($plugin_state['catalog'])) {
        return $plugin_state['catalog'];
    }
    $plugins = is_array($plugin_state['plugins'] ?? null) ? $plugin_state['plugins'] : null;
    $catalog = mcp_catalog_load_cached($plugins);
    if ($catalog === null) {
        $catalog = mcp_build_catalog();
        mcp_catalog_save_cached($catalog, $plugins);
    }
    return $catalog;
}

function mcp_handle_message(array $request, array $server, array $plugin_state): array
{
    $id = array_key_exists('id', $request) ? $request['id'] : null;
    $method = (string) ($request['method'] ?? '');
    $baseurl = (string) ($plugin_state['baseurl'] ?? '');
    $trust_proxy = !empty($plugin_state['trust_proxy']);

    if (!mcp_https_ok($server, $baseurl, $trust_proxy)) {
        return mcp_message_error($id, 403, -32600, 'HTTPS required');
    }

    $plugins = $plugin_state['plugins'] ?? [];
    if (
        !is_array($plugins)
        || !in_array('resourcespace_mcp', $plugins, true)
        || empty($plugin_state['enable'])
        || empty($plugin_state['enable_remote_apis'])
    ) {
        return mcp_message_error($id, 403, -32001, 'Plugin not enabled');
    }

    $auth = mcp_authenticate_bearer(mcp_authorization_header($server));
    if (!$auth['ok']) {
        mcp_activity_note('MCP authentication failed');
        return mcp_message_error($id, 401, -32001, 'Unauthorized', ['WWW-Authenticate: ' . mcp_oauth_www_authenticate()]);
    }

    if ($method !== 'initialize') {
        $proto = mcp_protocol_version_ok($server['HTTP_MCP_PROTOCOL_VERSION'] ?? null);
        if (!$proto['ok']) {
            return mcp_message_error($id, (int) $proto['http'], -32600, 'Unsupported protocol version');
        }
    }

    switch ($method) {
        case 'initialize':
            return mcp_message_result($id, [
                'protocolVersion' => MCP_PROTOCOL_VERSION,
                'capabilities' => ['tools' => new stdClass()],
                'serverInfo' => ['name' => 'ResourceSpace', 'version' => '1'],
            ]);
        case 'ping':
            return mcp_message_result($id, new stdClass());
        case 'notifications/initialized':
            if (!array_key_exists('id', $request)) {
                return ['http' => 202, 'body' => null, 'empty' => true];
            }
            return mcp_message_result($id, new stdClass());
        case 'tools/list':
            return mcp_message_result($id, ['tools' => mcp_tool_list()]);
        case 'tools/call':
            $params = is_array($request['params'] ?? null) ? $request['params'] : [];
            $arguments = is_array($params['arguments'] ?? null) ? $params['arguments'] : [];
            $handled = mcp_handle_tool(
                (string) ($params['name'] ?? ''),
                $arguments,
                mcp_message_catalog($plugin_state),
                $plugin_state['allowlist'] ?? []
            );
            return mcp_message_result($id, [
                'content' => [
                    ['type' => 'text', 'text' => $handled['text']],
                ],
                'isError' => (bool) $handled['isError'],
            ]);
        default:
            return mcp_message_error($id, 200, -32601, 'Method not found');
    }
}

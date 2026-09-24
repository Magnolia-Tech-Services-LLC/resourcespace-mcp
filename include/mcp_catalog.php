<?php

function mcp_deny_list(): array
{
    return ['login', 'validate_upload_url', 'do_report', 'upload_file'];
}

function mcp_categories(): array
{
    return ['resources', 'search', 'collections', 'metadata', 'users', 'system', 'plugins', 'uncurated'];
}

function mcp_catalog_id(string $php_function): ?string
{
    if (strpos($php_function, 'api_') !== 0) {
        return null;
    }
    return substr($php_function, 4);
}

function mcp_current_allowlist(): array
{
    $out = [];
    foreach (mcp_categories() as $cat) {
        $out[$cat] = !empty($GLOBALS['resourcespace_mcp_allow_' . $cat]);
    }
    return $out;
}

function mcp_catalog_row(string $id, array $params, array $meta, bool $unannotated): array
{
    return [
        'name' => $id,
        'params' => $params,
        'category' => $meta['category'] ?? 'uncurated',
        'description' => $meta['description'] ?? $id,
        'synonyms' => $meta['synonyms'] ?? [],
        'readOnlyHint' => (bool) ($meta['readOnlyHint'] ?? false),
        'destructiveHint' => (bool) ($meta['destructiveHint'] ?? true),
        'unannotated' => $unannotated,
    ];
}

function mcp_catalog_from_functions(array $php_names, array $annotations): array
{
    $deny = mcp_deny_list();
    $out = [];
    foreach ($php_names as $fn) {
        $id = mcp_catalog_id($fn);
        if ($id === null || in_array($id, $deny, true)) {
            continue;
        }
        $params = [];
        if (function_exists($fn)) {
            foreach ((new ReflectionFunction($fn))->getParameters() as $p) {
                $params[] = $p->getName();
            }
        }
        $curated = is_array($annotations[$id] ?? null);
        $out[$id] = mcp_catalog_row($id, $params, $curated ? $annotations[$id] : [], !$curated);
    }
    return $out;
}

function mcp_build_catalog(): array
{
    require dirname(__DIR__) . '/config/catalog_annotations.php';
    return mcp_catalog_from_functions(get_defined_functions()['user'], $resourcespace_mcp_annotations);
}

function mcp_catalog_cache_path(): string
{
    return rtrim(get_temp_dir(false), '/') . '/resourcespace_mcp_catalog.json';
}

function mcp_catalog_cache_key(?array $plugins_override = null): string
{
    global $productversion, $plugins;
    $ann = dirname(__DIR__) . '/config/catalog_annotations.php';
    $use = $plugins_override ?? (is_array($plugins ?? null) ? $plugins : []);
    $parts = [
        phpversion(),
        (string) ($productversion ?? ''),
        implode(',', $use),
        is_file($ann) ? (string) filemtime($ann) : '0',
        (string) filemtime(__FILE__),
    ];
    include_once __DIR__ . '/mcp_rs_path.php';
    $core = mcp_rs_include_dir(__DIR__) . '/api_bindings.php';
    $parts[] = is_file($core) ? (string) filemtime($core) : '0';
    $plugin_root = dirname(__DIR__, 2);
    foreach ($use as $p) {
        $f = $plugin_root . '/' . $p . '/api/api_bindings.php';
        if (is_file($f)) {
            $parts[] = $p . ':' . filemtime($f);
        }
    }
    return implode('|', $parts);
}

function mcp_catalog_load_cached(?array $plugins_override = null): ?array
{
    $path = mcp_catalog_cache_path();
    if (!is_file($path)) {
        return null;
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return null;
    }
    $decoded = json_decode($raw, true);
    if (
        !is_array($decoded)
        || ($decoded['key'] ?? null) !== mcp_catalog_cache_key($plugins_override)
        || !is_array($decoded['catalog'] ?? null)
    ) {
        return null;
    }
    return $decoded['catalog'];
}

function mcp_catalog_save_cached(array $catalog, ?array $plugins_override = null): void
{
    $payload = json_encode(['key' => mcp_catalog_cache_key($plugins_override), 'catalog' => $catalog]);
    if ($payload === false) {
        return;
    }
    $path = mcp_catalog_cache_path();
    foreach (glob($path . '.*.tmp') ?: [] as $stale) {
        unlink($stale);
    }
    $tmp = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
    if (file_put_contents($tmp, $payload) === false) {
        return;
    }
    if (!rename($tmp, $path) && is_file($tmp)) {
        unlink($tmp);
    }
}

function mcp_action_permitted(string $action, array $catalog, array $allowlist): bool
{
    if (in_array($action, mcp_deny_list(), true)) {
        return false;
    }
    if (!isset($catalog[$action])) {
        return false;
    }
    $cat = $catalog[$action]['category'];
    return !empty($allowlist[$cat]);
}

function mcp_search_actions(string $intent, ?string $category, int $limit, array $catalog, array $allowlist): array
{
    $tokens = preg_split('/\W+/', strtolower($intent), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $scored = [];
    foreach ($catalog as $id => $row) {
        if (!mcp_action_permitted($id, $catalog, $allowlist)) {
            continue;
        }
        if ($category !== null && $category !== '' && $row['category'] !== $category) {
            continue;
        }
        if (!empty($row['unannotated']) && count($tokens) < 2) {
            continue;
        }
        $hay = strtolower($id . ' ' . $row['description'] . ' ' . $row['category'] . ' ' . implode(' ', $row['synonyms']));
        $score = 0;
        foreach ($tokens as $t) {
            if (str_contains($hay, $t)) {
                $score++;
            }
        }
        if ($score > 0) {
            $row['score'] = $score;
            $scored[] = $row;
        }
    }
    usort($scored, static function ($a, $b) {
        return $b['score'] <=> $a['score'];
    });
    $scored = array_slice($scored, 0, max(1, $limit));
    if ($scored === []) {
        return ['categories' => mcp_categories(), 'notice' => 'No actions matched; pick a category'];
    }
    return $scored;
}

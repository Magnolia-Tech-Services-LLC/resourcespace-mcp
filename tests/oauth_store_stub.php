<?php

function mcp_oauth_test_reset_store(): void
{
    $GLOBALS['mcp_oauth_test_db'] = [
        'resourcespace_mcp_oauth_client' => [],
        'resourcespace_mcp_oauth_code' => [],
        'resourcespace_mcp_oauth_token' => [],
        'resourcespace_mcp_oauth_dcr' => [],
    ];
    $GLOBALS['mcp_oauth_test_next_ref'] = 1;
    $GLOBALS['mcp_test_affected'] = 0;
    $dir = get_temp_dir(false, 'resourcespace_mcp_cimd');
    if (is_dir($dir)) {
        foreach (scandir($dir) as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . '/' . $name;
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}

function mcp_oauth_test_values(array $params): array
{
    $out = [];
    for ($i = 0; $i < count($params); $i += 2) {
        $out[] = $params[$i + 1] ?? null;
    }
    return $out;
}

function mcp_oauth_test_now(): string
{
    return date('Y-m-d H:i:s', $GLOBALS['mcp_test_time'] ?? time());
}

if (!function_exists('ps_query')) {
    function ps_query($sql, $params = [])
    {
        $db =& $GLOBALS['mcp_oauth_test_db'];
        $vals = mcp_oauth_test_values(is_array($params) ? $params : []);
        $sql = trim((string) $sql);
        $GLOBALS['mcp_test_affected'] = 0;

        if (stripos($sql, 'INSERT INTO resourcespace_mcp_oauth_client') === 0) {
            $db['resourcespace_mcp_oauth_client'][] = [
                'ref' => $GLOBALS['mcp_oauth_test_next_ref']++,
                'client_id' => (string) $vals[0],
                'client_name' => (string) $vals[1],
                'redirect_uris' => (string) $vals[2],
                'created' => (string) $vals[3],
            ];
            $GLOBALS['mcp_test_affected'] = 1;
            return [];
        }
        if (stripos($sql, 'SELECT client_id, client_name, redirect_uris FROM resourcespace_mcp_oauth_client') === 0) {
            foreach ($db['resourcespace_mcp_oauth_client'] as $row) {
                if ($row['client_id'] === (string) $vals[0]) {
                    return [$row];
                }
            }
            return [];
        }
        if (stripos($sql, 'INSERT INTO resourcespace_mcp_oauth_code') === 0) {
            $db['resourcespace_mcp_oauth_code'][] = [
                'ref' => $GLOBALS['mcp_oauth_test_next_ref']++,
                'code_hash' => (string) $vals[0],
                'userref' => (int) $vals[1],
                'client_id' => (string) $vals[2],
                'redirect_uri' => (string) $vals[3],
                'code_challenge' => (string) $vals[4],
                'resource' => (string) $vals[5],
                'scope' => (string) $vals[6],
                'expires' => (string) $vals[7],
                'used' => 0,
            ];
            $GLOBALS['mcp_test_affected'] = 1;
            return [];
        }
        if (stripos($sql, 'SELECT ref, code_hash, userref, client_id, redirect_uri, code_challenge, resource, scope, expires, used FROM resourcespace_mcp_oauth_code') === 0) {
            foreach ($db['resourcespace_mcp_oauth_code'] as $row) {
                if ($row['code_hash'] === (string) $vals[0]) {
                    return [$row];
                }
            }
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_code SET expires') === 0) {
            $by_user = stripos($sql, 'userref') !== false;
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_code'] as &$row) {
                if ((int) $row['used'] !== 0) {
                    continue;
                }
                if ($by_user && (int) $row['userref'] !== (int) $vals[1]) {
                    continue;
                }
                $row['expires'] = (string) $vals[0];
                $n++;
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_code SET used = 1') === 0) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_code'] as &$row) {
                if (
                    $row['code_hash'] === (string) $vals[0]
                    && (int) $row['used'] === 0
                    && $row['expires'] > (string) $vals[1]
                ) {
                    $row['used'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'INSERT INTO resourcespace_mcp_oauth_token') === 0) {
            $db['resourcespace_mcp_oauth_token'][] = [
                'ref' => $GLOBALS['mcp_oauth_test_next_ref']++,
                'token_hash' => (string) $vals[0],
                'token_type' => (string) $vals[1],
                'userref' => (int) $vals[2],
                'client_id' => (string) $vals[3],
                'resource' => (string) $vals[4],
                'scope' => (string) $vals[5],
                'expires' => (string) $vals[6],
                'family' => (string) $vals[7],
                'revoked' => 0,
            ];
            $GLOBALS['mcp_test_affected'] = 1;
            return [];
        }
        if (stripos($sql, 'SELECT ref, token_hash, token_type, userref, client_id, resource, scope, expires, family, revoked FROM resourcespace_mcp_oauth_token') === 0) {
            foreach ($db['resourcespace_mcp_oauth_token'] as $row) {
                if ($row['token_hash'] === (string) $vals[0] && $row['token_type'] === (string) $vals[1]) {
                    return [$row];
                }
            }
            return [];
        }
        if (stripos($sql, "SELECT userref, client_id, resource, scope, expires, revoked FROM resourcespace_mcp_oauth_token") === 0) {
            foreach ($db['resourcespace_mcp_oauth_token'] as $row) {
                if (
                    $row['token_hash'] === (string) $vals[0]
                    && $row['token_type'] === 'access'
                    && (int) $row['revoked'] === 0
                    && $row['expires'] > (string) $vals[1]
                ) {
                    return [$row];
                }
            }
            return [];
        }
        if (stripos($sql, "UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE token_hash = ? AND token_type = 'refresh' AND revoked = 0") === 0
            || (stripos($sql, 'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE token_hash') === 0 && stripos($sql, 'refresh') !== false)
        ) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_token'] as &$row) {
                if ($row['token_hash'] === (string) $vals[0] && $row['token_type'] === 'refresh' && (int) $row['revoked'] === 0) {
                    $row['revoked'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE userref = ? AND client_id = ?') === 0) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_token'] as &$row) {
                if (
                    (int) $row['userref'] === (int) $vals[0]
                    && $row['client_id'] === (string) $vals[1]
                    && (int) $row['revoked'] === 0
                ) {
                    $row['revoked'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE userref = ? AND revoked = 0') === 0) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_token'] as &$row) {
                if ((int) $row['userref'] === (int) $vals[0] && (int) $row['revoked'] === 0) {
                    $row['revoked'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'DELETE FROM resourcespace_mcp_oauth_code') === 0) {
            $keep = [];
            foreach ($db['resourcespace_mcp_oauth_code'] as $row) {
                $purge = isset($vals[0]) && $row['expires'] < (string) $vals[0] && (int) $row['used'] === 0;
                if (!$purge) {
                    $keep[] = $row;
                }
            }
            $db['resourcespace_mcp_oauth_code'] = $keep;
            return [];
        }
        if (stripos($sql, 'DELETE FROM resourcespace_mcp_oauth_token') === 0) {
            $keep = [];
            foreach ($db['resourcespace_mcp_oauth_token'] as $row) {
                $purge = isset($vals[0]) && $row['expires'] < (string) $vals[0] && (int) $row['revoked'] === 0;
                if (!$purge) {
                    $keep[] = $row;
                }
            }
            $db['resourcespace_mcp_oauth_token'] = $keep;
            return [];
        }
        if (stripos($sql, 'DELETE FROM resourcespace_mcp_oauth_dcr') === 0) {
            $keep = [];
            foreach ($db['resourcespace_mcp_oauth_dcr'] as $row) {
                if ($row['created'] >= (string) $vals[0]) {
                    $keep[] = $row;
                }
            }
            $db['resourcespace_mcp_oauth_dcr'] = $keep;
            return [];
        }
        if (stripos($sql, 'DROP TABLE IF EXISTS') === 0) {
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE family = ?') === 0) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_token'] as &$row) {
                if ($row['family'] === (string) $vals[0] && (int) $row['revoked'] === 0) {
                    $row['revoked'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE revoked = 0') === 0) {
            $n = 0;
            foreach ($db['resourcespace_mcp_oauth_token'] as &$row) {
                if ((int) $row['revoked'] === 0) {
                    $row['revoked'] = 1;
                    $n++;
                }
            }
            unset($row);
            $GLOBALS['mcp_test_affected'] = $n;
            return [];
        }
        if (stripos($sql, 'INSERT INTO resourcespace_mcp_oauth_dcr') === 0) {
            $db['resourcespace_mcp_oauth_dcr'][] = [
                'ref' => $GLOBALS['mcp_oauth_test_next_ref']++,
                'ip' => (string) $vals[0],
                'created' => (string) $vals[1],
            ];
            $GLOBALS['mcp_test_affected'] = 1;
            return [];
        }
        throw new RuntimeException('unhandled ps_query: ' . $sql);
    }
}

if (!function_exists('ps_value')) {
    function ps_value($sql, $params, $default)
    {
        $vals = mcp_oauth_test_values(is_array($params) ? $params : []);
        $sql = trim((string) $sql);
        if (stripos($sql, 'SELECT COUNT(*) AS value FROM resourcespace_mcp_oauth_dcr') === 0) {
            $n = 0;
            foreach ($GLOBALS['mcp_oauth_test_db']['resourcespace_mcp_oauth_dcr'] as $row) {
                if ($row['ip'] === (string) $vals[0] && $row['created'] > (string) $vals[1]) {
                    $n++;
                }
            }
            return $n;
        }
        return $default;
    }
}

if (!function_exists('sql_affected_rows')) {
    function sql_affected_rows()
    {
        return (int) ($GLOBALS['mcp_test_affected'] ?? 0);
    }
}

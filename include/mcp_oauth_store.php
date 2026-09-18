<?php

function mcp_oauth_b64url(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function mcp_oauth_random(): string
{
    return mcp_oauth_b64url(random_bytes(32));
}

function mcp_oauth_hash(string $value): string
{
    return hash('sha256', $value);
}

function mcp_oauth_pkce_s256(string $verifier): string
{
    return mcp_oauth_b64url(hash('sha256', $verifier, true));
}

function mcp_oauth_issuer(): string
{
    global $baseurl;
    return rtrim((string) $baseurl, '/');
}

function mcp_oauth_canonical_resource(): string
{
    return mcp_oauth_issuer() . '/mcp';
}

function mcp_oauth_plugin_resource(): string
{
    return mcp_oauth_issuer() . '/plugins/resourcespace_mcp/mcp.php';
}

function mcp_oauth_prm_url(): string
{
    return mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/oauth_protected_resource.php';
}

function mcp_oauth_effective_resource(?string $resource): ?string
{
    $canonical = mcp_oauth_canonical_resource();
    if ($resource === null || $resource === '') {
        return $canonical;
    }
    $issuer = mcp_oauth_issuer();
    $normalized = rtrim($resource, '/');
    $aliases = [
        $canonical,
        mcp_oauth_plugin_resource(),
        $issuer . '/plugins/resourcespace_mcp/pages/mcp.php',
    ];
    foreach ($aliases as $alias) {
        if (hash_equals($alias, $resource) || hash_equals($alias, $normalized)) {
            return $canonical;
        }
    }
    return null;
}

function mcp_oauth_normalize_scope(?string $scope): string
{
    return 'mcp';
}

function mcp_oauth_www_authenticate(): string
{
    return 'Bearer error="invalid_token", resource_metadata="' . mcp_oauth_prm_url() . '", scope="mcp"';
}

function mcp_oauth_insert_client(string $client_id, string $client_name, string $redirect_uris_json): void
{
    ps_query(
        'INSERT INTO resourcespace_mcp_oauth_client (client_id, client_name, redirect_uris, created) VALUES (?, ?, ?, ?)',
        [
            's', $client_id,
            's', $client_name,
            's', $redirect_uris_json,
            's', date('Y-m-d H:i:s'),
        ]
    );
}

function mcp_oauth_get_client(string $client_id): ?array
{
    $rows = ps_query(
        'SELECT client_id, client_name, redirect_uris FROM resourcespace_mcp_oauth_client WHERE client_id = ?',
        ['s', $client_id]
    );
    return $rows[0] ?? null;
}

function mcp_oauth_insert_code(array $row): void
{
    ps_query(
        'INSERT INTO resourcespace_mcp_oauth_code (code_hash, userref, client_id, redirect_uri, code_challenge, resource, scope, expires, used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
        [
            's', $row['code_hash'],
            'i', (int) $row['userref'],
            's', $row['client_id'],
            's', $row['redirect_uri'],
            's', $row['code_challenge'],
            's', $row['resource'],
            's', $row['scope'],
            's', $row['expires'],
        ]
    );
}

function mcp_oauth_get_code(string $code_hash): ?array
{
    $rows = ps_query(
        'SELECT ref, code_hash, userref, client_id, redirect_uri, code_challenge, resource, scope, expires, used FROM resourcespace_mcp_oauth_code WHERE code_hash = ?',
        ['s', $code_hash]
    );
    return $rows[0] ?? null;
}

function mcp_oauth_consume_code(string $code_hash): bool
{
    ps_query(
        'UPDATE resourcespace_mcp_oauth_code SET used = 1 WHERE code_hash = ? AND used = 0 AND expires > ?',
        ['s', $code_hash, 's', date('Y-m-d H:i:s')]
    );
    return sql_affected_rows() === 1;
}

function mcp_oauth_insert_token(array $row): void
{
    ps_query(
        'INSERT INTO resourcespace_mcp_oauth_token (token_hash, token_type, userref, client_id, resource, scope, expires, family, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
        [
            's', $row['token_hash'],
            's', $row['token_type'],
            'i', (int) $row['userref'],
            's', $row['client_id'],
            's', $row['resource'],
            's', $row['scope'],
            's', $row['expires'],
            's', $row['family'],
        ]
    );
}

function mcp_oauth_get_token(string $token_hash, string $token_type): ?array
{
    $rows = ps_query(
        'SELECT ref, token_hash, token_type, userref, client_id, resource, scope, expires, family, revoked FROM resourcespace_mcp_oauth_token WHERE token_hash = ? AND token_type = ?',
        ['s', $token_hash, 's', $token_type]
    );
    return $rows[0] ?? null;
}

function mcp_oauth_lookup_access(string $token_hash): ?array
{
    $rows = ps_query(
        "SELECT userref, client_id, resource, scope, expires, revoked FROM resourcespace_mcp_oauth_token WHERE token_hash = ? AND token_type = 'access' AND revoked = 0 AND expires > ?",
        ['s', $token_hash, 's', date('Y-m-d H:i:s')]
    );
    return $rows[0] ?? null;
}

function mcp_oauth_revoke_refresh(string $token_hash): bool
{
    ps_query(
        "UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE token_hash = ? AND token_type = 'refresh' AND revoked = 0",
        ['s', $token_hash]
    );
    return sql_affected_rows() === 1;
}

function mcp_oauth_revoke_family(string $family): void
{
    ps_query(
        'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE family = ? AND revoked = 0',
        ['s', $family]
    );
}

function mcp_oauth_revoke_user_client(int $userref, string $client_id): void
{
    ps_query(
        'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE userref = ? AND client_id = ? AND revoked = 0',
        ['i', $userref, 's', $client_id]
    );
}

function mcp_oauth_revoke_all(): void
{
    ps_query('UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE revoked = 0');
    ps_query('UPDATE resourcespace_mcp_oauth_code SET expires = ? WHERE used = 0', ['s', '1970-01-01 00:00:00']);
}

function mcp_oauth_revoke_user(int $userref): void
{
    ps_query(
        'UPDATE resourcespace_mcp_oauth_token SET revoked = 1 WHERE userref = ? AND revoked = 0',
        ['i', $userref]
    );
    ps_query(
        'UPDATE resourcespace_mcp_oauth_code SET expires = ? WHERE userref = ? AND used = 0',
        ['s', '1970-01-01 00:00:00', 'i', $userref]
    );
}

function mcp_oauth_purge_expired(): void
{
    $now = date('Y-m-d H:i:s');
    // Keep used codes and revoked tokens so replay still triggers reuse revocation.
    ps_query('DELETE FROM resourcespace_mcp_oauth_code WHERE expires < ? AND used = 0', ['s', $now]);
    ps_query(
        'DELETE FROM resourcespace_mcp_oauth_token WHERE expires < ? AND revoked = 0',
        ['s', $now]
    );
    ps_query(
        'DELETE FROM resourcespace_mcp_oauth_dcr WHERE created < ?',
        ['s', date('Y-m-d H:i:s', time() - 86400)]
    );
}

function mcp_oauth_drop_tables(): void
{
    foreach (
        [
            'resourcespace_mcp_oauth_token',
            'resourcespace_mcp_oauth_code',
            'resourcespace_mcp_oauth_client',
            'resourcespace_mcp_oauth_dcr',
        ] as $table
    ) {
        ps_query('DROP TABLE IF EXISTS `' . $table . '`');
    }
}

function mcp_oauth_dcr_count(string $ip): int
{
    return (int) ps_value(
        'SELECT COUNT(*) AS value FROM resourcespace_mcp_oauth_dcr WHERE ip = ? AND created > ?',
        ['s', $ip, 's', date('Y-m-d H:i:s', time() - 3600)],
        0
    );
}

function mcp_oauth_dcr_hit(string $ip): void
{
    ps_query(
        'INSERT INTO resourcespace_mcp_oauth_dcr (ip, created) VALUES (?, ?)',
        ['s', $ip, 's', date('Y-m-d H:i:s')]
    );
}

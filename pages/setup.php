<?php
require_once __DIR__ . '/../include/mcp_rs_path.php';
$rs_include = mcp_rs_include_dir(__DIR__);
include $rs_include . '/boot.php';
include $rs_include . '/authenticate.php';
if (!checkperm('a')) {
    exit('Permission denied.');
}
$plugin_name = 'resourcespace_mcp';
if (!in_array($plugin_name, $plugins)) {
    plugin_activate_for_setup($plugin_name);
}

include_once dirname(__DIR__) . '/include/mcp_catalog.php';
include_once dirname(__DIR__) . '/include/mcp_oauth.php';

/**
 * Closed disclosure. Selects inside still post with Save.
 * Action results must pass $open so the outcome is visible.
 */
function resourcespace_mcp_setup_details(string $summary, bool $open = false): string
{
    $open_attr = $open ? ' open' : '';
    return '<details class="resourcespace-mcp-details"' . $open_attr . '>'
        . '<summary><h2>' . escape($summary) . '</h2></summary>';
}

$page_def = [];
$page_def[] = config_add_html(
    '<style>'
    . '.resourcespace-mcp-details{clear:both;margin:4px 0 18px;display:flow-root;}'
    . '.resourcespace-mcp-details>summary{cursor:pointer;}'
    . '.resourcespace-mcp-details>summary h2{display:inline;font-size:1.1em;margin:0;}'
    . '</style>'
);
$help_url = $baseurl . '/plugins/resourcespace_mcp/pages/help.php';
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_help_url_label']) . '</label><div class="Fixed">'
    . '<input class="stdwidth" type="text" readonly="readonly" value="' . escape(mcp_oauth_canonical_resource()) . '" onclick="this.select();" onkeydown="if(event.key===\'Enter\'){event.preventDefault();}" />'
    . '<p><a href="' . escape($help_url) . '" onclick="return CentralSpaceLoad(this,true);">'
    . escape($lang['resourcespace_mcp_help_title']) . '</a></p>'
    . '</div><div class="clearerleft"></div></div>'
);

$remote = empty($enable_remote_apis)
    ? $lang['resourcespace_mcp_remote_apis_off']
    : $lang['resourcespace_mcp_remote_apis_on'];
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_remote_apis']) . '</label><div class="Fixed">'
    . escape($remote)
    . '</div><div class="clearerleft"></div></div>'
);
$page_def[] = config_add_boolean_select('resourcespace_mcp_enable', $lang['resourcespace_mcp_enable']);

$page_def[] = config_add_html(resourcespace_mcp_setup_details($lang['resourcespace_mcp_allowlist']));
foreach (mcp_categories() as $cat) {
    $page_def[] = config_add_boolean_select('resourcespace_mcp_allow_' . $cat, $lang['resourcespace_mcp_allow_' . $cat]);
}
$page_def[] = config_add_html('</details>');

$https_on = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off';
include_once dirname(__DIR__) . '/include/mcp_jsonrpc.php';
$trust_for_warning = $resourcespace_mcp_trust_proxy;
if ((getval('save', '') !== '' || getval('submit', '') !== '') && enforcePostRequest(false)) {
    $trust_for_warning = getval('resourcespace_mcp_trust_proxy', $resourcespace_mcp_trust_proxy);
}
$proxy_warning = !$https_on && mcp_forwarded_https($_SERVER) && empty($trust_for_warning);
$page_def[] = config_add_html(resourcespace_mcp_setup_details($lang['resourcespace_mcp_server_setup'], $proxy_warning));
if ($proxy_warning) {
    $page_def[] = config_add_html(
        '<div class="Question"><div class="Fixed">' . escape($lang['resourcespace_mcp_trust_proxy_needed'])
        . '</div><div class="clearerleft"></div></div>'
    );
}
$page_def[] = config_add_boolean_select('resourcespace_mcp_trust_proxy', $lang['resourcespace_mcp_trust_proxy']);

$issuer_path = rtrim((string) (parse_url((string) $baseurl, PHP_URL_PATH) ?? ''), '/');
$mcp_pub = $issuer_path . '/mcp';
$mcp_page = $issuer_path . '/plugins/resourcespace_mcp/mcp.php';
$as_page = $issuer_path . '/plugins/resourcespace_mcp/pages/oauth_authorization_server.php';
$prm_page = $issuer_path . '/plugins/resourcespace_mcp/pages/oauth_protected_resource.php';
$apache = 'CGIPassAuth On' . "\n"
    . 'RewriteEngine On' . "\n"
    . 'RewriteCond %{REQUEST_URI} ^' . $mcp_pub . '$' . "\n"
    . 'RewriteRule ^.*$ ' . $mcp_page . ' [L]' . "\n"
    . 'RewriteCond %{REQUEST_URI} ^/\.well-known/oauth-protected-resource' . "\n"
    . 'RewriteRule ^.*$ ' . $prm_page . ' [L]' . "\n"
    . 'RewriteCond %{REQUEST_URI} ^/\.well-known/oauth-authorization-server$' . "\n"
    . 'RewriteRule ^.*$ ' . $as_page . ' [L]';
$nginx = 'location = ' . $mcp_pub . ' {' . "\n"
    . '    rewrite ^ ' . $mcp_page . ' last;' . "\n"
    . '}' . "\n"
    . 'location = /.well-known/oauth-authorization-server {' . "\n"
    . '    rewrite ^ ' . $as_page . ' last;' . "\n"
    . '}' . "\n"
    . 'location ^~ /.well-known/oauth-protected-resource {' . "\n"
    . '    rewrite ^ ' . $prm_page . ' last;' . "\n"
    . '}';
$page_def[] = config_add_html(
    '<div class="Question"><div class="Fixed">' . escape($lang['resourcespace_mcp_oauth_discovery_help'])
    . '</div><div class="clearerleft"></div></div>'
);
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_apache']) . '</label>'
    . '<div class="Fixed"><pre>' . escape($apache) . '</pre></div>'
    . '<div class="clearerleft"></div></div>'
);
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_nginx']) . '</label>'
    . '<div class="Fixed"><pre>' . escape($nginx) . '</pre></div>'
    . '<div class="clearerleft"></div></div>'
);
$page_def[] = config_add_html('</details>');

$tokens_open = false;
$revoked_note = false;
if (getval('revoke_oauth', '') !== '' && enforcePostRequest(false)) {
    mcp_oauth_revoke_all();
    if (function_exists('log_activity')) {
        log_activity('MCP OAuth tokens revoked');
    }
    $tokens_open = true;
    $revoked_note = true;
}
$dropped_note = false;
if (getval('drop_oauth', '') !== '' && enforcePostRequest(false)) {
    mcp_oauth_drop_tables();
    if (function_exists('log_activity')) {
        log_activity('MCP OAuth tables dropped');
    }
    $tokens_open = true;
    $dropped_note = true;
}
$page_def[] = config_add_html(resourcespace_mcp_setup_details($lang['resourcespace_mcp_oauth_tokens'], $tokens_open));
$page_def[] = config_add_html(
    '<div class="Question"><div class="Fixed">' . escape($lang['resourcespace_mcp_oauth_totp'])
    . '</div><div class="clearerleft"></div></div>'
);
if ($revoked_note) {
    $page_def[] = config_add_html(
        '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_revoke']) . '</label><div class="Fixed">'
        . escape($lang['resourcespace_mcp_oauth_revoked'])
        . '</div><div class="clearerleft"></div></div>'
    );
}
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_revoke']) . '</label>'
    . '<input type="submit" name="revoke_oauth" value="' . escape($lang['resourcespace_mcp_oauth_revoke']) . '"'
    . ' onclick="return confirm(' . json_encode($lang['resourcespace_mcp_oauth_revoke_confirm'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ');" />'
    . '<div class="clearerleft"></div></div>'
);
if ($dropped_note) {
    $page_def[] = config_add_html(
        '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_drop']) . '</label><div class="Fixed">'
        . escape($lang['resourcespace_mcp_oauth_dropped'])
        . '</div><div class="clearerleft"></div></div>'
    );
}
$page_def[] = config_add_html(
    '<div class="Question"><label>' . escape($lang['resourcespace_mcp_oauth_drop']) . '</label>'
    . '<input type="submit" name="drop_oauth" value="' . escape($lang['resourcespace_mcp_oauth_drop']) . '"'
    . ' onclick="return confirm(' . json_encode($lang['resourcespace_mcp_oauth_drop_confirm'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ');" />'
    . '<div class="clearerleft"></div></div>'
);
$page_def[] = config_add_html('</details>');

config_gen_setup_post($page_def, $plugin_name);
include $rs_include . '/header.php';
config_gen_setup_html($page_def, $plugin_name, null, $lang['resourcespace_mcp_title']);
include $rs_include . '/footer.php';

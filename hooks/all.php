<?php

function HookResourcespace_mcpAllExtra_checks(): array
{
    global $enable_remote_apis, $resourcespace_mcp_enable, $resourcespace_mcp_trust_proxy, $baseurl, $CSRF_exempt_pages;
    $fail = [];
    if (empty($enable_remote_apis)) {
        $fail[] = 'enable_remote_apis is off';
    }
    if (empty($resourcespace_mcp_enable)) {
        $fail[] = 'MCP plugin toggle is off';
    }
    if (parse_url((string) $baseurl, PHP_URL_SCHEME) !== 'https') {
        $fail[] = 'MCP HTTPS check would refuse this host configuration';
    }
    $https_on = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off';
    $forwarded = strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    if (!$https_on && $forwarded === 'https' && empty($resourcespace_mcp_trust_proxy)) {
        $fail[] = 'request is HTTPS via proxy but trust-proxy is off';
    }
    $base_path = (string) (parse_url((string) $baseurl, PHP_URL_PATH) ?? '');
    if ($base_path !== '' && $base_path !== '/') {
        $fail[] = 'MCP origin well-known assumes $baseurl has no path; ChatGPT/Grok discovery will fail';
    }
    $exempt = is_array($CSRF_exempt_pages ?? null) ? $CSRF_exempt_pages : [];
    if (!in_array('login', $exempt, true)) {
        $fail[] = 'CSRF exempt list dropped login';
    }
    if (!in_array('mcp_upload', $exempt, true)) {
        $fail[] = 'mcp_upload is not CSRF-exempt';
    }
    $status = $fail === [] ? 'OK' : 'FAIL';
    $info = $fail === [] ? 'MCP Server looks ready' : implode('; ', $fail);
    return ['resourcespace_mcp' => ['status' => $status, 'info' => $info]];
}

function HookResourcespace_mcpAllBeforetermsredirect()
{
    return ['oauth_authorize'];
}

function HookResourcespace_mcpAllPreheaderoutput()
{
    global $pagename;
    if ($pagename !== 'home') {
        return;
    }
    include_once dirname(__DIR__) . '/include/mcp_oauth.php';
    $uri = mcp_oauth_consume_return();
    if ($uri !== null) {
        redirect($uri);
    }
}

function resourcespace_mcp_render_help_nav(): bool
{
    global $lang, $baseurl;
    $help_url = $baseurl . '/plugins/resourcespace_mcp/pages/help.php';
    ?>
    <li title="<?php echo escape($lang['resourcespace_mcp_help_nav']); ?>">
        <a href="<?php echo escape($help_url); ?>" onclick="return CentralSpaceLoad(this,true);">
            <i aria-hidden="true" class="fa fa-fw fa-plug"></i>
            <br /><?php echo escape($lang['resourcespace_mcp_help_nav']); ?>
        </a>
    </li>
    <?php
    return false;
}

function HookResourcespace_mcpAllUser_home_additional_links()
{
    return resourcespace_mcp_render_help_nav();
}

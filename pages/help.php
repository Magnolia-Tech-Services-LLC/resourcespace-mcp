<?php
require_once __DIR__ . '/../include/mcp_rs_path.php';
$rs_include = mcp_rs_include_dir(__DIR__);
include $rs_include . '/boot.php';
include $rs_include . '/authenticate.php';
include_once dirname(__DIR__) . '/include/mcp_oauth.php';

if (mcp_oauth_is_anonymous_user()) {
    exit('Permission denied.');
}

$paste_url = mcp_oauth_canonical_resource();
$fallback_url = mcp_oauth_plugin_resource();
$upload_url = mcp_oauth_issuer() . '/plugins/resourcespace_mcp/pages/mcp_upload.php';
$revoked_mine = false;

if (getval('revoke_mine', '') !== '' && enforcePostRequest(false) && mcp_oauth_posted_csrf_ok()) {
    global $userref;
    mcp_oauth_revoke_user((int) $userref);
    if (function_exists('log_activity')) {
        log_activity('MCP OAuth tokens revoked for user');
    }
    $revoked_mine = true;
}

include $rs_include . '/header.php';
?>
<div class="BasicsBox">
    <h1><?php echo escape($lang['resourcespace_mcp_help_title']); ?></h1>
    <p><?php echo escape($lang['resourcespace_mcp_help_intro']); ?></p>
    <div class="Question">
        <label for="resourcespace_mcp_paste_url"><?php echo escape($lang['resourcespace_mcp_help_url_label']); ?></label>
        <input id="resourcespace_mcp_paste_url" class="stdwidth" type="text" readonly="readonly"
            value="<?php echo escape($paste_url); ?>" onclick="this.select();" />
        <div class="clearerleft"></div>
    </div>
    <div class="Question">
        <label for="resourcespace_mcp_fallback_url"><?php echo escape($lang['resourcespace_mcp_help_fallback_label']); ?></label>
        <input id="resourcespace_mcp_fallback_url" class="stdwidth" type="text" readonly="readonly"
            value="<?php echo escape($fallback_url); ?>" onclick="this.select();" />
        <p><?php echo escape($lang['resourcespace_mcp_help_fallback']); ?></p>
        <div class="clearerleft"></div>
    </div>
    <ol>
        <li><?php echo escape($lang['resourcespace_mcp_help_step1']); ?></li>
        <li><?php echo escape($lang['resourcespace_mcp_help_step2']); ?></li>
        <li><?php echo escape($lang['resourcespace_mcp_help_step3']); ?></li>
        <li><?php echo escape($lang['resourcespace_mcp_help_step4']); ?></li>
    </ol>
</div>
<div class="BasicsBox">
    <h2><?php echo escape($lang['resourcespace_mcp_help_bearer_title']); ?></h2>
    <p><?php echo escape($lang['resourcespace_mcp_help_bearer']); ?></p>
    <p><?php echo escape($lang['resourcespace_mcp_help_upload']); ?></p>
    <input class="stdwidth" type="text" readonly="readonly"
        value="<?php echo escape($upload_url); ?>" onclick="this.select();" />
</div>
<div class="BasicsBox">
    <p><?php echo escape($lang['resourcespace_mcp_help_totp']); ?></p>
    <p><?php echo escape($lang['resourcespace_mcp_help_prereq']); ?></p>
    <?php if (!empty($revoked_mine)) { ?>
        <p><?php echo escape($lang['resourcespace_mcp_oauth_revoked_mine']); ?></p>
    <?php } ?>
    <form method="post" action="">
        <?php generateFormToken('mcp_oauth_revoke_mine'); ?>
        <input type="submit" name="revoke_mine" value="<?php echo escape($lang['resourcespace_mcp_oauth_revoke_mine']); ?>"
            onclick="return confirm(<?php echo json_encode($lang['resourcespace_mcp_oauth_revoke_mine_confirm'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>);" />
    </form>
</div>
<?php
include $rs_include . '/footer.php';

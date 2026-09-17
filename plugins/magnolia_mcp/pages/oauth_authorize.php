<?php
include '../../../include/boot.php';
include_once __DIR__ . '/../include/mcp_oauth.php';
include '../../../include/authenticate.php';

if (!mcp_oauth_plugin_enabled()) {
    http_response_code(403);
    exit('Permission denied.');
}

if (mcp_oauth_is_anonymous_user()) {
    http_response_code(401);
    include '../../../include/header.php';
    echo '<p>' . escape($lang['magnolia_mcp_oauth_need_account']) . '</p>';
    include '../../../include/footer.php';
    exit;
}

$query = mcp_oauth_authorize_params($_GET, $_POST, (string) ($_SERVER['QUERY_STRING'] ?? ''));
$validated = mcp_oauth_validate_authorize_request($query);
$is_post = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';

if ($is_post) {
    enforcePostRequest(false);
    if (!mcp_oauth_posted_csrf_ok()) {
        http_response_code(403);
        include '../../../include/header.php';
        echo '<p>' . escape($lang['magnolia_mcp_oauth_csrf']) . '</p>';
        include '../../../include/footer.php';
        exit;
    }
}

if (!$validated['ok']) {
    if (empty($validated['html']) && ($validated['redirect'] ?? '') !== '') {
        header('Location: ' . $validated['redirect'], true, 302);
        exit;
    }
    http_response_code(400);
    include '../../../include/header.php';
    echo '<p>' . escape((string) ($validated['error'] ?? 'invalid_request')) . '</p>';
    include '../../../include/footer.php';
    exit;
}

if ($is_post) {
    if (getval('deny', '') !== '') {
        header('Location: ' . mcp_oauth_deny_location($validated['redirect_uri'], $validated['state']), true, 302);
        exit;
    }
    global $userref;
    $code = mcp_oauth_random();
    mcp_oauth_insert_code([
        'code_hash' => mcp_oauth_hash($code),
        'userref' => (int) $userref,
        'client_id' => $validated['client_id'],
        'redirect_uri' => $validated['redirect_uri'],
        'code_challenge' => $validated['code_challenge'],
        'resource' => $validated['resource'],
        'scope' => 'mcp',
        'expires' => date('Y-m-d H:i:s', time() + 300),
    ]);
    if (function_exists('log_activity')) {
        log_activity('MCP OAuth consent granted');
    }
    header('Location: ' . mcp_oauth_grant_location($validated['redirect_uri'], $code, $validated['state']), true, 302);
    exit;
}

mcp_oauth_remember_return((string) ($_SERVER['REQUEST_URI'] ?? ''));

include '../../../include/header.php';
$client_display = (string) ($validated['client']['display'] ?? '');
$redirect_host = (string) parse_url($validated['redirect_uri'], PHP_URL_HOST);
$client = $client_display !== '' ? $client_display : $redirect_host;
$text = str_replace(
    ['[client]', '[username]'],
    [$client, (string) $username],
    $lang['magnolia_mcp_oauth_text']
);
?>
<div class="BasicsBox">
    <h1><?php echo escape($lang['magnolia_mcp_oauth_title']); ?></h1>
    <p><?php echo escape($text); ?></p>
    <?php if ($redirect_host !== '') { ?>
    <p><?php echo escape(str_replace('[host]', $redirect_host, $lang['magnolia_mcp_oauth_redirect'])); ?></p>
    <?php } ?>
    <form method="post" action="">
        <?php generateFormToken("mcp_oauth_authorize"); ?>
        <input type="hidden" name="client_id" value="<?php echo escape($validated['client_id']); ?>" />
        <input type="hidden" name="redirect_uri" value="<?php echo escape($validated['redirect_uri']); ?>" />
        <input type="hidden" name="state" value="<?php echo escape($validated['state']); ?>" />
        <input type="hidden" name="code_challenge" value="<?php echo escape($validated['code_challenge']); ?>" />
        <input type="hidden" name="code_challenge_method" value="S256" />
        <input type="hidden" name="resource" value="<?php echo escape($validated['resource']); ?>" />
        <input type="hidden" name="scope" value="<?php echo escape($validated['scope']); ?>" />
        <input type="hidden" name="response_type" value="code" />
        <div class="QuestionSubmit">
            <input type="submit" name="save" value="<?php echo escape($lang['magnolia_mcp_oauth_grant']); ?>" />
            <input type="submit" name="deny" value="<?php echo escape($lang['magnolia_mcp_oauth_deny']); ?>" />
            <div class="clearerleft"></div>
        </div>
    </form>
</div>
<?php
include '../../../include/footer.php';

<?php
/**
 * Hook de login break-glass OTP.
 * Incluído por index.php (marcadores BEGIN/END issabel-security-fix breakglass).
 *
 * @return bool true se o hook já tratou a requisição (die/redirect)
 */
function isf_breakglass_handle($pACL, $smarty, $arrConf)
{
    $root = '/opt/issabel-security-fix';
    $conf = $root . '/conf/breakglass.conf';
    $iptablesDb = isset($arrConf['issabel_dbdir'])
        ? rtrim($arrConf['issabel_dbdir'], '/') . '/iptables.db'
        : '/var/www/db/iptables.db';

    require_once $root . '/php/breakglass/Totp.php';
    require_once $root . '/php/breakglass/Policy.php';

    $policy = new IsfBreakglassPolicy($conf, $iptablesDb);
    if (!$policy->isEnabled()) {
        return false;
    }

    // Validação do código OTP (passo 2)
    if (isset($_POST['isf_otp_code']) && !empty($_SESSION['isf_bg_user'])) {
        return isf_breakglass_verify_otp($pACL, $smarty, $policy);
    }

    // Após senha correta (passo 1) — intercepta antes do 2FA/licença
    if (isset($_POST['submit_login']) && !empty($_POST['input_user'])) {
        // Só age se autenticação já foi validada pelo caller OU validamos aqui
        // O patch no index.php chama ANTES do fluxo nativo quando senha OK.
    }

    return false;
}

/**
 * Chamado pelo patch de index.php logo após authenticateUser OK.
 * Se IP não está na whitelist explícita, força OTP e encerra.
 *
 * @return bool true = OTP exigido (já exibiu tela / die)
 */
function isf_breakglass_after_password($pACL, $smarty, $arrConf, $user, $pass_md5)
{
    $root = '/opt/issabel-security-fix';
    require_once $root . '/php/breakglass/Totp.php';
    require_once $root . '/php/breakglass/Policy.php';

    $iptablesDb = isset($arrConf['issabel_dbdir'])
        ? rtrim($arrConf['issabel_dbdir'], '/') . '/iptables.db'
        : '/var/www/db/iptables.db';
    $policy = new IsfBreakglassPolicy($root . '/conf/breakglass.conf', $iptablesDb);

    if (!$policy->isEnabled()) {
        return false;
    }
    if ($policy->isExplicitlyWhitelisted()) {
        return false; // IP confiável — fluxo normal
    }

    $secret = '';
    if (method_exists($pACL, 'getTwoFactorSecret')) {
        $secret = (string) $pACL->getTwoFactorSecret($user);
    }
    if ($secret === '' || $secret === false) {
        $policy->audit("BREAKGLASS deny no-secret user=$user ip=" . $policy->clientIp());
        isf_breakglass_render_blocked(
            $smarty,
            'OTP obrigatório: seu IP não está na whitelist e este usuário ainda não tem TOTP. '
            . 'No servidor (SSH): isf-enroll-totp ' . htmlspecialchars($user, ENT_QUOTES, 'UTF-8')
        );
        return true; // never reached
    }

    $_SESSION['isf_bg_user'] = $user;
    $_SESSION['isf_bg_pass'] = $pass_md5;
    $_SESSION['isf_bg_ip'] = $policy->clientIp();
    isf_breakglass_render_otp($smarty);
    $policy->audit("BREAKGLASS otp-challenge user=$user ip=" . $policy->clientIp());
    return true;
}

function isf_breakglass_verify_otp($pACL, $smarty, $policy)
{
    $user = $_SESSION['isf_bg_user'];
    $pass_md5 = $_SESSION['isf_bg_pass'];
    $code = isset($_POST['isf_otp_code']) ? $_POST['isf_otp_code'] : '';
    $secret = method_exists($pACL, 'getTwoFactorSecret')
        ? (string) $pACL->getTwoFactorSecret($user)
        : '';

    if ($secret === '' || !IsfTotp::verify($secret, $code)) {
        $policy->audit("BREAKGLASS otp-fail user=$user ip=" . $policy->clientIp());
        isf_breakglass_render_otp($smarty, 'Código OTP inválido. Tente novamente.');
        return true;
    }

    // Sessão completa
    if (class_exists('IssabelAuth')) {
        $iauth = new IssabelAuth();
        // acquire_jwt_token espera senha em texto em alguns fluxos; usamos md5 já autenticado
        // Mantém padrão do index.php após 2FA nativo:
        list($access_token, $refresh_token) = $iauth->acquire_jwt_token($user, $pass_md5);
        $_SESSION['access_token'] = $access_token;
        $_SESSION['refresh_token'] = $refresh_token;
    }
    $_SESSION['issabel_user'] = $user;
    $_SESSION['issabel_pass'] = $pass_md5;

    $ip = $policy->clientIp();
    $policy->addTemporaryWhitelist($ip, $user);

    unset($_SESSION['isf_bg_user'], $_SESSION['isf_bg_pass'], $_SESSION['isf_bg_ip']);
    $policy->audit("BREAKGLASS otp-ok user=$user ip=$ip ttl_h=" . $policy->ttlHours());

    if (function_exists('writeLOG')) {
        writeLOG(
            'audit.log',
            "LOGIN $user: Break-glass OTP OK from $ip (temp whitelist " . $policy->ttlHours() . 'h).'
        );
    }

    header('Location: index.php');
    exit;
}

function isf_breakglass_resolve_theme()
{
    $theme = '';
    if (function_exists('load_theme')) {
        $theme = (string) load_theme('/var/www/html/');
    }
    if ($theme === '' && is_file('/var/www/db/settings.db')) {
        $db = @new SQLite3('/var/www/db/settings.db', SQLITE3_OPEN_READONLY);
        if ($db) {
            $row = @$db->querySingle("SELECT value FROM settings WHERE key='theme'", true);
            if (is_array($row) && !empty($row['value'])) {
                $theme = (string) $row['value'];
            } elseif (is_string($row) && $row !== '') {
                $theme = $row;
            }
            $db->close();
        }
    }
    if ($theme === '' || !is_dir('/var/www/html/themes/' . $theme)) {
        $theme = is_dir('/var/www/html/themes/virtual') ? 'virtual' : 'tenant';
    }
    return $theme;
}

function isf_breakglass_render_otp($smarty, $error = '')
{
    $sCurYear = date('Y');
    if ($sCurYear < '2013') {
        $sCurYear = '2013';
    }
    $theme = isf_breakglass_resolve_theme();
    $logoCandidates = array(
        "/var/www/html/themes/{$theme}/images/issabel_logo_mini.png",
        "/var/www/html/themes/{$theme}/images/logo.png",
        '/var/www/html/themes/tenant/images/issabel_logo_mini.png',
    );
    $logoSrc = '';
    foreach ($logoCandidates as $abs) {
        if (is_file($abs)) {
            $logoSrc = str_replace('/var/www/html/', '', $abs);
            break;
        }
    }

    $tpl = '/opt/issabel-security-fix/php/breakglass/otp.tpl';
    $smarty->assign('currentyear', $sCurYear);
    $smarty->assign('THEMENAME', $theme);
    $smarty->assign('WEBPATH', '');
    $smarty->assign('LOGO_SRC', $logoSrc);
    $smarty->assign('SUBMIT', 'Verificar');
    $smarty->assign('PAGE_NAME', 'Verificação OTP (Break-glass)');
    $smarty->assign('WELCOME', 'Seu IP não está na whitelist. Digite o código de 6 dígitos do Google Authenticator / FreeOTP / Authy.');
    $smarty->assign('CODE', 'Código OTP');
    $smarty->assign('OTP_ERROR', $error);
    $smarty->assign('ISSABEL_LICENSED', 'is licensed under');
    $smarty->assign('LOGIN_COLOR_1', '#1b2838');
    $smarty->assign('LOGIN_COLOR_2', '#0f1720');
    if (is_file($tpl)) {
        $smarty->display($tpl);
    } else {
        echo '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>OTP</title></head><body>';
        echo '<form method="post" action="index.php"><h2>Código OTP</h2>';
        if ($error) {
            echo '<p style="color:red">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</p>';
        }
        echo '<input name="isf_otp_code" autocomplete="one-time-code" autofocus required> '
            . '<button type="submit">Verificar</button></form></body></html>';
    }
    die();
}

function isf_breakglass_render_blocked($smarty, $msg)
{
    header('HTTP/1.1 403 Forbidden');
    $safe = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
    echo '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>OTP necessário</title></head>'
        . '<body style="font-family:sans-serif;max-width:40rem;margin:3rem auto">'
        . '<h1>Acesso break-glass</h1><p>' . $safe . '</p>'
        . '<p><a href="index.php">Voltar ao login</a></p></body></html>';
    die();
}

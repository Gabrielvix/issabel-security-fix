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
            $val = @$db->querySingle("SELECT value FROM settings WHERE key='theme'");
            if (is_string($val) && $val !== '') {
                $theme = $val;
            }
            $db->close();
        }
    }
    if ($theme === '' || !is_dir('/var/www/html/themes/' . $theme)) {
        $theme = is_dir('/var/www/html/themes/tenant') ? 'tenant' : 'virtual';
    }
    return $theme;
}

/**
 * Monta template OTP a partir do login.tpl do tema (mesma identidade visual).
 * Só substitui o <form> de usuário/senha pelo formulário de código.
 */
function isf_breakglass_otp_form_snippet()
{
    return <<<'TPL'
			<p class="isf-otp-hint" style="text-align:center;margin:0 0 16px;opacity:0.9;">{$WELCOME}</p>
			<form method="post" action="index.php" autocomplete="off">
				<div class="form-group">
					<div class="input-group">
						<div class="input-group-addon">
							<i class="entypo-key"></i>
						</div>
						<input type="text" class="form-control" name="isf_otp_code" id="isf_otp_code"
						       placeholder="{$CODE}" inputmode="numeric" pattern="[0-9]*" maxlength="8"
						       autocomplete="one-time-code" autofocus />
					</div>
				</div>
				<div class="form-group">
					<button type="submit" class="btn btn-primary btn-block btn-login" name="isf_otp_submit" value="1">
						<i class="entypo-login"></i>
						{$SUBMIT}
					</button>
				</div>
			</form>
			<p style="text-align:center;margin-top:12px;">
				<a href="index.php" style="text-decoration:none;opacity:0.85;">{$BACK_LOGIN}</a>
			</p>
TPL;
}

function isf_breakglass_build_theme_otp_tpl($loginTplPath)
{
    $src = @file_get_contents($loginTplPath);
    if ($src === false || $src === '') {
        return false;
    }

    // Garante formulário visível mesmo se neon-login.js falhar
    if (strpos($src, 'login-form-fall-init') === false) {
        $src = preg_replace('/\blogin-form-fall\b/', 'login-form-fall login-form-fall-init', $src, 1);
    }

    $otpForm = isf_breakglass_otp_form_snippet();
    $count = 0;
    $out = preg_replace('/<form\b[^>]*>.*?<\/form>/is', $otpForm, $src, 1, $count);
    if ($count < 1 || !is_string($out)) {
        return false;
    }
    return $out;
}

function isf_breakglass_render_otp($smarty, $error = '')
{
    $sCurYear = date('Y');
    if ($sCurYear < '2013') {
        $sCurYear = '2013';
    }
    $theme = isf_breakglass_resolve_theme();
    $webroot = '/var/www/html';
    $loginTpl = "{$webroot}/themes/{$theme}/_common/login.tpl";

    // jQuery / HEAD libs — mesmo caminho do login e do 2FA nativo
    if (class_exists('paloSantoNavigation')) {
        $oPn = new paloSantoNavigation(array(), $smarty);
        if (method_exists($oPn, 'putHEAD_JQUERY_HTML')) {
            $oPn->putHEAD_JQUERY_HTML();
        }
    }

    $submit = function_exists('_tr') ? _tr('Submit') : 'Verificar';
    $pageName = function_exists('_tr') ? _tr('Two Factor Authentication') : 'Verificação OTP (Break-glass)';
    $codeLbl = function_exists('_tr') ? _tr('Code') : 'Código OTP';
    $welcome = 'Seu IP não está na whitelist. Digite o código de 6 dígitos do autenticador.';
    $back = function_exists('_tr') ? _tr('Back') : 'Voltar ao login';
    if ($back === 'Back') {
        $back = 'Voltar ao login';
    }

    $smarty->assign('currentyear', $sCurYear);
    $smarty->assign('THEMENAME', $theme);
    $smarty->assign('WEBPATH', '');
    $smarty->assign('SUBMIT', $submit);
    $smarty->assign('PAGE_NAME', $pageName . ' (Break-glass)');
    $smarty->assign('WELCOME', $welcome);
    $smarty->assign('CODE', $codeLbl);
    $smarty->assign('OTP_ERROR', $error);
    $smarty->assign('LOGIN_INCORRECT', $error);
    $smarty->assign('BACK_LOGIN', $back);
    $smarty->assign('USERNAME', function_exists('_tr') ? _tr('Username') : 'Username');
    $smarty->assign('PASSWORD', function_exists('_tr') ? _tr('Password') : 'Password');
    $smarty->assign('ISSABEL_LICENSED', function_exists('_tr') ? _tr('is licensed under') : 'is licensed under');
    $smarty->assign('LOGIN_COLOR_1', '#2c3e50');
    $smarty->assign('LOGIN_COLOR_2', '#34495e');

    $rendered = false;
    if (is_file($loginTpl)) {
        $built = isf_breakglass_build_theme_otp_tpl($loginTpl);
        if (is_string($built) && $built !== '') {
            $cacheDir = $webroot . '/templates_c';
            if (!is_dir($cacheDir)) {
                @mkdir($cacheDir, 0755, true);
            }
            $cacheFile = $cacheDir . '/isf_breakglass_otp_' . preg_replace('/[^a-zA-Z0-9_-]/', '', $theme) . '.tpl';
            if (@file_put_contents($cacheFile, $built) !== false) {
                $smarty->display($cacheFile);
                $rendered = true;
            }
        }
    }

    if (!$rendered) {
        // Fallback genérico (tema sem login.tpl padrão)
        $tpl = '/opt/issabel-security-fix/php/breakglass/otp.tpl';
        $logoSrc = '';
        foreach (array(
            "{$webroot}/themes/{$theme}/images/issabel_logo_mini.png",
            "{$webroot}/themes/{$theme}/images/logo.png",
            "{$webroot}/images/logo.png",
        ) as $abs) {
            if (is_file($abs)) {
                $logoSrc = ltrim(str_replace($webroot, '', $abs), '/');
                break;
            }
        }
        $smarty->assign('LOGO_SRC', $logoSrc);
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

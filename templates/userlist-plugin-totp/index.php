<?php
/**
 * Plugin userlist: cadastro TOTP (break-glass / issabel-security-fix)
 */
require_once '/opt/issabel-security-fix/php/breakglass/Totp.php';

class paloUserPlugin_totp extends paloSantoUserPluginBase
{
    function userReport_labels()
    {
        return array(_tr('TOTP'));
    }

    function userReport_data($username, $id_user)
    {
        $sec = '';
        if (method_exists($this->_pACL, 'getTwoFactorSecret')) {
            $sec = (string) $this->_pACL->getTwoFactorSecret($username);
        }
        return array($sec !== '' ? _tr('Configured') : _tr('Not configured'));
    }

    function addFormElements($privileged)
    {
        return array();
    }

    function loadFormEditValues($username, $id_user)
    {
        // noop
    }

    function fetchForm($smarty, $oForm, $local_templates_dir, $pvars)
    {
        $username = isset($pvars['name']) ? trim($pvars['name']) : '';
        $secret = '';
        if ($username !== '' && method_exists($this->_pACL, 'getTwoFactorSecret')) {
            $secret = (string) $this->_pACL->getTwoFactorSecret($username);
        }

        $uri = '';
        $qrDataUri = '';
        if ($secret !== '') {
            $uri = IsfTotp::otpAuthUri($secret, $username !== '' ? $username : 'user', 'Issabel');
            $qrDataUri = $this->_qrDataUri($uri);
        }

        $bgEnabled = $this->_breakglassEnabled();
        $smarty->assign(array(
            'LBL_TOTP_TITLE'   => _tr('Two-Factor Authentication (TOTP)'),
            'LBL_TOTP_HELP'    => _tr('Required for login from IPs outside the Issabel whitelist when Break-glass OTP is enabled. Scan the QR with Google Authenticator, FreeOTP or Authy.'),
            'LBL_TOTP_STATUS'  => _tr('Status'),
            'LBL_TOTP_SECRET'  => _tr('Secret (base32)'),
            'LBL_TOTP_URI'     => _tr('otpauth URI'),
            'LBL_TOTP_GEN'     => _tr('Generate new TOTP'),
            'LBL_TOTP_CLEAR'   => _tr('Remove TOTP'),
            'LBL_TOTP_KEEP'    => _tr('Keep current TOTP'),
            'TOTP_CONFIGURED'  => ($secret !== ''),
            'TOTP_STATUS_TXT'  => ($secret !== '') ? _tr('Configured') : _tr('Not configured'),
            'TOTP_SECRET'      => $secret,
            'TOTP_URI'         => $uri,
            'TOTP_QR'          => $qrDataUri,
            'TOTP_BG_ENABLED'  => $bgEnabled,
            'LBL_TOTP_BG'      => $bgEnabled
                ? _tr('Break-glass OTP is ENABLED on this server.')
                : _tr('Break-glass OTP is DISABLED (Apache IP lock only). You can still enroll TOTP now for later use.'),
            'TOTP_USERNAME'    => $username,
        ));

        return $smarty->fetch("$local_templates_dir/new_totp.tpl");
    }

    function runPostCreateUser($smarty, $username, $id_user)
    {
        return $this->_applyTotpAction($smarty, $username);
    }

    function runPostUpdateUser($smarty, $username, $id_user, $privileged)
    {
        return $this->_applyTotpAction($smarty, $username);
    }

    private function _applyTotpAction($smarty, $username)
    {
        if (!method_exists($this->_pACL, 'setTwoFactorSecret')) {
            return true;
        }
        $action = isset($_POST['isf_totp_action']) ? $_POST['isf_totp_action'] : 'keep';
        if ($action === 'generate') {
            $secret = IsfTotp::generateSecret();
            if (!$this->_pACL->setTwoFactorSecret($username, $secret)) {
                $smarty->assign(array(
                    'mb_title'   => _tr('ERROR'),
                    'mb_message' => _tr('Failed to save TOTP secret'),
                ));
                return false;
            }
            // Guarda para exibir QR no próximo load (já salvo)
            return true;
        }
        if ($action === 'clear') {
            if (!$this->_pACL->setTwoFactorSecret($username, '')) {
                $smarty->assign(array(
                    'mb_title'   => _tr('ERROR'),
                    'mb_message' => _tr('Failed to remove TOTP secret'),
                ));
                return false;
            }
        }
        return true;
    }

    private function _breakglassEnabled()
    {
        $f = '/opt/issabel-security-fix/conf/breakglass.conf';
        if (!is_file($f)) {
            return false;
        }
        foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (preg_match('/^ENABLED\s*=\s*1\s*$/', $line)) {
                return true;
            }
        }
        return false;
    }

    private function _qrDataUri($uri)
    {
        $qrlib = '/var/www/html/modules/sec_2fa/libs/phpqrcode.php';
        if (!is_file($qrlib)) {
            return '';
        }
        require_once $qrlib;
        if (!class_exists('QRcode')) {
            return '';
        }
        ob_start();
        @QRcode::png($uri, false, QR_ECLEVEL_L, 4, 2);
        $png = ob_get_clean();
        if ($png === '' || $png === false) {
            return '';
        }
        return 'data:image/png;base64,' . base64_encode($png);
    }
}

<?php
/**
 * TOTP (RFC 6238) — implementação mínima sem dependências.
 * Compatível com Google Authenticator / FreeOTP / Authy.
 */
class IsfTotp
{
    const PERIOD = 30;
    const DIGITS = 6;
    const ALGO = 'sha1';

    public static function generateSecret($bytes = 20)
    {
        return self::base32Encode(random_bytes($bytes));
    }

    public static function getCode($secret, $time = null)
    {
        if ($time === null) {
            $time = time();
        }
        $secretKey = self::base32Decode($secret);
        $counter = pack('N*', 0, (int) floor($time / self::PERIOD));
        $hash = hash_hmac(self::ALGO, $counter, $secretKey, true);
        $offset = ord(substr($hash, -1)) & 0x0f;
        $truncated = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        );
        $code = $truncated % (10 ** self::DIGITS);
        return str_pad((string) $code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function verify($secret, $code, $window = 1)
    {
        $code = preg_replace('/\s+/', '', (string) $code);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        $now = time();
        for ($i = -$window; $i <= $window; $i++) {
            $t = $now + ($i * self::PERIOD);
            if (hash_equals(self::getCode($secret, $t), $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Nome que aparece no Authenticator (issuer).
     * Sempre o domínio/hostname DESTE servidor (do cliente), nunca um valor fixo de outro site.
     * Preferência: HTTP_HOST → SERVER_NAME → hostname FQDN → "Issabel".
     * Ex.: pabx.cliente.exemplo:admin
     */
    public static function defaultIssuer()
    {
        foreach (array(
            isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '',
            isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '',
        ) as $raw) {
            $host = self::normalizeHost($raw);
            if ($host !== '') {
                return $host;
            }
        }

        $hn = @gethostname();
        $host = self::normalizeHost(is_string($hn) ? $hn : '');
        if ($host !== '') {
            return $host;
        }

        $fqdn = '';
        if (is_executable('/usr/bin/hostname')) {
            $fqdn = @trim((string) shell_exec('/usr/bin/hostname -f 2>/dev/null'));
        }
        $host = self::normalizeHost($fqdn);
        if ($host !== '') {
            return $host;
        }

        return 'Issabel';
    }

    /**
     * Normaliza host/domínio do cliente (sem porta, sem localhost).
     */
    private static function normalizeHost($raw)
    {
        $host = strtolower(trim((string) $raw));
        if ($host === '') {
            return '';
        }
        $host = preg_replace('/:\d+$/', '', $host);
        $host = trim($host, '[]');
        if ($host === '' || $host === 'localhost' || $host === 'localhost.localdomain') {
            return '';
        }
        // Ignora IP puro no label do Authenticator quando houver FQDN melhor depois
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return '';
        }
        return $host;
    }

    public static function otpAuthUri($secret, $account, $issuer = null)
    {
        if ($issuer === null || $issuer === '') {
            $issuer = self::defaultIssuer();
        }
        $account = trim((string) $account);
        if ($account === '') {
            $account = 'user';
        }
        // Label padrão Key URI: Issuer:account → Authenticator mostra domínio + usuário
        $label = rawurlencode($issuer . ':' . $account);
        $q = http_build_query(array(
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ));
        return 'otpauth://totp/' . $label . '?' . $q;
    }

    private static function base32Encode($data)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        foreach (str_split($data) as $c) {
            $binary .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($binary, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $out .= $alphabet[bindec($chunk)];
        }
        return $out;
    }

    private static function base32Decode($b32)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
        $binary = '';
        foreach (str_split($b32) as $c) {
            $pos = strpos($alphabet, $c);
            if ($pos === false) {
                continue;
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($binary, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $out .= chr(bindec($chunk));
            }
        }
        return $out;
    }
}

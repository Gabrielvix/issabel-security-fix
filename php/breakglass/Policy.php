<?php
/**
 * Política break-glass: OTP se IP ∉ whitelist explícita do Issabel.
 */
class IsfBreakglassPolicy
{
    private $conf;
    private $iptablesDb;

    public function __construct($confPath, $iptablesDb)
    {
        $this->conf = $this->loadConf($confPath);
        $this->iptablesDb = $iptablesDb;
    }

    public function isEnabled()
    {
        return !empty($this->conf['ENABLED']) && (string) $this->conf['ENABLED'] === '1';
    }

    public function ttlHours()
    {
        $h = isset($this->conf['TTL_HOURS']) ? (int) $this->conf['TTL_HOURS'] : 10;
        return $h > 0 ? $h : 10;
    }

    public function tempWhitelistEnabled()
    {
        return !isset($this->conf['TEMP_WHITELIST']) || (string) $this->conf['TEMP_WHITELIST'] === '1';
    }

    public function notePrefix()
    {
        return isset($this->conf['NOTE_PREFIX']) ? $this->conf['NOTE_PREFIX'] : 'isf-breakglass';
    }

    public function clientIp()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * Whitelist explícita = tabela whitelist do iptables.db (+ extra-allow opcional).
     * NÃO inclui RFC1918 automático.
     */
    public function isExplicitlyWhitelisted($ip = null)
    {
        if ($ip === null) {
            $ip = $this->clientIp();
        }
        if ($ip === '' || $ip === '127.0.0.1' || $ip === '::1') {
            return true;
        }

        $entries = $this->loadExplicitEntries();
        foreach ($entries as $entry) {
            if ($this->ipMatches($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    public function loadExplicitEntries()
    {
        $out = array();
        if (is_file($this->iptablesDb) && class_exists('SQLite3')) {
            try {
                $db = new SQLite3($this->iptablesDb, SQLITE3_OPEN_READONLY);
                $res = $db->query('SELECT ip_address FROM whitelist');
                if ($res) {
                    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                        if (!empty($row['ip_address'])) {
                            $out[] = trim($row['ip_address']);
                        }
                    }
                }
                $db->close();
            } catch (Exception $e) {
                // ignore
            }
        }
        $extra = '/opt/issabel-security-fix/conf/extra-allow-ips.txt';
        if (is_file($extra)) {
            foreach (file($extra, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $out[] = $line;
            }
        }
        return array_unique($out);
    }

    public function addTemporaryWhitelist($ip, $user)
    {
        if (!$this->tempWhitelistEnabled() || $ip === '') {
            return false;
        }
        $expires = time() + ($this->ttlHours() * 3600);
        $note = sprintf(
            '%s expires=%d user=%s created=%s',
            $this->notePrefix(),
            $expires,
            preg_replace('/[^a-zA-Z0-9._@-]/', '', $user),
            date('c')
        );

        if (is_file($this->iptablesDb) && class_exists('SQLite3')) {
            try {
                $db = new SQLite3($this->iptablesDb);
                $stmt = $db->prepare('SELECT COUNT(*) AS c FROM whitelist WHERE ip_address = :ip');
                $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
                $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                if ((int) $row['c'] === 0) {
                    $ins = $db->prepare('INSERT INTO whitelist (ip_address, note) VALUES (:ip, :note)');
                    $ins->bindValue(':ip', $ip, SQLITE3_TEXT);
                    $ins->bindValue(':note', $note, SQLITE3_TEXT);
                    $ins->execute();
                } else {
                    $upd = $db->prepare('UPDATE whitelist SET note = :note WHERE ip_address = :ip');
                    $upd->bindValue(':note', $note, SQLITE3_TEXT);
                    $upd->bindValue(':ip', $ip, SQLITE3_TEXT);
                    $upd->execute();
                }
                $db->close();
            } catch (Exception $e) {
                return false;
            }
        }

        $extra = '/opt/issabel-security-fix/conf/extra-allow-ips.txt';
        $dir = dirname($extra);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $have = is_file($extra) ? file($extra, FILE_IGNORE_NEW_LINES) : array();
        if (!in_array($ip, $have, true)) {
            file_put_contents($extra, $ip . "\n", FILE_APPEND | LOCK_EX);
        }

        // Sync Apache na hora (sudo → isf-sync-apache). Asterisk não é root.
        $sync = '/opt/issabel-security-fix/bin/isf-sync-apache';
        $log = '/var/log/issabel-security-fix-sync-apache.log';
        if (is_executable($sync)) {
            $cmd = '/usr/bin/sudo -n ' . escapeshellarg($sync) . ' >>' . escapeshellarg($log) . ' 2>&1';
            @exec($cmd);
        } elseif (is_executable('/opt/issabel-security-fix/issabel-security-fix.sh')) {
            $cmd = 'nohup /usr/bin/sudo -n /opt/issabel-security-fix/issabel-security-fix.sh --harden --apply >>'
                . escapeshellarg($log) . ' 2>&1 &';
            @exec($cmd);
        }
        if (is_executable('/usr/sbin/issabel-helper') || is_executable('/usr/bin/issabel-helper')) {
            @exec('/usr/bin/issabel-helper fwconfig --add_wl ' . escapeshellarg($ip) . ' >/dev/null 2>&1 &');
        }

        $this->audit("BREAKGLASS temp-whitelist ip=$ip user=$user expires=" . date('c', $expires));
        return true;
    }

    public function audit($msg)
    {
        $line = date('Y-m-d H:i:s') . ' ' . $msg . "\n";
        @file_put_contents('/var/log/issabel-security-fix-breakglass.log', $line, FILE_APPEND | LOCK_EX);
        if (function_exists('writeLOG')) {
            writeLOG('audit.log', $msg);
        }
    }

    private function ipMatches($ip, $entry)
    {
        if ($ip === $entry) {
            return true;
        }
        if (strpos($entry, '/') === false) {
            return false;
        }
        list($subnet, $mask) = explode('/', $entry, 2);
        $mask = (int) $mask;
        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
            !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $ipLong = ip2long($ip);
        $subLong = ip2long($subnet);
        $maskLong = -1 << (32 - $mask);
        return ($ipLong & $maskLong) === ($subLong & $maskLong);
    }

    private function loadConf($path)
    {
        $cfg = array(
            'ENABLED' => '0',
            'TTL_HOURS' => '10',
            'TEMP_WHITELIST' => '1',
            'NOTE_PREFIX' => 'isf-breakglass',
        );
        if (!is_file($path)) {
            return $cfg;
        }
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (strpos($line, '=') === false) {
                continue;
            }
            list($k, $v) = explode('=', $line, 2);
            $cfg[trim($k)] = trim($v);
        }
        return $cfg;
    }
}

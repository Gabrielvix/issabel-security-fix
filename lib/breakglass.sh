#!/usr/bin/env bash
# Break-glass OTP — install, patch index.php, expire temp whitelist, enroll helpers

BREAKGLASS_CONF="${FIX_ROOT}/conf/breakglass.conf"
BREAKGLASS_PHP_SRC="${FIX_ROOT}/php/breakglass"
BREAKGLASS_PHP_DST="${WEBROOT}/libs/isf_breakglass"
INDEX_PHP="${WEBROOT}/index.php"

breakglass_enabled() {
  [[ -f "$BREAKGLASS_CONF" ]] || return 1
  grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*1[[:space:]]*$' "$BREAKGLASS_CONF"
}

breakglass_ttl_hours() {
  local h
  h="$(grep -E '^[[:space:]]*TTL_HOURS[[:space:]]*=' "$BREAKGLASS_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
  [[ -n "$h" ]] || h=10
  echo "$h"
}

install_breakglass_php() {
  log INFO "Instalando PHP break-glass em $BREAKGLASS_PHP_DST ..."
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] copiaria Totp/Policy/hook + symlink conf"
    return 0
  fi
  mkdir -p "$BREAKGLASS_PHP_DST"
  install -o asterisk -g asterisk -m 0644 "${BREAKGLASS_PHP_SRC}/Totp.php" "${BREAKGLASS_PHP_DST}/Totp.php"
  install -o asterisk -g asterisk -m 0644 "${BREAKGLASS_PHP_SRC}/Policy.php" "${BREAKGLASS_PHP_DST}/Policy.php"
  install -o asterisk -g asterisk -m 0644 "${BREAKGLASS_PHP_SRC}/hook.php" "${BREAKGLASS_PHP_DST}/hook.php"
  install -o asterisk -g asterisk -m 0644 "${BREAKGLASS_PHP_SRC}/otp.tpl" "${BREAKGLASS_PHP_DST}/otp.tpl"
  # hook usa paths em /opt — ok
  log OK "PHP break-glass instalado"
}

patch_index_php_breakglass() {
  log INFO "Aplicando hook break-glass em index.php ..."
  if [[ ! -f "$INDEX_PHP" ]]; then
    log ERROR "index.php ausente: $INDEX_PHP"
    return 1
  fi
  if grep -q 'issabel-security-fix breakglass' "$INDEX_PHP" 2>/dev/null; then
    log OK "Hook breakglass já presente em index.php"
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] inseriria marcadores breakglass em $INDEX_PHP"
    return 0
  fi
  backup_file "$INDEX_PHP"

  # 1) Include + handle OTP submit (após $pACL / $smarty)
  local marker_load='// Two Factor Authentication Check'
  if ! grep -qF "$marker_load" "$INDEX_PHP"; then
    log ERROR "Marcador de 2FA não encontrado em index.php — patch manual necessário"
    return 1
  fi

  local load_block
  load_block="$(cat <<'PHP'
// BEGIN issabel-security-fix breakglass
if (file_exists('/opt/issabel-security-fix/php/breakglass/hook.php')) {
    require_once '/opt/issabel-security-fix/php/breakglass/hook.php';
    if (isset($_POST['isf_otp_code']) && !empty($_SESSION['isf_bg_user'])) {
        $iptablesDbBg = isset($arrConf['issabel_dbdir']) ? rtrim($arrConf['issabel_dbdir'],'/').'/iptables.db' : '/var/www/db/iptables.db';
        require_once '/opt/issabel-security-fix/php/breakglass/Policy.php';
        require_once '/opt/issabel-security-fix/php/breakglass/Totp.php';
        $isfBgPolicy = new IsfBreakglassPolicy('/opt/issabel-security-fix/conf/breakglass.conf', $iptablesDbBg);
        if ($isfBgPolicy->isEnabled()) {
            isf_breakglass_verify_otp($pACL, $smarty, $isfBgPolicy);
        }
    }
}
// END issabel-security-fix breakglass

PHP
)"

  # Insert before Two Factor Authentication Check
  local tmp
  tmp="$(mktemp)"
  awk -v block="$load_block" '
    /\/\/ Two Factor Authentication Check/ && !done {
      print block
      done=1
    }
    { print }
  ' "$INDEX_PHP" >"$tmp"

  # 2) After password OK — inject after session_regenerate_id
  local inject
  inject="$(cat <<'PHP'
        // BEGIN issabel-security-fix breakglass-gate
        if (!function_exists('isf_breakglass_after_password') && file_exists('/opt/issabel-security-fix/php/breakglass/hook.php')) {
            require_once '/opt/issabel-security-fix/php/breakglass/hook.php';
        }
        if (function_exists('isf_breakglass_after_password')) {
            // Retorna true somente após die() interno; se retornar, não continuar o login.
            if (isf_breakglass_after_password($pACL, $smarty, $arrConf, $_POST['input_user'], $pass_md5)) {
                die();
            }
        }
        // END issabel-security-fix breakglass-gate

PHP
)"

  awk -v inj="$inject" '
    /session_regenerate_id\(TRUE\);/ && !done {
      print
      print inj
      done=1
      next
    }
    { print }
  ' "$tmp" >"${tmp}.2"
  mv -f "${tmp}.2" "$INDEX_PHP"
  rm -f "$tmp"
  chown asterisk:asterisk "$INDEX_PHP"
  chmod 644 "$INDEX_PHP"

  if ! grep -q 'breakglass-gate' "$INDEX_PHP"; then
    log ERROR "Falha ao inserir breakglass-gate em index.php"
    return 1
  fi
  log OK "index.php patchado (breakglass)"
}

# Quando breakglass ativo: index.php liberado para todos; resto usa whitelist SEM RFC1918 auto
collect_whitelist_ips_breakglass() {
  local -a ips=()
  local ip note line

  ips+=("127.0.0.1" "::1")

  local ssh_ip
  ssh_ip="$(current_ssh_ip)"
  [[ -n "$ssh_ip" ]] && ips+=("$ssh_ip")

  if [[ -f "$IPTABLES_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
    while IFS='|' read -r ip note; do
      if is_ipv4_or_cidr "$ip"; then
        ips+=("$ip")
      fi
    done < <(sqlite3 "$IPTABLES_DB" "SELECT ip_address, IFNULL(note,'') FROM whitelist;" 2>/dev/null) || true
  fi

  local f
  shopt -s nullglob
  for f in /etc/fail2ban/jail.local /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf; do
    [[ -f "$f" ]] || continue
    while read -r line; do
      [[ "$line" =~ ^ignoreip[[:space:]]*= ]] || continue
      line="${line#*=}"
      for ip in $line; do
        is_ipv4_or_cidr "$ip" && ips+=("$ip")
      done
    done <"$f" || true
  done
  shopt -u nullglob

  if [[ -f "$EXTRA_ALLOW_FILE" ]]; then
    while read -r ip; do
      [[ -n "$ip" && "$ip" != \#* ]] || continue
      is_ipv4_or_cidr "$ip" && ips+=("$ip")
    done <"$EXTRA_ALLOW_FILE" || true
  fi

  printf '%s\n' "${ips[@]}" | awk 'NF' | sort -u
}

expire_breakglass_whitelist() {
  log INFO "Expirando entradas break-glass da whitelist..."
  local now prefix ttl
  now="$(date +%s)"
  prefix="$(grep -E '^[[:space:]]*NOTE_PREFIX[[:space:]]*=' "$BREAKGLASS_CONF" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
  [[ -n "$prefix" ]] || prefix="isf-breakglass"

  [[ -f "$IPTABLES_DB" ]] || return 0
  command -v sqlite3 >/dev/null 2>&1 || return 0

  local row ip note expires
  local removed=0
  while IFS='|' read -r ip note; do
    [[ -n "$ip" ]] || continue
    [[ "$note" == *"$prefix"* ]] || continue
    expires="$(echo "$note" | sed -n 's/.*expires=\([0-9][0-9]*\).*/\1/p')"
    [[ -n "$expires" ]] || continue
    if [[ "$expires" -le "$now" ]]; then
      log INFO "Expirado: $ip (note=$note)"
      if [[ $DRY_RUN -eq 0 ]]; then
        sqlite3 "$IPTABLES_DB" "DELETE FROM whitelist WHERE ip_address='$(echo "$ip" | sed "s/'/''/g")';"
        if [[ -f "$EXTRA_ALLOW_FILE" ]]; then
          grep -vxF "$ip" "$EXTRA_ALLOW_FILE" >"${EXTRA_ALLOW_FILE}.tmp" 2>/dev/null || true
          mv -f "${EXTRA_ALLOW_FILE}.tmp" "$EXTRA_ALLOW_FILE"
        fi
        command -v issabel-helper >/dev/null 2>&1 && issabel-helper fwconfig --remove_wl "$ip" >/dev/null 2>&1 || true
      fi
      removed=$((removed + 1))
    fi
  done < <(sqlite3 "$IPTABLES_DB" "SELECT ip_address, IFNULL(note,'') FROM whitelist;" 2>/dev/null) || true

  if [[ $removed -gt 0 && $DRY_RUN -eq 0 ]]; then
    log INFO "Reaplicando harden após expirar $removed IP(s)..."
    DRY_RUN=0 APPLY=1 run_harden
  else
    log OK "Nenhuma entrada break-glass expirada ($removed)"
  fi
}

enroll_totp_user() {
  local user="${1:-}"
  if [[ -z "$user" ]]; then
    log ERROR "Uso: isf-enroll-totp <usuario_issabel>"
    return 1
  fi
  local acl_db="/var/www/db/acl.db"
  if [[ ! -f /var/www/db/acl.db ]]; then
    log ERROR "acl.db não encontrado"
    return 1
  fi
  acl_db="/var/www/db/acl.db"

  local exists
  exists="$(sqlite3 "$acl_db" "SELECT COUNT(*) FROM acl_user WHERE name='$(echo "$user" | sed "s/'/''/g")';")"
  if [[ "$exists" != "1" ]]; then
    log ERROR "Usuário Issabel não encontrado: $user"
    return 1
  fi

  if ! sqlite3 "$acl_db" "PRAGMA table_info(acl_user);" | grep -q twofactorsecret; then
    sqlite3 "$acl_db" "ALTER TABLE acl_user ADD twofactorsecret varchar(200) DEFAULT '';"
  fi

  local secret
  secret="$(php -r 'require "/opt/issabel-security-fix/php/breakglass/Totp.php"; echo IsfTotp::generateSecret();')"
  sqlite3 "$acl_db" "UPDATE acl_user SET twofactorsecret='$(echo "$secret" | sed "s/'/''/g")' WHERE name='$(echo "$user" | sed "s/'/''/g")';"

  local uri
  uri="$(php -r 'require "/opt/issabel-security-fix/php/breakglass/Totp.php"; echo IsfTotp::otpAuthUri($argv[1], $argv[2], "Issabel");' "$secret" "$user")"

  # PNG para escanear (não imprime no terminal — abre no browser ou scp)
  local png="/tmp/isf-totp-${user}.png"
  php -r '
    require "/var/www/html/modules/sec_2fa/libs/phpqrcode.php";
    if (!class_exists("QRcode")) { fwrite(STDERR, "phpqrcode ausente\n"); exit(1); }
    QRcode::png($argv[1], $argv[2], QR_ECLEVEL_L, 6, 2);
  ' "$uri" "$png" 2>/dev/null || png=""

  echo
  echo "=== TOTP gerado para: $user ==="
  echo
  echo "IMPORTANTE: o terminal NÃO pede código do Authenticator — ele só cria o segredo."
  echo "Você precisa ADICIONAR a conta no app e, se quiser, confirmar abaixo."
  echo
  echo "--- Opção A (recomendada): interface web ---"
  echo "  System → Users → editar $user → Gerar novo TOTP → Salvar → escanear o QR na tela"
  echo
  echo "--- Opção B: Google Authenticator (manual) ---"
  echo "  1) Abra o Google Authenticator"
  echo "  2) + → Inserir chave de configuração"
  echo "  3) Conta: Issabel ($user)"
  echo "  4) Chave: $secret"
  echo "  5) Tipo: Baseada em tempo"
  echo
  echo "--- Opção C: escanear QR em arquivo ---"
  if [[ -n "$png" && -f "$png" ]]; then
    echo "  Arquivo PNG: $png"
    echo "  Copie para o PC (scp) ou: python3 -m http.server 8888 --directory /tmp"
    echo "  e abra http://SERVIDOR:8888/$(basename "$png") (só na rede confiável)"
  else
    echo "  (PNG não gerado — use Opção A ou B)"
  fi
  if command -v qrencode >/dev/null 2>&1; then
    echo
    echo "--- QR ASCII (escaneável em alguns apps) ---"
    qrencode -t ANSIUTF8 "$uri" || true
  fi
  echo
  echo "Secret (base32): $secret"
  echo "otpauth URI:     $uri"
  echo

  # Confirmação opcional com código do app
  if [[ -t 0 ]]; then
    local code=""
    read -r -p "Digite o código de 6 dígitos do Authenticator para confirmar (ou Enter para pular): " code || true
    if [[ -n "$code" ]]; then
      local ok
      ok="$(php -r 'require "/opt/issabel-security-fix/php/breakglass/Totp.php"; echo IsfTotp::verify($argv[1], $argv[2]) ? "1" : "0";' "$secret" "$code")"
      if [[ "$ok" == "1" ]]; then
        log OK "Código válido — Authenticator sincronizado com $user"
      else
        log ERROR "Código inválido. Confira o relógio do celular e use o secret/QR desta execução (não um antigo)."
        return 2
      fi
    else
      log WARN "Confirmação pulada. Cadastre o secret no Authenticator antes de ativar --enable-breakglass."
    fi
  fi

  log OK "Enrollment concluído para $user"
}

install_breakglass_cron() {
  local cronf="/etc/cron.d/issabel-security-fix-breakglass"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria $cronf"
    return 0
  fi
  cat >"$cronf" <<EOF
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
# Expira IPs break-glass e re-sincroniza Apache
*/15 * * * * root ${FIX_ROOT}/issabel-security-fix.sh --expire-breakglass --apply >>/var/log/issabel-security-fix-breakglass.log 2>&1
EOF
  chmod 644 "$cronf"
  log OK "Cron break-glass instalado: $cronf"
}

install_breakglass_cli() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] ln isf-enroll-totp"
    return 0
  fi
  cat >"${FIX_ROOT}/bin/isf-enroll-totp" <<'EOF'
#!/usr/bin/env bash
# Gera TOTP (Google Authenticator / FreeOTP) para usuário Issabel
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE" ]]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd -P "$(dirname "$SOURCE")/.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT}/lib/common.sh"
# shellcheck source=/dev/null
source "${ROOT}/lib/breakglass.sh"

if [[ $# -lt 1 ]]; then
  cat <<EOF2
Uso: $(basename "$0") <usuario_issabel>

Exemplos:
  $(basename "$0") admin
  ${ROOT}/issabel-security-fix.sh --enroll-totp admin
EOF2
  exit 1
fi

require_root
enroll_totp_user "$1"
EOF
  chmod +x "${FIX_ROOT}/bin/isf-enroll-totp"
  ln -sfn "${FIX_ROOT}/bin/isf-enroll-totp" /usr/local/sbin/isf-enroll-totp
  log OK "CLI: isf-enroll-totp"
}

install_totp_userlist_plugin() {
  local src="${FIX_ROOT}/templates/userlist-plugin-totp"
  local dst="${WEBROOT}/modules/userlist/plugins/totp"
  log INFO "Instalando plugin TOTP em userlist (tela de usuários)..."
  if [[ ! -d "$src" ]]; then
    log WARN "Template do plugin TOTP ausente: $src"
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria plugin em $dst"
    return 0
  fi
  mkdir -p "$dst/tpl" "$dst/lang"
  install -o asterisk -g asterisk -m 0644 "$src/index.php" "$dst/index.php"
  install -o asterisk -g asterisk -m 0644 "$src/tpl/new_totp.tpl" "$dst/tpl/new_totp.tpl"
  install -o asterisk -g asterisk -m 0644 "$src/lang/en.lang" "$dst/lang/en.lang"
  install -o asterisk -g asterisk -m 0644 "$src/lang/br.lang" "$dst/lang/br.lang"
  # pt-br alias se Issabel carregar pt-br
  install -o asterisk -g asterisk -m 0644 "$src/lang/br.lang" "$dst/lang/pt-br.lang"
  log OK "Plugin userlist/totp instalado — edite usuários em System → Users"
}

set_breakglass_enabled() {
  local want="${1:-0}"
  local conf="$BREAKGLASS_CONF"
  mkdir -p "$(dirname "$conf")"
  if [[ ! -f "$conf" ]]; then
    cat >"$conf" <<EOF
ENABLED=${want}
TTL_HOURS=10
TEMP_WHITELIST=1
NOTE_PREFIX=isf-breakglass
EOF
  else
    if grep -qE '^[[:space:]]*ENABLED[[:space:]]*=' "$conf"; then
      sed -i "s/^[[:space:]]*ENABLED[[:space:]]*=.*/ENABLED=${want}/" "$conf"
    else
      echo "ENABLED=${want}" >>"$conf"
    fi
  fi
  log OK "breakglass.conf ENABLED=${want}"
}

run_breakglass_install() {
  log INFO "=== BREAKGLASS OTP (enabled=$(breakglass_enabled && echo yes || echo no)) ==="
  # Plugin de UI sempre (cadastro TOTP na tela de usuários), mesmo com ENABLED=0
  install_breakglass_php
  install_totp_userlist_plugin
  install_breakglass_cli

  if ! breakglass_enabled; then
    log INFO "Break-glass DESATIVADO — Apache permanece com bloqueio total por whitelist (recomendado)."
    log INFO "Para ativar depois: $0 --harden --apply --enable-breakglass"
    # Remove patch gate se existir? Melhor deixar patch inerte (policy checks ENABLED)
    # Ainda assim patchar index para OTP submit funcionar quando ativar sem re-patch
    patch_index_php_breakglass || true
    return 0
  fi

  patch_index_php_breakglass
  install_breakglass_cron
  log OK "=== BREAKGLASS ATIVO (TTL=$(breakglass_ttl_hours)h) ==="
  log WARN "Cadastre TOTP: isf-enroll-totp admin  OU  System → Users → editar usuário"
  log WARN "index.php público para login+OTP; /admin e configs.php CONTINUAM bloqueados por IP."
}

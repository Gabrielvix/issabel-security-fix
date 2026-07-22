#!/usr/bin/env bash
# Hardening Apache / admin / PHP / uploads — Issabel Security Fix

HTACCESS_ADMIN="${WEBROOT}/admin/.htaccess"
APACHE_CONF_DROPIN="/etc/httpd/conf.d/issabel-admin-ip-restrict.conf"
APACHE_UPLOAD_DROPIN="/etc/httpd/conf.d/issabel-upload-security.conf"
APACHE_BASELINE_DROPIN="/etc/httpd/conf.d/issabel-security-baseline.conf"
APACHE_NOWELCOME_DROPIN="/etc/httpd/conf.d/zz-issabel-security-no-welcome.conf"
PHP_SECURITY_INI="/etc/php.d/99-issabel-security-fix.ini"

# Diretórios onde PHP NÃO deve executar (uploads/cache/tmp)
DENY_PHP_DIRS=(
  "${WEBROOT}/cache"
  "${WEBROOT}/captures"
  "${WEBROOT}/download"
  "${WEBROOT}/images"
  "${WEBROOT}/tmp"
  "${WEBROOT}/templates_c"
  "${WEBROOT}/_jsons"
  "${WEBROOT}/var"
  "${WEBROOT}/fop2/admin/uploads"
  "${WEBROOT}/fop2/admin/_cache"
  "${WEBROOT}/admin/modules/_cache"
  "/var/spool/asterisk/tmp"
  "/var/spool/asterisk/monitor"
)

generate_admin_htaccess_v2() {
  local out="$1"
  local ip
  {
    echo "# Gerado por issabel-security-fix ${FIX_VERSION} em $(date -Iseconds)"
    if declare -F breakglass_enabled >/dev/null 2>&1 && breakglass_enabled; then
      echo "# Breakglass: whitelist explícita (sem auto-RFC1918) + fail2ban + SSH + extra-allow"
    else
      echo "# Fonte: whitelist Issabel (iptables.db) + fail2ban ignoreip + SSH atual + extra-allow-ips.txt"
    fi
    echo "# Atualize com: issabel-security-fix.sh --harden"
    echo
    echo "# 1) Restrição por IP (Apache 2.4)"
    echo "<IfModule mod_authz_core.c>"
    echo "  <RequireAny>"
    while read -r ip; do
      [[ -n "$ip" ]] || continue
      echo "    Require ip $ip"
    done < <(harden_collect_ips)
    echo "  </RequireAny>"
    echo "</IfModule>"
    echo
    echo "# 2) Restrição de arquivos (padrão Issabel, sintaxe 2.4)"
    echo "<FilesMatch \"\\..*\$\">"
    echo "    Require all denied"
    echo "</FilesMatch>"
    echo "<FilesMatch \"(^\$|index\\.php|config\\.php|\\.(gif|GIF|jpg|jpeg|png|css|js|swf|txt|ico|ttf|svg|eot|woff|wav|mp3|aac|ogg|webm|json)\$)\">"
    echo "    Require all granted"
    echo "</FilesMatch>"
  } >"$out"
}

generate_deny_php_htaccess() {
  local out="$1"
  cat >"$out" <<'EOF'
# Gerado por issabel-security-fix — bloqueia execução PHP neste diretório
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<FilesMatch "\.(?i:php|phtml|php[0-9]|phar|cgi|pl|py|sh|asp|aspx|jsp)$">
    Require all denied
</FilesMatch>
# Bloqueia double-extension (shell.php.jpg)
<FilesMatch "\.(?i:php|phtml|phar)\.[a-z0-9]+$">
    Require all denied
</FilesMatch>
EOF
}

# Lista de IPs para restrição Apache (breakglass = sem RFC1918 automático)
harden_collect_ips() {
  if declare -F breakglass_enabled >/dev/null 2>&1 && breakglass_enabled; then
    collect_whitelist_ips_breakglass
  else
    collect_whitelist_ips
  fi
}

generate_apache_dropin() {
  local out="$1"
  local ip
  local bg=0
  if declare -F breakglass_enabled >/dev/null 2>&1 && breakglass_enabled; then
    bg=1
  fi
  {
    echo "# Gerado por issabel-security-fix ${FIX_VERSION}"
    if [[ $bg -eq 1 ]]; then
      echo "# MODO BREAKGLASS OTP: index.php aberto (login+OTP); demais endpoints = whitelist explícita"
      echo "# (sem auto-RFC1918). Após OTP o IP entra na whitelist por TTL_HOURS."
    else
      echo "# Restringe /admin E a UI Issabel (index.php = firewall/whitelist/fail2ban/etc)"
      echo "# Sempre liberado: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, localhost"
      echo "# + whitelist Issabel + fail2ban ignoreip + conf/extra-allow-ips.txt"
    fi
    echo
    echo "<Directory \"${WEBROOT}/admin\">"
    echo "    AllowOverride All"
    echo "    AuthMerging And"
    echo "    <RequireAny>"
    while read -r ip; do
      [[ -n "$ip" ]] || continue
      echo "      Require ip $ip"
    done < <(harden_collect_ips)
    echo "    </RequireAny>"
    echo "</Directory>"
    echo
    if [[ $bg -eq 1 ]]; then
      # Login acessível de qualquer IP; OTP no PHP decide
      echo "<Files \"index.php\">"
      echo "    Require all granted"
      echo "</Files>"
      echo
      echo "# Demais entrypoints Issabel ainda restritos (whitelist explícita)"
      echo "<FilesMatch \"^(configs|config\\.all|rest|issabel_warning_authentication)\\.php\$\">"
      echo "    <RequireAny>"
      while read -r ip; do
        [[ -n "$ip" ]] || continue
        echo "      Require ip $ip"
      done < <(harden_collect_ips)
      echo "    </RequireAny>"
      echo "</FilesMatch>"
      echo
      echo "<LocationMatch \"^/\$\">"
      echo "    Require all granted"
      echo "</LocationMatch>"
    else
      echo "# Interface Issabel (index.php?menu=sec_whitelist, sec_rules, sec_fb_*, ...)"
      echo "<FilesMatch \"^(index|configs|config\\.all|rest|issabel_warning_authentication)\\.php\$\">"
      echo "    <RequireAny>"
      while read -r ip; do
        [[ -n "$ip" ]] || continue
        echo "      Require ip $ip"
      done < <(harden_collect_ips)
      echo "    </RequireAny>"
      echo "</FilesMatch>"
      echo
      echo "# Raiz / tambem restrita (senao DirectoryIndex negado vira HTTP Server Test Page)"
      echo "<LocationMatch \"^/\$\">"
      echo "    <RequireAny>"
      while read -r ip; do
        [[ -n "$ip" ]] || continue
        echo "      Require ip $ip"
      done < <(harden_collect_ips)
      echo "    </RequireAny>"
      echo "</LocationMatch>"
    fi
  } >"$out"
}

generate_upload_apache_conf() {
  local out="$1"
  local d
  {
    echo "# Gerado por issabel-security-fix ${FIX_VERSION}"
    echo "# Desliga engine PHP e nega scripts em dirs de upload/cache"
    echo
    for d in "${DENY_PHP_DIRS[@]}"; do
      [[ -d "$d" ]] || continue
      echo "<Directory \"$d\">"
      echo "    AllowOverride All"
      echo "    <IfModule mod_php7.c>"
      echo "        php_admin_flag engine off"
      echo "    </IfModule>"
      echo "    <IfModule mod_php.c>"
      echo "        php_admin_flag engine off"
      echo "    </IfModule>"
      echo "    <FilesMatch \"\\.(?i:php|phtml|php[0-9]|phar|cgi|pl|py|sh)\$\">"
      echo "        Require all denied"
      echo "    </FilesMatch>"
      echo "    Options -ExecCGI -Includes"
      echo "</Directory>"
      echo
    done
  } >"$out"
}

generate_baseline_apache_conf() {
  local out="$1"
  local forbid_page="/var/www/html/isf-403.html"
  if [[ $DRY_RUN -eq 0 ]]; then
    cat >"$forbid_page" <<'HTML'
<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>403 Acesso negado</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:4rem">
<h1>403 &mdash; Acesso negado</h1>
<p>Seu IP nao esta autorizado a acessar este painel.</p>
<p>Solicite inclusao na whitelist ou use: <code>isf-allow-ip SEU.IP</code></p>
</body></html>
HTML
    chown asterisk:asterisk "$forbid_page" 2>/dev/null || true
  fi
  cat >"$out" <<EOF
# Gerado por issabel-security-fix ${FIX_VERSION}
# Baseline HTTP hardening

ServerTokens Prod
ServerSignature Off
TraceEnable Off
DirectoryIndex index.php index.html

<Directory "${WEBROOT}">
    <FilesMatch "\\.(?i:phtml|php[3-7]|phar|cgi|pl)\$">
        Require all denied
    </FilesMatch>
    <FilesMatch "\\.(?i:php|phtml|phar)\\.[A-Za-z0-9]+\$">
        Require all denied
    </FilesMatch>
</Directory>

ErrorDocument 403 /isf-403.html

# Pagina 403 deve ser acessivel mesmo sem whitelist
<Files "isf-403.html">
    Require all granted
</Files>
EOF
}

generate_php_security_ini() {
  local out="$1"
  cat >"$out" <<'EOF'
; Gerado por issabel-security-fix
; NÃO desabilitamos exec/system/passthru globalmente — o Issabel/Asterisk depende disso.
; Contenção de webshell = engine off em dirs de upload + IP allow no /admin.

expose_php = Off
allow_url_include = Off
cgi.fix_path = 0
enable_dl = Off

; Cookies de sessão mais seguros
session.cookie_httponly = 1
session.use_strict_mode = 1

; Limita uploads absurdos (ainda permite áudio/MOH grandes)
upload_max_filesize = 64M
post_max_size = 72M
max_file_uploads = 20
EOF
}

harden_admin_htaccess() {
  log INFO "Aplicando .htaccess restritivo em /admin ..."
  local tmp
  tmp="$(mktemp)"
  generate_admin_htaccess_v2 "$tmp"

  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] escreveria $HTACCESS_ADMIN"
    rm -f "$tmp"
    return 0
  fi

  backup_file "$HTACCESS_ADMIN"
  install -o asterisk -g asterisk -m 0644 "$tmp" "$HTACCESS_ADMIN"
  rm -f "$tmp"
  log OK "Atualizado $HTACCESS_ADMIN"
}

harden_deny_php_dirs() {
  local d tmp
  for d in "${DENY_PHP_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    tmp="$(mktemp)"
    generate_deny_php_htaccess "$tmp"
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] escreveria ${d}/.htaccess (deny PHP + engine off)"
      rm -f "$tmp"
      continue
    fi
    [[ -f "${d}/.htaccess" ]] && backup_file "${d}/.htaccess"
    install -o asterisk -g asterisk -m 0644 "$tmp" "${d}/.htaccess"
    rm -f "$tmp"
    # remove bit de execução em arquivos já dropados
    find "$d" -type f -name '*.php' -exec chmod a-x {} + 2>/dev/null || true
    log OK "PHP negado em $d"
  done
}

harden_apache_conf() {
  log INFO "Gerando drop-ins Apache (admin IP + upload + baseline)..."
  local tmp1 tmp2 tmp3 tmp4
  tmp1="$(mktemp)"; tmp2="$(mktemp)"; tmp3="$(mktemp)"; tmp4="$(mktemp)"
  generate_apache_dropin "$tmp1"
  generate_upload_apache_conf "$tmp2"
  generate_baseline_apache_conf "$tmp3"
  cat >"$tmp4" <<'EOF'
# Sobrescreve welcome.conf: nao mostrar "HTTP Server Test Page" em /
<LocationMatch "^/+$">
    Options -Indexes
    ErrorDocument 403 /isf-403.html
</LocationMatch>
EOF

  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] escreveria drop-ins Apache + zz-no-welcome"
    rm -f "$tmp1" "$tmp2" "$tmp3" "$tmp4"
    return 0
  fi

  backup_file "$APACHE_CONF_DROPIN"
  backup_file "$APACHE_UPLOAD_DROPIN"
  backup_file "$APACHE_BASELINE_DROPIN"
  backup_file "$APACHE_NOWELCOME_DROPIN"
  install -o root -g root -m 0644 "$tmp1" "$APACHE_CONF_DROPIN"
  install -o root -g root -m 0644 "$tmp2" "$APACHE_UPLOAD_DROPIN"
  install -o root -g root -m 0644 "$tmp3" "$APACHE_BASELINE_DROPIN"
  install -o root -g root -m 0644 "$tmp4" "$APACHE_NOWELCOME_DROPIN"
  rm -f "$tmp1" "$tmp2" "$tmp3" "$tmp4"

  if apachectl configtest >/dev/null 2>&1; then
    systemctl reload httpd >/dev/null 2>&1 || service httpd reload >/dev/null 2>&1 || true
    log OK "Apache configs OK e recarregado"
  else
    log ERROR "apachectl configtest FALHOU — revertendo drop-ins"
    rm -f "$APACHE_CONF_DROPIN" "$APACHE_UPLOAD_DROPIN" "$APACHE_BASELINE_DROPIN" "$APACHE_NOWELCOME_DROPIN"
    return 1
  fi
}

harden_php_ini() {
  log INFO "Aplicando PHP security ini ($PHP_SECURITY_INI)..."
  local tmp
  tmp="$(mktemp)"
  generate_php_security_ini "$tmp"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] escreveria $PHP_SECURITY_INI"
    rm -f "$tmp"
    return 0
  fi
  backup_file "$PHP_SECURITY_INI"
  install -o root -g root -m 0644 "$tmp" "$PHP_SECURITY_INI"
  rm -f "$tmp"
  log OK "PHP ini de segurança instalado (sem disable_functions global)"
}

harden_permissions() {
  log INFO "Ajustando permissões sensíveis..."
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] chmod 750 admin, 640 configs, upload dirs 750"
    return 0
  fi
  chmod 750 "${WEBROOT}/admin" 2>/dev/null || true
  chmod 640 /etc/amportal.conf 2>/dev/null || true
  chmod 640 /etc/issabelpbx.conf 2>/dev/null || true
  local d
  for d in "${DENY_PHP_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    chmod 750 "$d" 2>/dev/null || true
  done
  # remove world-writable em webroot (mantém dirs necessários)
  find "$WEBROOT" -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true
  log OK "Permissões básicas aplicadas"
}

install_whitelist_sync_cron() {
  local cronf="/etc/cron.d/issabel-security-fix-whitelist"
  local body
  body="SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
15 3 * * * root ${FIX_ROOT}/issabel-security-fix.sh --harden --apply >>/var/log/issabel-security-fix-harden.log 2>&1
"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria $cronf"
    return 0
  fi
  echo "$body" >"$cronf"
  chmod 644 "$cronf"
  log OK "Cron de sync whitelist instalado: $cronf"
}

install_integrity_cron() {
  local cronf="/etc/cron.d/issabel-security-fix-scan"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria scan horário $cronf"
    return 0
  fi
  cat >"$cronf" <<EOF
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 * * * * root ${FIX_ROOT}/issabel-security-fix.sh --scan >>/var/log/issabel-security-fix-scan.log 2>&1
EOF
  chmod 644 "$cronf"
  log OK "Cron de scan horário instalado"
}


install_cli_symlinks() {
  log INFO "Instalando CLIs isf-allow-ip / isf-deny-ip..."
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] ln -sfn bin/isf-* /usr/local/sbin/"
    return 0
  fi
  chmod +x "${FIX_ROOT}/bin/isf-allow-ip" "${FIX_ROOT}/bin/isf-deny-ip" 2>/dev/null || true
  ln -sfn "${FIX_ROOT}/bin/isf-allow-ip" /usr/local/sbin/isf-allow-ip
  ln -sfn "${FIX_ROOT}/bin/isf-deny-ip" /usr/local/sbin/isf-deny-ip
  log OK "CLIs: isf-allow-ip, isf-deny-ip"
}

install_whitelist_apache_hook() {
  local target="/var/www/html/modules/sec_whitelist/libs/Issabelwhitelist.class.php"
  local patched="${FIX_ROOT}/templates/Issabelwhitelist.class.php.patched"
  log INFO "Aplicando hook whitelist Issabel -> Apache sync..."
  if [[ ! -f "$target" ]]; then
    log WARN "Modulo sec_whitelist nao encontrado — pulando hook"
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria hook em $target"
    return 0
  fi
  if [[ -f "$patched" ]] && grep -q '_syncApacheAllowlist' "$patched"; then
    backup_file "$target"
    install -o asterisk -g asterisk -m 0644 "$patched" "$target"
    log OK "Hook whitelist Apache instalado"
  elif grep -q '_syncApacheAllowlist' "$target"; then
    log OK "Hook whitelist ja presente"
  else
    log WARN "Patch do hook indisponivel — add/delete no painel pode nao sincronizar Apache ate corrigir"
  fi
}

run_harden() {
  log INFO "=== HARDENING (dry-run=$DRY_RUN) ==="
  print_whitelist
  local count
  count="$(harden_collect_ips | wc -l)"
  local min_ips=2
  if declare -F breakglass_enabled >/dev/null 2>&1 && breakglass_enabled; then
    min_ips=1
  fi
  if [[ "$count" -lt "$min_ips" ]]; then
    log ERROR "Whitelist resultante muito pequena ($count). Abortando harden para evitar lockout total."
    return 1
  fi
  harden_admin_htaccess
  harden_apache_conf
  harden_deny_php_dirs
  harden_php_ini
  harden_permissions
  install_cli_symlinks
  install_whitelist_apache_hook
  if [[ "${INSTALL_CRONS:-1}" == "1" ]]; then
    install_whitelist_sync_cron
    install_integrity_cron
  fi
  if declare -F run_breakglass_install >/dev/null 2>&1; then
    run_breakglass_install
  fi
  log OK "=== HARDENING concluído ==="
  log WARN "Teste o acesso ao /admin a partir de um IP liberado antes de sair da sessão SSH."
  log INFO "Nota: exec/system NÃO foram desabilitados no PHP global (Issabel depende disso). Contenção = engine off em uploads + IP no /admin."
  if declare -F breakglass_enabled >/dev/null 2>&1 && breakglass_enabled; then
    log WARN "Break-glass OTP ATIVO: index.php público para login; /admin bloqueado por whitelist; OTP fora da lista explícita; IP liberado por $(breakglass_ttl_hours)h após OTP."
  else
    log INFO "Break-glass OTP desativado — Apache bloqueia index.php e /admin por whitelist (máxima contenção)."
  fi
}

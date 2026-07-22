#!/usr/bin/env bash
# Scan de IoCs — Issabel Security Fix

scan_engine() {
  log INFO "Analisando issabelpbx_engine..."
  if [[ ! -f "$ENGINE_PATH" ]]; then
    log WARN "Engine ausente: $ENGINE_PATH"
    inc_finding critical
    return
  fi
  if file_matches_ioc_content "$ENGINE_PATH"; then
    log CRITICAL "ENGINE INFECTADO: $ENGINE_PATH"
    inc_finding critical
  elif grep -q 'IssabelPBX Control Script\|STARTING ASTERISK\|chown_asterisk' "$ENGINE_PATH" 2>/dev/null; then
    log OK "Engine aparenta ser legítimo"
  else
    log WARN "Engine presente mas conteúdo inesperado (verificar manualmente)"
    inc_finding
  fi
}

scan_startup_d() {
  log INFO "Analisando ${STARTUP_D}..."
  if [[ -d "$STARTUP_D" ]]; then
    local f
    while IFS= read -r -d '' f; do
      if file_matches_ioc_content "$f"; then
        log CRITICAL "Script malicioso em startup.d: $f"
        inc_finding critical
      fi
    done < <(find "$STARTUP_D" -type f -print0 2>/dev/null) || true
  fi
}

scan_rclocal() {
  log INFO "Analisando rc.local..."
  if [[ -f "$RC_LOCAL" ]] && file_matches_ioc_content "$RC_LOCAL"; then
    log CRITICAL "Persistência em $RC_LOCAL"
    inc_finding critical
  else
    log OK "rc.local sem IoCs conhecidos"
  fi
}

scan_setuid() {
  log INFO "Analisando /usr/sbin/setuid..."
  if [[ -e "$SETUID_BIN" ]]; then
    local mode
    mode="$(stat -c '%a' "$SETUID_BIN" 2>/dev/null || true)"
    log CRITICAL "Binário SUID suspeito presente: $SETUID_BIN (mode=$mode)"
    inc_finding critical
  else
    log OK "setuid malicioso ausente"
  fi
}

scan_users() {
  log INFO "Analisando usuários UID 0..."
  local user uid
  while IFS=: read -r user _ uid _; do
    [[ "$uid" == "0" ]] || continue
    if uid0_is_kept "$user"; then
      continue
    fi
    case "$user" in
      abort|yuki)
        log CRITICAL "Backdoor user presente: $user (UID 0)"
        ;;
      *)
        log CRITICAL "Usuário UID 0 não autorizado: $user"
        ;;
    esac
    inc_finding critical
  done < /etc/passwd || true
}

scan_acl_users() {
  log INFO "Analisando logins Issabel (acl.db) suspeitos..."
  [[ -f "$ACL_DB" ]] || { log INFO "acl.db ausente — pulando"; return 0; }
  if ! command -v sqlite3 >/dev/null 2>&1; then
    log WARN "sqlite3 ausente — não foi possível varrer acl.db"
    return 0
  fi
  local name
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if acl_user_exists "$name"; then
      log CRITICAL "Login Issabel de atacante presente: $name (acl.db)"
      inc_finding critical
    fi
    if getent passwd "$name" >/dev/null 2>&1; then
      log CRITICAL "Usuário Linux com nome de backdoor Issabel: $name"
      inc_finding critical
    fi
  done < <(acl_remove_list)
}

scan_ssh_keys() {
  log INFO "Analisando authorized_keys (marcador t3rr0r)..."
  local f
  for f in /root/.ssh/authorized_keys /home/asterisk/.ssh/authorized_keys; do
    if [[ -f "$f" ]] && grep -q 't3rr0r@private' "$f" 2>/dev/null; then
      log CRITICAL "Chave SSH backdoor em $f"
      inc_finding critical
    fi
  done
}

scan_crontabs() {
  log INFO "Analisando crontabs..."
  local f
  for f in /var/spool/cron/root /var/spool/cron/asterisk /var/spool/cron/apache; do
    if [[ -f "$f" ]] && file_matches_ioc_content "$f"; then
      log CRITICAL "Cron infectado: $f"
      inc_finding critical
    fi
  done
  # system crons
  if grep -RqlE '212\.83\.160\.70|postroot\.sh' /etc/cron* 2>/dev/null; then
    log CRITICAL "Referência C2 em /etc/cron*"
    inc_finding critical
  fi
}

scan_webshells() {
  log INFO "Procurando webshells em $WEBROOT ..."
  local count=0 f name md5 known
  declare -A KNOWN_MD5=()
  declare -A SEEN=()
  if [[ -f "$WEBSHELL_MD5" ]]; then
    while read -r known; do
      [[ -n "$known" ]] || continue
      KNOWN_MD5["$known"]=1
    done < "$WEBSHELL_MD5" || true
  fi

  mark_shell() {
    local path="$1"
    local why="$2"
    [[ -z "${SEEN[$path]:-}" ]] || return 0
    SEEN["$path"]=1
    log CRITICAL "Webshell ($why): $path"
    count=$((count + 1))
    inc_finding critical
  }

  if [[ -f "$WEBSHELL_NAMES" ]]; then
    while read -r name; do
      [[ -n "$name" ]] || continue
      while IFS= read -r -d '' f; do
        should_quarantine_named_webshell "$f" "$name" || continue
        mark_shell "$f" "nome"
      done < <(find_webshell_files_by_name "$name") || true
    done < "$WEBSHELL_NAMES" || true
  fi

  while IFS= read -r -d '' f; do
    md5="$(md5_of "$f")"
    if [[ -n "$md5" && -n "${KNOWN_MD5[$md5]:-}" ]]; then
      mark_shell "$f" "md5"
    fi
  done < <(find "$WEBROOT" -type f -name '*.php' -size 2068c -print0 2>/dev/null) || true

  local drop
  for drop in "$WEBROOT" "$WEBROOT/cache" "$WEBROOT/images" "$WEBROOT/tmp" \
              "$WEBROOT/templates_c" "$WEBROOT/captures" "$WEBROOT/download" \
              "$WEBROOT/fop2" "$WEBROOT/wizard" "$WEBROOT/pbxapi" \
              "$WEBROOT/lang" "$WEBROOT/libs" "$WEBROOT/panels" \
              "$WEBROOT/configs" "$WEBROOT/var" "$WEBROOT/themes" \
              "$WEBROOT/help" "$WEBROOT/reciclar" "$WEBROOT/_jsons" \
              "$WEBROOT/modules"; do
    [[ -d "$drop" ]] || continue
    while IFS= read -r -d '' f; do
      local sz
      sz="$(stat -c%s "$f" 2>/dev/null || echo 0)"
      [[ "$sz" -le 20000 ]] || continue
      if php_looks_like_webshell "$f"; then
        mark_shell "$f" "assinatura"
      fi
    done < <(find "$drop" -maxdepth 2 -type f -name '*.php' -print0 2>/dev/null) || true
  done

  log INFO "Webshells únicos encontrados: $count"
}

scan_defenses() {
  log INFO "Analisando defesas..."
  local fb=""
  fb="$(systemctl is-active fail2ban 2>/dev/null || true)"
  fb="$(echo "$fb" | tr -d '\r' | head -n1)"
  [[ -n "$fb" ]] || fb="unknown"
  if [[ "$fb" != "active" ]]; then
    log WARN "Fail2ban não está active (status=$fb)"
    inc_finding
  else
    log OK "Fail2ban active"
  fi

  local rules=0
  if iptables -L INPUT -n >/tmp/.isf-ipt.out 2>/dev/null; then
    if grep -q 'policy ACCEPT' /tmp/.isf-ipt.out; then
      rules="$(wc -l </tmp/.isf-ipt.out)"
      if [[ "$rules" -lt 8 ]]; then
        log WARN "iptables INPUT parece aberto/vazio (policy ACCEPT)"
        inc_finding
      fi
    fi
  fi
  rm -f /tmp/.isf-ipt.out
}

scan_shell_profiles() {
  log INFO "Analisando profiles shell..."
  local f
  for f in /root/.bashrc /root/.bash_profile /etc/profile /etc/rc.d/rc.local; do
    if [[ -f "$f" ]] && file_matches_ioc_content "$f"; then
      log CRITICAL "Persistência em $f"
      inc_finding critical
    fi
  done
}

run_scan() {
  log INFO "=== SCAN Issabel Security Fix v${FIX_VERSION} ==="
  FINDINGS=0
  CRITICAL=0
  scan_engine
  scan_startup_d
  scan_rclocal
  scan_setuid
  scan_users
  scan_acl_users
  scan_ssh_keys
  scan_crontabs
  scan_shell_profiles
  scan_campaign_extras
  scan_webshells
  scan_defenses
  log INFO "=== RESULTADO: ${FINDINGS} achados (${CRITICAL} críticos) ==="
  return 0
}

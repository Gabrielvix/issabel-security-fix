#!/usr/bin/env bash
# Remediação — Issabel Security Fix

clean_cron_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  if ! file_matches_ioc_content "$f"; then
    return 0
  fi
  backup_file "$f"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] limparia IoCs de cron: $f"
    return 0
  fi
  # remove linhas com C2 / postroot / cmd.txt botnet
  grep -vE '212\.83\.160\.70|postroot\.sh|cmd\.txt|/tmp/a\.txt|searchshells\.sh' "$f" >"${f}.clean" || true
  mv -f "${f}.clean" "$f"
  chmod 600 "$f"
  log OK "Cron limpo: $f"
}

remediate_crontabs() {
  local f
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/root /var/spool/cron/asterisk /var/spool/cron/apache; do
    clean_cron_file "$f"
  done
  # limpa também via crontab API se existir
  if [[ $DRY_RUN -eq 0 ]]; then
    if crontab -l 2>/dev/null | grep -qE '212\.83\.160\.70|postroot'; then
      crontab -l 2>/dev/null | grep -vE '212\.83\.160\.70|postroot\.sh|cmd\.txt|/tmp/a\.txt' | crontab - || true
      log OK "crontab root reescrito sem IoCs"
    fi
    if sudo -u asterisk crontab -l 2>/dev/null | grep -qE '212\.83\.160\.70|cmd\.txt'; then
      sudo -u asterisk crontab -l 2>/dev/null | grep -vE '212\.83\.160\.70|postroot\.sh|cmd\.txt|/tmp/a\.txt' | sudo -u asterisk crontab - || true
      log OK "crontab asterisk reescrito sem IoCs"
    fi
    if id apache &>/dev/null && crontab -u apache -l 2>/dev/null | grep -qE '212\.83\.160\.70|postroot|cmd\.txt'; then
      crontab -u apache -l 2>/dev/null | grep -vE '212\.83\.160\.70|postroot\.sh|cmd\.txt|/tmp/a\.txt' | crontab -u apache - || true
      log OK "crontab apache reescrito sem IoCs"
    fi
  fi
}

remediate_rclocal() {
  [[ -f "$RC_LOCAL" ]] || return 0
  if ! file_matches_ioc_content "$RC_LOCAL"; then
    return 0
  fi
  backup_file "$RC_LOCAL"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] limparia $RC_LOCAL"
    return 0
  fi
  grep -vE '212\.83\.160\.70|postroot\.sh|curl -ks|wget .*\| *bash' "$RC_LOCAL" >"${RC_LOCAL}.clean" || true
  # garante shebang e touch lock padrão Rocky
  if ! grep -q 'touch /var/lock/subsys/local' "${RC_LOCAL}.clean" 2>/dev/null; then
    cat >"${RC_LOCAL}.clean" <<'EOF'
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
touch /var/lock/subsys/local
EOF
  fi
  mv -f "${RC_LOCAL}.clean" "$RC_LOCAL"
  chmod 644 "$RC_LOCAL"
  log OK "rc.local limpo"
}

remediate_setuid() {
  [[ -e "$SETUID_BIN" ]] || return 0
  backup_file "$SETUID_BIN"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] removeria $SETUID_BIN"
    return 0
  fi
  quarantine_path "$SETUID_BIN"
  log OK "setuid malicioso removido"
}

remediate_uid0_extras() {
  local user uid
  while IFS=: read -r user _ uid _; do
    [[ "$uid" == "0" ]] || continue
    uid0_is_kept "$user" && continue
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] removeria usuário UID 0: $user"
      continue
    fi
    # UID 0 compartilhado com root → userdel pode reclamar de PIDs; force remove a conta
    userdel -rf "$user" 2>/dev/null || userdel -f "$user" 2>/dev/null || true
    if getent passwd "$user" >/dev/null 2>&1; then
      sed -i "/^${user}:/d" /etc/passwd /etc/shadow /etc/group 2>/dev/null || true
    fi
    if getent passwd "$user" >/dev/null 2>&1; then
      log ERROR "Falha ao remover usuário UID 0: $user"
    else
      log OK "Usuário UID 0 removido: $user"
    fi
  done < /etc/passwd || true
}

# compat: nome antigo
remediate_abort_user() { remediate_uid0_extras; }

remediate_ssh_keys() {
  local f
  for f in /root/.ssh/authorized_keys /home/asterisk/.ssh/authorized_keys; do
    [[ -f "$f" ]] || continue
    if ! grep -q 't3rr0r@private' "$f" 2>/dev/null; then
      continue
    fi
    backup_file "$f"
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] removeria chave t3rr0r de $f"
      continue
    fi
    grep -v 't3rr0r@private' "$f" >"${f}.clean" || true
    mv -f "${f}.clean" "$f"
    chmod 600 "$f"
    log OK "Chave backdoor removida de $f"
  done
}

remediate_startup_d() {
  [[ -d "$STARTUP_D" ]] || return 0
  local f
  while IFS= read -r -d '' f; do
    if file_matches_ioc_content "$f"; then
      backup_file "$f"
      if [[ $DRY_RUN -eq 1 ]]; then
        log INFO "[dry-run] quarentenaria $f"
      else
        quarantine_path "$f"
      fi
    fi
  done < <(find "$STARTUP_D" -type f -print0 2>/dev/null) || true
}

remediate_tmp_drops() {
  local f
  for f in /tmp/a.txt /tmp/a.tx /tmp/s.txt /tmp/setuid /tmp/setuid.c; do
    [[ -e "$f" ]] || continue
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] removeria $f"
    else
      rm -f "$f"
      log OK "Removido $f"
    fi
  done
}

remediate_webshells() {
  log INFO "Removendo webshells..."
  local f name md5 known
  declare -A KNOWN_MD5=()
  if [[ -f "$WEBSHELL_MD5" ]]; then
    while read -r known; do
      [[ -n "$known" ]] || continue
      KNOWN_MD5["$known"]=1
    done < "$WEBSHELL_MD5" || true
  fi

  local -a targets=()

  if [[ -f "$WEBSHELL_NAMES" ]]; then
    while read -r name; do
      [[ -n "$name" ]] || continue
      while IFS= read -r -d '' f; do
        should_quarantine_named_webshell "$f" "$name" || continue
        targets+=("$f")
      done < <(find_webshell_files_by_name "$name") || true
    done < "$WEBSHELL_NAMES" || true
  fi

  # MD5 match em php pequenos (inclui tokien ~822/843c e ofuscados ~2068c)
  while IFS= read -r -d '' f; do
    md5="$(md5_of "$f")"
    if [[ -n "$md5" && -n "${KNOWN_MD5[$md5]:-}" ]]; then
      targets+=("$f")
    fi
  done < <(find "$WEBROOT" -type f -name '*.php' -size -5k -print0 2>/dev/null) || true

  # ofuscados em drop dirs (não varrer admin/modules/* — evita tocar em guimodule/page.* legítimos)
  local drop
  for drop in "$WEBROOT" "$WEBROOT/cache" "$WEBROOT/images" "$WEBROOT/tmp" \
              "$WEBROOT/templates_c" "$WEBROOT/captures" "$WEBROOT/download" \
              "$WEBROOT/fop2" "$WEBROOT/wizard" "$WEBROOT/pbxapi" \
              "$WEBROOT/lang" "$WEBROOT/libs" "$WEBROOT/modules" \
              "$WEBROOT/panels" "$WEBROOT/configs" "$WEBROOT/var" \
              "$WEBROOT/themes" "$WEBROOT/help" "$WEBROOT/reciclar" \
              "$WEBROOT/_jsons"; do
    [[ -d "$drop" ]] || continue
    while IFS= read -r -d '' f; do
      local sz
      sz="$(stat -c%s "$f" 2>/dev/null || echo 0)"
      [[ "$sz" -le 20000 ]] || continue
      if php_looks_like_webshell "$f"; then
        targets+=("$f")
      fi
    done < <(find "$drop" -maxdepth 2 -type f -name '*.php' -print0 2>/dev/null) || true
  done

  # unique
  local -A seen=()
  local t
  for t in "${targets[@]:-}"; do
    [[ -n "$t" ]] || continue
    [[ -z "${seen[$t]:-}" ]] || continue
    seen["$t"]=1
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] quarentenaria webshell: $t"
    else
      backup_file "$t"
      quarantine_path "$t"
      plant_deny_stub "$t"
    fi
  done
}

restore_engine() {
  log INFO "Restaurando issabelpbx_engine limpo..."
  local tmp
  tmp="$(mktemp)"
  local ok=0

  # 1) vendor local
  if [[ -f "${FIX_ROOT}/vendor/issabelpbx_engine.clean" ]]; then
    cp -f "${FIX_ROOT}/vendor/issabelpbx_engine.clean" "$tmp"
    ok=1
  fi

  # 2) download GitHub oficial
  if [[ $ok -eq 0 ]]; then
    if curl -fsSL --max-time 60 "$ENGINE_URL" -o "$tmp" 2>/dev/null; then
      ok=1
      log INFO "Engine baixado de IssabelFoundation/issabelPBX"
    fi
  fi

  if [[ $ok -eq 0 ]]; then
    rm -f "$tmp"
    log ERROR "Não foi possível obter engine limpo. Baixe manualmente para ${FIX_ROOT}/vendor/issabelpbx_engine.clean"
    return 1
  fi

  # validação anti-trojan
  if file_matches_ioc_content "$tmp"; then
    rm -f "$tmp"
    log ERROR "Fonte do engine contém IoCs — abortando restore"
    return 1
  fi
  if ! grep -qE 'IssabelPBX Control Script|STARTING ASTERISK|chown_asterisk|amportal' "$tmp"; then
    rm -f "$tmp"
    log ERROR "Arquivo baixado não parece um issabelpbx_engine legítimo"
    return 1
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] substituiria $ENGINE_PATH pelo engine limpo ($(wc -l <"$tmp") linhas)"
    rm -f "$tmp"
    return 0
  fi

  if [[ -f "$ENGINE_PATH" ]]; then
    backup_file "$ENGINE_PATH"
    quarantine_path "$ENGINE_PATH"
  fi
  mkdir -p "$(dirname "$ENGINE_PATH")"
  install -o asterisk -g asterisk -m 0755 "$tmp" "$ENGINE_PATH"
  rm -f "$tmp"
  log OK "Engine restaurado: $ENGINE_PATH"
}

block_c2() {
  log INFO "Bloqueando IPs C2 conhecidos..."
  [[ -f "$C2_LIST" ]] || return 0
  local ip
  while read -r ip; do
    [[ -n "$ip" && "$ip" != \#* ]] || continue
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] bloquearia $ip (iptables + /etc/hosts.deny opcional)"
      continue
    fi
    # evita regra duplicada
    if ! iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
      iptables -I OUTPUT -d "$ip" -j DROP
    fi
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
      iptables -I INPUT -s "$ip" -j DROP
    fi
    log OK "C2 bloqueado: $ip"
  done < "$C2_LIST" || true
}

restore_defenses() {
  log INFO "Restaurando defesas..."
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] iniciaria fail2ban, amportal firewall e removeria firewall.disable"
    return 0
  fi
  rm -f /var/spool/asterisk/incron/firewall.disable 2>/dev/null || true
  rm -f /var/run/fail2ban/fail2ban.sock 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || systemctl start fail2ban >/dev/null 2>&1 || log WARN "Falha ao iniciar fail2ban"
  if [[ -x /usr/sbin/amportal ]]; then
    /usr/sbin/amportal firewall enable >/dev/null 2>&1 || log WARN "amportal firewall enable falhou"
    /usr/sbin/amportal firewall start >/dev/null 2>&1 || log WARN "amportal firewall start falhou"
  fi
  if command -v issabel-helper >/dev/null 2>&1; then
    issabel-helper fwconfig --load >/dev/null 2>&1 || log WARN "fwconfig --load retornou erro (revisar firewall Issabel)"
  fi
  log OK "Defesas: fail2ban + firewall Issabel (best-effort)"
}

remediate_profiles() {
  local f
  for f in /root/.bashrc /root/.bash_profile /etc/profile; do
    [[ -f "$f" ]] || continue
    if ! file_matches_ioc_content "$f"; then
      continue
    fi
    backup_file "$f"
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] limparia $f"
      continue
    fi
    grep -vE '212\.83\.160\.70|postroot\.sh|curl -ks http|wget .*\| *bash' "$f" >"${f}.clean" || true
    mv -f "${f}.clean" "$f"
    log OK "Profile limpo: $f"
  done
}

restore_web_packages() {
  log INFO "Reinstalando pacotes Issabel da web (recupera index/ajax sobrescritos)..."
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] dnf reinstall issabel-framework issabel-pbx issabel-system (se disponíveis)"
    return 0
  fi
  if ! command -v dnf >/dev/null 2>&1; then
    log WARN "dnf indisponível — reinstale manualmente os pacotes Issabel da interface web"
    return 0
  fi
  # best-effort; não falha o script se repo estiver offline
  if dnf -y reinstall issabel-framework issabel-pbx issabel-system >/tmp/isf-reinstall.log 2>&1; then
    log OK "Pacotes Issabel reinstalados (ver /tmp/isf-reinstall.log)"
  else
    log WARN "Reinstall parcial/falhou — revise /tmp/isf-reinstall.log e restaure admin/views a partir de backup/RPM"
  fi
}

run_remediate() {
  log INFO "=== REMEDIAÇÃO (dry-run=$DRY_RUN) ==="
  ensure_dirs
  # ordem crítica: cortar C2 e engine primeiro (para não reescrever durante limpeza)
  block_c2
  kill_malware_processes
  restore_engine
  remediate_startup_d
  remediate_rclocal
  remediate_crontabs
  remediate_profiles
  remediate_setuid
  remediate_uid0_extras
  remediate_ssh_keys
  remediate_tmp_drops
  remediate_webshells
  remediate_campaign_extras
  restore_web_packages
  restore_defenses
  log OK "=== REMEDIAÇÃO concluída ==="
  log WARN "Troque senhas root/Issabel/DB/SIP se ainda não o fez após o incidente."
}

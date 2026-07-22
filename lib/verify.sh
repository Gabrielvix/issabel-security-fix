#!/usr/bin/env bash
# Verificação pós-remediação — prova que a infecção não volta

run_verify() {
  log INFO "=== VERIFY (pós-fix) ==="
  local failed=0

  # 1) Engine limpo
  if [[ ! -f "$ENGINE_PATH" ]]; then
    log ERROR "VERIFY FAIL: engine ausente"
    failed=$((failed + 1))
  elif file_matches_ioc_content "$ENGINE_PATH"; then
    log ERROR "VERIFY FAIL: engine ainda com IoCs"
    failed=$((failed + 1))
  elif ! grep -qE 'IssabelPBX Control Script|STARTING ASTERISK|chown_asterisk' "$ENGINE_PATH"; then
    log ERROR "VERIFY FAIL: engine não parece legítimo"
    failed=$((failed + 1))
  else
    log OK "Engine limpo"
  fi

  # 2) Persistências clássicas
  for f in "$RC_LOCAL" /var/spool/cron/root /var/spool/cron/asterisk; do
    if [[ -f "$f" ]] && file_matches_ioc_content "$f"; then
      log ERROR "VERIFY FAIL: IoC em $f"
      failed=$((failed + 1))
    fi
  done

  if [[ -e "$SETUID_BIN" ]]; then
    log ERROR "VERIFY FAIL: $SETUID_BIN ainda existe"
    failed=$((failed + 1))
  else
    log OK "setuid ausente"
  fi

  local uid0_bad=0 user uid
  while IFS=: read -r user _ uid _; do
    [[ "$uid" == "0" ]] || continue
    uid0_is_kept "$user" && continue
    log ERROR "VERIFY FAIL: usuário UID 0 não autorizado: $user"
    failed=$((failed + 1))
    uid0_bad=1
  done < /etc/passwd || true
  if [[ $uid0_bad -eq 0 ]]; then
    log OK "somente UID 0 autorizados presentes"
  fi

  local acl_bad=0 acl_name
  while IFS= read -r acl_name; do
    [[ -n "$acl_name" ]] || continue
    if acl_user_exists "$acl_name"; then
      log ERROR "VERIFY FAIL: login Issabel de atacante ainda presente: $acl_name"
      failed=$((failed + 1))
      acl_bad=1
    fi
  done < <(acl_remove_list)
  if [[ $acl_bad -eq 0 ]]; then
    log OK "logins Issabel da lista acl-remove-users ausentes"
  fi

  if grep -q 't3rr0r@private' /root/.ssh/authorized_keys /home/asterisk/.ssh/authorized_keys 2>/dev/null; then
    log ERROR "VERIFY FAIL: chave t3rr0r presente"
    failed=$((failed + 1))
  else
    log OK "chave t3rr0r ausente"
  fi

  if [[ -f "${STARTUP_D}/postroot.sh" ]] && file_matches_ioc_content "${STARTUP_D}/postroot.sh"; then
    log ERROR "VERIFY FAIL: startup.d/postroot.sh malicioso"
    failed=$((failed + 1))
  else
    log OK "startup.d limpo (ou sem postroot malicioso)"
  fi

  if [[ -f "$EXTENSIONS_CUSTOM" ]] && grep -qE 'thanku-outcall|thankuohoh|212\.83\.160\.70' "$EXTENSIONS_CUSTOM" 2>/dev/null; then
    log ERROR "VERIFY FAIL: IoC no dialplan ($EXTENSIONS_CUSTOM)"
    failed=$((failed + 1))
  else
    log OK "dialplan sem IoCs de fraude conhecidos"
  fi

  local rel fp
  if [[ -f "${FIX_ROOT}/conf/webshell-paths.txt" ]]; then
    while read -r rel; do
      [[ -n "$rel" && "$rel" != \#* ]] || continue
      fp="${WEBROOT}/${rel}"
      if [[ -f "$fp" ]]; then
        log ERROR "VERIFY FAIL: artefato de campanha ainda presente: $fp"
        failed=$((failed + 1))
      fi
    done <"${FIX_ROOT}/conf/webshell-paths.txt" || true
  fi

  # 3) C2 bloqueado
  if iptables -C OUTPUT -d 212.83.160.70 -j DROP 2>/dev/null; then
    log OK "C2 bloqueado no iptables OUTPUT"
  else
    log WARN "C2 sem regra DROP explícita no OUTPUT (verifique perímetro)"
  fi

  # 4) Exercita o engine (chown) e recheca IoCs — se malware voltar, falhou
  log INFO "Exercitando engine (amportal/issabelpbx_engine chown)..."
  if [[ -x /usr/sbin/amportal ]]; then
    /usr/sbin/amportal chown >/tmp/isf-amportal-chown.log 2>&1 || true
  elif [[ -x "$ENGINE_PATH" ]]; then
    "$ENGINE_PATH" chown >/tmp/isf-amportal-chown.log 2>&1 || true
  fi
  sleep 2
  if file_matches_ioc_content "$ENGINE_PATH" \
     || { [[ -f "$RC_LOCAL" ]] && file_matches_ioc_content "$RC_LOCAL"; } \
     || getent passwd abort >/dev/null 2>&1; then
    log ERROR "VERIFY FAIL: IoCs reapareceram após executar o engine"
    failed=$((failed + 1))
  else
    log OK "Engine executado sem reinfecção"
  fi

  # 5) Upload: PHP em cache não deve executar
  local probe="${WEBROOT}/cache/isf_probe_$$.php"
  mkdir -p "${WEBROOT}/cache"
  echo '<?php echo "PWNED";' >"$probe"
  chown asterisk:asterisk "$probe" 2>/dev/null || true
  local code
  code="$(curl -sk -o /tmp/isf_probe_out.txt -w '%{http_code}' "http://127.0.0.1/cache/$(basename "$probe")" 2>/dev/null || echo 000)"
  local body
  body="$(cat /tmp/isf_probe_out.txt 2>/dev/null || true)"
  rm -f "$probe" /tmp/isf_probe_out.txt
  if [[ "$body" == *PWNED* ]]; then
    log ERROR "VERIFY FAIL: PHP executou em /cache (upload desprotegido) HTTP=$code"
    failed=$((failed + 1))
  else
    log OK "PHP em /cache não executa (HTTP=$code) — upload path protegido"
  fi

  # 6) Fail2ban
  local fb
  fb="$(systemctl is-active fail2ban 2>/dev/null || true)"
  fb="$(echo "$fb" | head -n1)"
  if [[ "$fb" == "active" ]]; then
    log OK "fail2ban active"
  else
    log WARN "fail2ban status=$fb"
  fi

  # 7) Hardening files
  if [[ -f /etc/httpd/conf.d/issabel-admin-ip-restrict.conf ]]; then
    log OK "drop-in admin IP presente"
  else
    log WARN "drop-in admin IP ausente"
  fi
  if [[ -f /etc/httpd/conf.d/issabel-upload-security.conf ]]; then
    log OK "drop-in upload security presente"
  else
    log WARN "drop-in upload security ausente"
  fi

  if ! verify_time; then
    failed=$((failed + 1))
  fi

  if [[ $failed -gt 0 ]]; then
    log ERROR "=== VERIFY: $failed falha(s) ==="
    return 1
  fi
  log OK "=== VERIFY: OK — sem reinfecção detectada ==="
  return 0
}

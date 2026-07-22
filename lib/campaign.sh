#!/usr/bin/env bash
# IoCs extras da campanha: dialplan (toll fraud), paths fixos, processos

EXTENSIONS_CUSTOM="${EXTENSIONS_CUSTOM:-/etc/asterisk/extensions_custom.conf}"
WEBSHELL_PATHS="${FIX_ROOT}/conf/webshell-paths.txt"
DIALPLAN_IOC_RE='thanku-outcall|thankuohoh|212\.83\.160\.70|postroot\.sh'

scan_webshell_paths() {
  [[ -f "$WEBSHELL_PATHS" ]] || return 0
  local rel f
  while read -r rel; do
    [[ -n "$rel" && "$rel" != \#* ]] || continue
    f="${WEBROOT}/${rel}"
    if [[ -f "$f" ]]; then
      log CRITICAL "Artefato de campanha (path fixo): $f"
      inc_finding critical
    fi
  done <"$WEBSHELL_PATHS" || true
}

remediate_webshell_paths() {
  [[ -f "$WEBSHELL_PATHS" ]] || return 0
  local rel f
  while read -r rel; do
    [[ -n "$rel" && "$rel" != \#* ]] || continue
    f="${WEBROOT}/${rel}"
    [[ -f "$f" ]] || continue
    if [[ $DRY_RUN -eq 1 ]]; then
      log INFO "[dry-run] quarentenaria path fixo: $f"
      continue
    fi
    backup_file "$f"
    quarantine_path "$f"
    plant_deny_stub "$f"
  done <"$WEBSHELL_PATHS" || true
}

scan_dialplan() {
  log INFO "Analisando dialplan custom ($EXTENSIONS_CUSTOM)..."
  [[ -f "$EXTENSIONS_CUSTOM" ]] || return 0
  if grep -qE "$DIALPLAN_IOC_RE" "$EXTENSIONS_CUSTOM" 2>/dev/null; then
    log CRITICAL "Fraude/IoC no dialplan: $EXTENSIONS_CUSTOM"
    inc_finding critical
  else
    log OK "extensions_custom.conf sem IoCs conhecidos"
  fi
}

remediate_dialplan() {
  [[ -f "$EXTENSIONS_CUSTOM" ]] || return 0
  if ! grep -qE "$DIALPLAN_IOC_RE" "$EXTENSIONS_CUSTOM" 2>/dev/null; then
    return 0
  fi
  backup_file "$EXTENSIONS_CUSTOM"
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] limparia linhas maliciosas em $EXTENSIONS_CUSTOM"
    return 0
  fi
  grep -vE "$DIALPLAN_IOC_RE" "$EXTENSIONS_CUSTOM" >"${EXTENSIONS_CUSTOM}.clean" || true
  mv -f "${EXTENSIONS_CUSTOM}.clean" "$EXTENSIONS_CUSTOM"
  chmod 644 "$EXTENSIONS_CUSTOM" 2>/dev/null || true
  chown asterisk:asterisk "$EXTENSIONS_CUSTOM" 2>/dev/null || true
  if command -v asterisk >/dev/null 2>&1; then
    asterisk -rx "dialplan reload" >/dev/null 2>&1 || log WARN "dialplan reload falhou"
  fi
  log OK "Dialplan limpo: $EXTENSIONS_CUSTOM"
}

scan_systemd_iocs() {
  log INFO "Analisando unidades systemd (IoCs)..."
  if grep -rE '212\.83\.160\.70|postroot\.sh|/usr/sbin/setuid' \
    /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null | grep -q .; then
    log CRITICAL "Referência a IoC em unit systemd"
    inc_finding critical
  fi
}

kill_malware_processes() {
  log INFO "Encerrando processos ligados a IoCs..."
  local pat
  local -a patterns=(
    '212\.83\.160\.70'
    'postroot\.sh'
    '/tmp/a\.txt'
    'php /tmp/a\.txt'
    'searchshells\.sh'
  )
  for pat in "${patterns[@]}"; do
    if pgrep -f "$pat" >/dev/null 2>&1; then
      if [[ $DRY_RUN -eq 1 ]]; then
        log INFO "[dry-run] mataria processos: $pat"
      else
        pkill -9 -f "$pat" 2>/dev/null || true
        log OK "Processos encerrados (padrão: $pat)"
      fi
    fi
  done
}

scan_campaign_extras() {
  scan_webshell_paths
  scan_dialplan
  scan_systemd_iocs
}

remediate_campaign_extras() {
  remediate_webshell_paths
  remediate_dialplan
}

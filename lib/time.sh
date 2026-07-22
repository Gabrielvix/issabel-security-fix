#!/usr/bin/env bash
# Sincronização de relógio (chrony) — crítico para TOTP/OTP

TIME_CONF="${FIX_ROOT}/conf/time.conf"
CHRONY_CONF="${CHRONY_CONF:-/etc/chrony.conf}"

time_conf_get() {
  local key="$1" def="${2:-}"
  [[ -f "$TIME_CONF" ]] || { echo "$def"; return 0; }
  local v
  v="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$TIME_CONF" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
  [[ -n "$v" ]] && echo "$v" || echo "$def"
}

time_is_synchronized() {
  if command -v timedatectl >/dev/null 2>&1; then
    timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes && return 0
  fi
  if command -v chronyc >/dev/null 2>&1; then
    chronyc tracking 2>/dev/null | grep -qi 'Leap status[[:space:]]*:[[:space:]]*Normal' && return 0
  fi
  return 1
}

time_chrony_offset_seconds() {
  # valor absoluto do System time offset (quando disponível)
  local line off
  line="$(chronyc tracking 2>/dev/null | grep -i 'System time' || true)"
  off="$(echo "$line" | sed -n 's/.*:[[:space:]]*\([0-9.]*\)[[:space:]]*seconds.*/\1/p')"
  [[ -n "$off" ]] && echo "$off" || echo ""
}

scan_time() {
  log INFO "Analisando relógio / NTP (crítico para OTP)..."
  local now
  now="$(date -R 2>/dev/null || date)"
  log INFO "Hora local: $now"

  if command -v timedatectl >/dev/null 2>&1; then
    local sync ntp svc tz
    sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
    ntp="$(timedatectl show -p NTP --value 2>/dev/null || echo unknown)"
    tz="$(timedatectl show -p Timezone --value 2>/dev/null || echo unknown)"
    log INFO "Timezone=$tz NTP=$ntp Synchronized=$sync"
  fi

  if time_is_synchronized; then
    local off
    off="$(time_chrony_offset_seconds)"
    if [[ -n "$off" ]]; then
      # offset > 30s é problemático para TOTP (passo padrão 30s)
      if awk -v o="$off" 'BEGIN{exit !(o+0 > 30)}' 2>/dev/null; then
        log WARN "Relógio sincronizado, mas offset NTP alto (${off}s) — OTP pode falhar"
        inc_finding
      else
        log OK "Relógio sincronizado via NTP (offset=${off:-?}s)"
      fi
    else
      log OK "Relógio sincronizado via NTP"
    fi
    return 0
  fi

  log CRITICAL "Relógio NÃO sincronizado com NTP — TOTP/OTP tende a falhar"
  inc_finding critical
  if [[ -f "$CHRONY_CONF" ]]; then
    log INFO "Fontes chrony atuais:"
    grep -E '^[[:space:]]*(server|pool)[[:space:]]' "$CHRONY_CONF" 2>/dev/null | while read -r l; do
      log INFO "  $l"
    done || true
  fi
}

ensure_chrony_package() {
  if command -v chronyd >/dev/null 2>&1; then
    return 0
  fi
  log INFO "Instalando chrony..."
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install chrony >/tmp/isf-chrony-install.log 2>&1 || {
      log ERROR "Falha ao instalar chrony (ver /tmp/isf-chrony-install.log)"
      return 1
    }
  elif command -v yum >/dev/null 2>&1; then
    yum -y install chrony >/tmp/isf-chrony-install.log 2>&1 || {
      log ERROR "Falha ao instalar chrony"
      return 1
    }
  else
    log ERROR "Sem dnf/yum — instale chrony manualmente"
    return 1
  fi
  log OK "chrony instalado"
}

chrony_has_usable_public_pool() {
  grep -qE '^[[:space:]]*(server|pool)[[:space:]]+(pool\.ntp\.org|[a-z]\.st1\.ntp\.br|2\.centos\.pool\.ntp\.org|0\.pool\.ntp\.org)' \
    "$CHRONY_CONF" 2>/dev/null
}

chrony_append_fallback_pools() {
  local pools csv p
  csv="$(time_conf_get NTP_POOLS 'a.st1.ntp.br,b.st1.ntp.br,pool.ntp.org')"
  [[ -f "$CHRONY_CONF" ]] || return 1
  backup_file "$CHRONY_CONF"

  # Garante makestep agressivo na partida (hora muito errada)
  if [[ "$(time_conf_get FORCE_STEP 1)" == "1" ]]; then
    if grep -qE '^[[:space:]]*makestep[[:space:]]' "$CHRONY_CONF"; then
      sed -i 's/^[[:space:]]*makestep[[:space:]].*/makestep 1.0 -1/' "$CHRONY_CONF"
    else
      echo "makestep 1.0 -1" >>"$CHRONY_CONF"
    fi
    grep -qE '^[[:space:]]*rtcsync' "$CHRONY_CONF" || echo "rtcsync" >>"$CHRONY_CONF"
  fi

  if ! grep -q 'issabel-security-fix NTP fallback' "$CHRONY_CONF" 2>/dev/null; then
    {
      echo ""
      echo "# BEGIN issabel-security-fix NTP fallback (OTP/TOTP)"
      IFS=',' read -ra pools <<<"$csv"
      for p in "${pools[@]}"; do
        p="$(echo "$p" | tr -d '[:space:]')"
        [[ -n "$p" ]] || continue
        if ! grep -qE "^[[:space:]]*(server|pool)[[:space:]]+${p}([[:space:]]|$)" "$CHRONY_CONF" \
           && ! grep -Fq "pool $p" "$CHRONY_CONF" \
           && ! grep -Fq "server $p" "$CHRONY_CONF"; then
          echo "pool $p iburst"
        fi
      done
      echo "# END issabel-security-fix NTP fallback"
    } >>"$CHRONY_CONF"
    log OK "Fontes NTP de fallback adicionadas em $CHRONY_CONF"
  else
    log INFO "Bloco NTP fallback já presente em chrony.conf"
  fi
}

apply_timezone_if_configured() {
  local tz
  tz="$(time_conf_get TIMEZONE '')"
  [[ -n "$tz" ]] || return 0
  if [[ ! -e "/usr/share/zoneinfo/$tz" ]]; then
    log WARN "TIMEZONE inválido em time.conf: $tz"
    return 1
  fi
  local cur
  cur="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  if [[ "$cur" == "$tz" ]]; then
    log OK "Timezone já é $tz"
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] timedatectl set-timezone $tz"
    return 0
  fi
  timedatectl set-timezone "$tz"
  log OK "Timezone definido: $tz"
}

force_chrony_sync() {
  systemctl enable chronyd >/dev/null 2>&1 || true
  systemctl restart chronyd >/dev/null 2>&1 || service chronyd restart >/dev/null 2>&1 || true
  # Aguarda fontes / força passo
  sleep 2
  chronyc -a 'burst 4/4' >/dev/null 2>&1 || true
  chronyc -a makestep >/dev/null 2>&1 || true
  # até ~20s para sync
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if time_is_synchronized; then
      return 0
    fi
    sleep 2
    chronyc -a makestep >/dev/null 2>&1 || true
  done
  return 1
}

harden_time_sync() {
  log INFO "Ajustando relógio/NTP (necessário para OTP)..."
  if [[ "$(time_conf_get ENSURE_CHRONY 1)" != "1" ]]; then
    log INFO "ENSURE_CHRONY=0 — pulando"
    return 0
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] instalaria/habilitaria chrony, fallbacks NTP e sync"
    apply_timezone_if_configured || true
    return 0
  fi

  apply_timezone_if_configured || true
  ensure_chrony_package || return 1

  # Se já sincronizado e tem pool público, só garante serviço
  if time_is_synchronized && chrony_has_usable_public_pool; then
    systemctl enable --now chronyd >/dev/null 2>&1 || true
    log OK "NTP já sincronizado"
    return 0
  fi

  # Sem sync (ou só NTP interno morto) → adiciona fallbacks públicos
  if ! time_is_synchronized; then
    log WARN "NTP não sincronizado — aplicando fallbacks públicos e forçando sync"
    chrony_append_fallback_pools
  elif ! chrony_has_usable_public_pool; then
    log INFO "Sincronizado, mas sem pool público — adicionando fallbacks preventivos"
    chrony_append_fallback_pools
  fi

  if force_chrony_sync; then
    log OK "Relógio sincronizado: $(date -R)"
    return 0
  fi

  log ERROR "Falha ao sincronizar NTP. Verifique firewall UDP/123 e chronyc sources."
  log ERROR "OTP/TOTP pode continuar inválido até a hora estar correta."
  chronyc sources 2>/dev/null | head -20 | while read -r l; do log INFO "chrony: $l"; done || true
  return 1
}

verify_time() {
  if time_is_synchronized; then
    log OK "NTP sincronizado ($(date -Iseconds))"
    return 0
  fi
  log ERROR "VERIFY FAIL: relógio não sincronizado com NTP (OTP quebrará)"
  return 1
}

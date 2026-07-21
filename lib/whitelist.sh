#!/usr/bin/env bash
# Coleta whitelist Issabel + IPs extras + redes privadas para restrição Apache

# Redes locais sempre liberadas (RFC1918 + link-local + loopback)
PRIVATE_NETWORKS=(
  "127.0.0.1"
  "::1"
  "10.0.0.0/8"
  "172.16.0.0/12"
  "192.168.0.0/16"
)

collect_whitelist_ips() {
  local -a ips=()
  local ip note line net

  # sempre redes privadas / localhost
  for net in "${PRIVATE_NETWORKS[@]}"; do
    ips+=("$net")
  done

  # IP da sessão SSH atual (evita lockout do admin)
  local ssh_ip
  ssh_ip="$(current_ssh_ip)"
  if [[ -n "$ssh_ip" ]]; then
    ips+=("$ssh_ip")
  fi

  # Issabel whitelist (sqlite)
  if [[ -f "$IPTABLES_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
    while IFS='|' read -r ip note; do
      if is_ipv4_or_cidr "$ip"; then
        ips+=("$ip")
      fi
    done < <(sqlite3 "$IPTABLES_DB" "SELECT ip_address, IFNULL(note,'') FROM whitelist;" 2>/dev/null) || true
  else
    log WARN "iptables.db/sqlite3 indisponível — whitelist Issabel não lida"
  fi

  # fail2ban ignoreip
  local f
  shopt -s nullglob
  for f in /etc/fail2ban/jail.local /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf; do
    [[ -f "$f" ]] || continue
    while read -r line; do
      [[ "$line" =~ ^ignoreip[[:space:]]*= ]] || continue
      line="${line#*=}"
      line="${line//$'\r'/}"
      for ip in $line; do
        ip="${ip//$'\r'/}"
        if is_ipv4_or_cidr "$ip" || [[ "$ip" == "127.0.0.1" ]]; then
          ips+=("$ip")
        fi
      done
    done < "$f" || true
  done
  shopt -u nullglob

  # extras do operador
  if [[ -f "$EXTRA_ALLOW_FILE" ]]; then
    while read -r ip; do
      [[ -n "$ip" && "$ip" != \#* ]] || continue
      if is_ipv4_or_cidr "$ip"; then
        ips+=("$ip")
      else
        log WARN "IP inválido em extra-allow-ips.txt: $ip"
      fi
    done < "$EXTRA_ALLOW_FILE" || true
  fi

  # unique sort
  printf '%s\n' "${ips[@]}" | awk 'NF' | sort -u
}

print_whitelist() {
  log INFO "IPs/redes liberados (UI Issabel + /admin):"
  collect_whitelist_ips | while read -r ip; do
    echo "  - $ip"
  done
}

# Adiciona IP na whitelist Issabel + extra-allow + reaplica harden
allow_ip_cli() {
  local ip="${1:-}"
  local note="${2:-isf-allow-ip $(date +%F)}"
  if ! is_ipv4_or_cidr "$ip"; then
    log ERROR "IP/CIDR inválido: $ip"
    return 1
  fi

  log INFO "Liberando $ip ($note)..."

  # 1) Issabel DB + firewall helper
  if [[ -f "$IPTABLES_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
    local exists
    exists="$(sqlite3 "$IPTABLES_DB" "SELECT COUNT(*) FROM whitelist WHERE ip_address='$ip';" 2>/dev/null || echo 0)"
    if [[ "$exists" == "0" ]]; then
      sqlite3 "$IPTABLES_DB" "INSERT INTO whitelist (ip_address, note) VALUES ('$ip', '$(echo "$note" | sed "s/'/''/g")');" 2>/dev/null \
        || log WARN "Falha ao inserir em iptables.db"
    else
      log INFO "IP já estava na whitelist Issabel"
    fi
  fi
  if command -v issabel-helper >/dev/null 2>&1; then
    issabel-helper fwconfig --add_wl "$ip" >/dev/null 2>&1 || log WARN "issabel-helper --add_wl retornou erro (pode já existir)"
  fi

  # 2) extra-allow-ips.txt (fonte do Apache)
  mkdir -p "$(dirname "$EXTRA_ALLOW_FILE")"
  touch "$EXTRA_ALLOW_FILE"
  if ! grep -qxF "$ip" "$EXTRA_ALLOW_FILE" 2>/dev/null; then
    echo "$ip" >>"$EXTRA_ALLOW_FILE"
    log OK "Adicionado a $EXTRA_ALLOW_FILE"
  fi

  # 3) reaplica harden (Apache/htaccess)
  DRY_RUN=0
  APPLY=1
  run_harden
  log OK "IP $ip liberado. Teste: curl -I https://SERVIDOR/index.php?menu=sec_whitelist"
}

# Remove IP da whitelist Issabel + extra-allow e reaplica harden (bloqueia na hora)
deny_ip_cli() {
  local ip="${1:-}"
  if ! is_ipv4_or_cidr "$ip"; then
    log ERROR "IP/CIDR inválido: $ip"
    return 1
  fi

  case "$ip" in
    10.*|192.168.*|127.*|::1|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|10.0.0.0/8|172.16.0.0/12|192.168.0.0/16)
      log WARN "Redes privadas continuam liberadas no Apache mesmo fora da whitelist Issabel."
      ;;
  esac

  log INFO "Removendo $ip da whitelist / Apache..."

  if [[ -f "$IPTABLES_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$IPTABLES_DB" "DELETE FROM whitelist WHERE ip_address='$ip';" 2>/dev/null || true
  fi
  if command -v issabel-helper >/dev/null 2>&1; then
    issabel-helper fwconfig --remove_wl "$ip" >/dev/null 2>&1 || true
  fi
  if [[ -f "$EXTRA_ALLOW_FILE" ]]; then
    grep -vxF "$ip" "$EXTRA_ALLOW_FILE" >"${EXTRA_ALLOW_FILE}.tmp" 2>/dev/null || true
    mv -f "${EXTRA_ALLOW_FILE}.tmp" "$EXTRA_ALLOW_FILE"
  fi

  DRY_RUN=0
  APPLY=1
  run_harden
  log OK "IP $ip removido da allowlist Apache (salvo se for rede privada/fail2ban ignoreip)."
}

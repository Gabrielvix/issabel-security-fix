#!/usr/bin/env bash
# shellcheck disable=SC2034
# Funções comuns — Issabel Security Fix

set -o errtrace

FIX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX_VERSION="1.5.0"
FIX_TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/issabel-security-fix/${FIX_TS}}"
LOG_FILE="${LOG_FILE:-/var/log/issabel-security-fix.log}"
QUARANTINE_DIR="${QUARANTINE_DIR:-${FIX_ROOT}/quarantine/${FIX_TS}}"

WEBROOT="${WEBROOT:-/var/www/html}"
ENGINE_PATH="${ENGINE_PATH:-/var/lib/asterisk/bin/issabelpbx_engine}"
ENGINE_URL="${ENGINE_URL:-https://raw.githubusercontent.com/IssabelFoundation/issabelPBX/master/framework/amp_conf/bin/issabelpbx_engine}"
IPTABLES_DB="${IPTABLES_DB:-/var/www/db/iptables.db}"
RC_LOCAL="${RC_LOCAL:-/etc/rc.local}"
SETUID_BIN="${SETUID_BIN:-/usr/sbin/setuid}"
STARTUP_D="${STARTUP_D:-/etc/asterisk/startup.d}"

C2_LIST="${FIX_ROOT}/conf/c2-blocklist.txt"
WEBSHELL_MD5="${FIX_ROOT}/conf/webshell-md5.txt"
WEBSHELL_NAMES="${FIX_ROOT}/conf/webshell-names.txt"
EXTRA_ALLOW_FILE="${FIX_ROOT}/conf/extra-allow-ips.txt"
UID0_KEEP_FILE="${FIX_ROOT}/conf/uid0-keep.txt"

DRY_RUN=1
APPLY=0
VERBOSE=0
FINDINGS=0
CRITICAL=0

# cores
if [[ -t 1 ]]; then
  C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
  C_BLU=$'\033[1;34m'; C_RST=$'\033[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_BLU=; C_RST=
fi

log() {
  local level="$1"; shift
  local msg="$*"
  local line="[$(date '+%F %T')] [$level] $msg"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  echo "$line" >>"$LOG_FILE" 2>/dev/null || true
  case "$level" in
    ERROR|CRITICAL) echo "${C_RED}${line}${C_RST}" >&2 ;;
    WARN)           echo "${C_YEL}${line}${C_RST}" >&2 ;;
    OK)             echo "${C_GRN}${line}${C_RST}" ;;
    INFO)           echo "${C_BLU}${line}${C_RST}" ;;
    *)              echo "$line" ;;
  esac
}

die() { log ERROR "$*"; exit 1; }

require_root() {
  [[ $EUID -eq 0 ]] || die "Execute como root (sudo)."
}

inc_finding() {
  FINDINGS=$((FINDINGS + 1))
  if [[ "${1:-}" == "critical" ]]; then
    CRITICAL=$((CRITICAL + 1))
  fi
  return 0
}

backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  mkdir -p "$BACKUP_DIR"
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest"
  log INFO "Backup: $f -> $dest"
}

quarantine_path() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  mkdir -p "$QUARANTINE_DIR"
  local base
  base="$(echo "$f" | tr '/' '_')"
  chattr -i -a "$f" 2>/dev/null || true
  mv -f "$f" "${QUARANTINE_DIR}/${base}"
  log OK "Quarentena: $f"
}

# Impede reinfecção imediata no mesmo path (visto com shells tokien/Yuki)
plant_deny_stub() {
  local f="$1"
  local dir
  dir="$(dirname "$f")"
  [[ -d "$dir" ]] || return 0
  chattr -i -a "$f" 2>/dev/null || true
  printf '<?php\nhttp_response_code(403);\nexit;\n' >"$f"
  chown asterisk:asterisk "$f" 2>/dev/null || true
  chmod 644 "$f" 2>/dev/null || true
  chattr +i "$f" 2>/dev/null || true
  log OK "Stub 403 imutável: $f"
}

is_ipv4_or_cidr() {
  local v="$1"
  [[ "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]
}

current_ssh_ip() {
  local ip=""
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    ip="${SSH_CLIENT%% *}"
  elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    ip="${SSH_CONNECTION%% *}"
  fi
  if is_ipv4_or_cidr "$ip"; then
    echo "$ip"
  fi
}

file_matches_ioc_content() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  grep -qE '212\.83\.160\.70|postroot\.sh|t3rr0r@private|useradd[[:space:]].*abort|/usr/sbin/setuid|searchshells\.sh|cmd\.txt>/tmp/a\.txt|thanku-outcall|thankuohoh' "$f" 2>/dev/null
}

# Busca por nome de webshell; exclui gravações legítimas (ex.: recordings/audio.php)
find_webshell_files_by_name() {
  local name="$1"
  find "$WEBROOT" -type f -name "$name" \
    ! -path '*/recordings/*' \
    ! -path '*/monitor/*' \
    -print0 2>/dev/null
}

# Nomes comuns demais — só trata como webshell se a assinatura bater
webshell_name_is_ambiguous() {
  case "$1" in
    configs.php|config.all.php|page.framework.php|graph.php|h.php|free.php|fa.php|italy.php|uk.php|super.php)
      return 0
      ;;
  esac
  return 1
}

should_quarantine_named_webshell() {
  local f="$1"
  local name="$2"
  if webshell_name_is_ambiguous "$name"; then
    php_looks_like_webshell "$f" && return 0
    file_matches_ioc_content "$f" && return 0
    return 1
  fi
  return 0
}

uid0_is_kept() {
  local user="$1"
  [[ "$user" == "root" ]] && return 0
  [[ -f "$UID0_KEEP_FILE" ]] || return 1
  grep -qxF "$user" "$UID0_KEEP_FILE" 2>/dev/null
}

php_looks_like_webshell() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  # Assinatura desta campanha: monta base64_decode/gzuncompress via chr() e dá eval
  if grep -qE 'chr\(98\)\.chr\(97\)\.chr\(115\)\.chr\(101\)\.chr\(54\)\.chr\(52\)' "$f" 2>/dev/null; then
    return 0
  fi
  if grep -qE '\$[A-Za-z0-9_]+\s*=\s*chr\(98\)\.chr\(97\)' "$f" 2>/dev/null \
     && grep -qE 'eval\s*\(' "$f" 2>/dev/null; then
    return 0
  fi
  # Campanha "tokien"/Yuki: shell_exec + upload com pasta yuki
  if grep -qE "session_name\(['\"]tokien['\"]\)" "$f" 2>/dev/null; then
    return 0
  fi
  if grep -qE "mkdir\(['\"]yuki['\"]\)|name=y>Yuki" "$f" 2>/dev/null \
     && grep -qE 'shell_exec\s*\(' "$f" 2>/dev/null; then
    return 0
  fi
  return 1
}

md5_of() {
  md5sum "$1" 2>/dev/null | awk '{print $1}'
}

ensure_dirs() {
  mkdir -p "$BACKUP_DIR" "$QUARANTINE_DIR" "$(dirname "$LOG_FILE")"
}

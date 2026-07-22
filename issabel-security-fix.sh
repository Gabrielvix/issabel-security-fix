#!/usr/bin/env bash
#
# issabel-security-fix.sh
# Remediação + hardening para compromisso Issabel (webshell / abort / engine / C2)
#
# Uso:
#   ./issabel-security-fix.sh --scan
#   ./issabel-security-fix.sh --fix --dry-run
#   ./issabel-security-fix.sh --fix --apply
#   ./issabel-security-fix.sh --harden --apply
#   ./issabel-security-fix.sh --all --apply
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/scan.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/remediate.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/whitelist.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/harden.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/verify.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/ssl.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/campaign.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/breakglass.sh"

usage() {
  cat <<EOF
Issabel Security Fix v${FIX_VERSION}

Uso:
  $0 --scan                 Apenas diagnostica IoCs (padrão)
  $0 --fix [--dry-run|--apply]
                            Remove malware / restaura engine / bloqueia C2
  $0 --harden [--dry-run|--apply]
                            Restringe UI Issabel + /admin + protege uploads
  $0 --allow-ip <IP> [nota] Libera IP (whitelist + Apache) — escape de lockout
  $0 --deny-ip <IP>         Remove IP da whitelist e bloqueia no Apache na hora
  $0 --fix-ssl [--dry-run|--apply]
                            Regenera Let's Encrypt (conf/ssl-domains.txt) e atualiza Apache
  $0 --expire-breakglass [--apply]
                            Remove IPs temporários break-glass expirados e re-sincroniza Apache
  $0 --enroll-totp <user>   Gera TOTP (terminal) para usuário Issabel
  $0 --enable-breakglass    Marca ENABLED=1 (usar com --harden --apply)
  $0 --disable-breakglass   Marca ENABLED=0 e restaura bloqueio Apache total
  $0 --verify               Valida limpeza (engine, persistência, upload PHP)
  $0 --all [--dry-run|--apply]
                            scan + fix + harden (+ verify se --apply)
  $0 --show-whitelist       Lista IPs/redes liberados
  $0 --help

Flags:
  --dry-run     Mostra ações sem alterar o sistema (padrão se --apply omitido)
  --apply       Aplica alterações (cria backup em ${BACKUP_DIR%/*}/)
  -v            Verbose
  --enable-breakglass / --disable-breakglass
                Opt-in do OTP break-glass (padrão = DESLIGADO = Apache fecha tudo)

Arquivos de configuração:
  conf/c2-blocklist.txt       IPs C2 para bloquear
  conf/webshell-md5.txt       MD5s de webshells conhecidas
  conf/webshell-names.txt     Nomes de arquivos suspeitos
  conf/webshell-paths.txt     Caminhos fixos de artefatos da campanha
  conf/extra-allow-ips.txt    IPs extras liberados na UI
  conf/breakglass.conf        OTP opcional (ENABLED=0 por padrão)

Camadas de mitigação (padrão):
  1) Apache: só IPs da whitelist acessam index.php, /admin, configs.php
  2) Fail2ban + firewall Issabel
  3) PHP desligado em uploads/cache
  4) Scan horário de IoCs + restore do engine limpo
  5) OPCIONAL --enable-breakglass: login+OTP para IP fora da lista; /admin segue bloqueado

Cadastro TOTP (com ou sem break-glass):
  Terminal:  isf-enroll-totp admin
  Web:       System → Users → editar usuário → seção TOTP

Escape se ficou fora da whitelist:
  $0 --allow-ip SEU.IP.PUBLICO

IMPORTANTE:
  1) Rode --scan e --fix --dry-run primeiro.
  2) Bloqueie o C2 no firewall perimetral se possível.
  3) Após --harden --apply, teste /index.php e /admin do IP liberado.
  4) Se usar --enable-breakglass: enroll TOTP ANTES (web ou terminal).
  5) Troque senhas (root, Issabel, DB, SIP) e revise usuários UID 0.
EOF
}

DO_SCAN=0
DO_FIX=0
DO_HARDEN=0
DO_VERIFY=0
DO_SSL=0
DO_SHOW_WL=0
DO_ALLOW_IP=""
DO_DENY_IP=""
DO_EXPIRE_BG=0
DO_ENROLL_USER=""
DO_BG_ENABLE=""
ALLOW_NOTE=""
MODE_SET=0

parse_args() {
  if [[ $# -eq 0 ]]; then
    DO_SCAN=1
    return
  fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scan) DO_SCAN=1; MODE_SET=1; shift ;;
      --fix) DO_FIX=1; MODE_SET=1; shift ;;
      --harden) DO_HARDEN=1; MODE_SET=1; shift ;;
      --verify) DO_VERIFY=1; MODE_SET=1; shift ;;
      --fix-ssl) DO_SSL=1; MODE_SET=1; shift ;;
      --expire-breakglass) DO_EXPIRE_BG=1; MODE_SET=1; shift ;;
      --enable-breakglass) DO_BG_ENABLE=1; MODE_SET=1; shift ;;
      --disable-breakglass) DO_BG_ENABLE=0; MODE_SET=1; shift ;;
      --enroll-totp)
        MODE_SET=1
        shift
        DO_ENROLL_USER="${1:-}"
        shift || true
        ;;
      --all) DO_FIX=1; DO_HARDEN=1; DO_SCAN=1; DO_VERIFY=1; DO_SSL=1; MODE_SET=1; shift ;;
      --show-whitelist) DO_SHOW_WL=1; MODE_SET=1; shift ;;
      --allow-ip)
        MODE_SET=1
        shift
        DO_ALLOW_IP="${1:-}"
        shift || true
        if [[ $# -gt 0 && "$1" != --* ]]; then
          ALLOW_NOTE="$1"
          shift
        fi
        ;;
      --deny-ip)
        MODE_SET=1
        shift
        DO_DENY_IP="${1:-}"
        shift || true
        ;;
      --dry-run) DRY_RUN=1; APPLY=0; shift ;;
      --apply) DRY_RUN=0; APPLY=1; shift ;;
      -v|--verbose) VERBOSE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Opção desconhecida: $1"; usage; exit 1 ;;
    esac
  done
  [[ $MODE_SET -eq 1 ]] || DO_SCAN=1
}

main() {
  parse_args "$@"
  require_root
  ensure_dirs

  log INFO "Issabel Security Fix v${FIX_VERSION} | host=$(hostname) | dry-run=$DRY_RUN"

  if [[ -n "$DO_BG_ENABLE" ]]; then
    set_breakglass_enabled "$DO_BG_ENABLE"
    # Se só passou --enable/--disable sem harden, aplica harden automaticamente com --apply
    if [[ $DO_HARDEN -eq 0 && $DO_FIX -eq 0 && $DO_SCAN -eq 0 && $DO_VERIFY -eq 0 && $DO_EXPIRE_BG -eq 0 && -z "$DO_ENROLL_USER" ]]; then
      DO_HARDEN=1
      if [[ $APPLY -eq 0 && $DRY_RUN -eq 1 ]]; then
        # se veio só --enable-breakglass, aplica de verdade
        DRY_RUN=0
        APPLY=1
      fi
    fi
  fi

  if [[ -n "$DO_ENROLL_USER" ]]; then
    enroll_totp_user "$DO_ENROLL_USER"
    exit $?
  fi

  if [[ -n "$DO_ALLOW_IP" ]]; then
    DRY_RUN=0
    APPLY=1
    allow_ip_cli "$DO_ALLOW_IP" "${ALLOW_NOTE:-isf-allow-ip $(date +%F)}"
    exit 0
  fi

  if [[ -n "$DO_DENY_IP" ]]; then
    DRY_RUN=0
    APPLY=1
    deny_ip_cli "$DO_DENY_IP"
    exit 0
  fi

  if [[ $DO_SHOW_WL -eq 1 ]]; then
    print_whitelist
    exit 0
  fi

  if [[ $DO_EXPIRE_BG -eq 1 ]]; then
    if [[ $APPLY -eq 0 ]]; then
      log WARN "expire-breakglass em dry-run. Use --apply para remover IPs expirados."
    fi
    expire_breakglass_whitelist
    exit 0
  fi

  if [[ $DO_SCAN -eq 1 ]]; then
    run_scan
  fi

  if [[ $DO_FIX -eq 1 ]]; then
    if [[ $APPLY -eq 0 ]]; then
      log WARN "Modo dry-run: nenhuma alteração permanente. Use --apply para executar."
    else
      log WARN "APPLY ativo: alterações serão gravadas. Backup em $BACKUP_DIR"
    fi
    run_remediate
  fi

  if [[ $DO_SSL -eq 1 ]]; then
    if [[ $APPLY -eq 0 ]]; then
      log WARN "SSL em dry-run. Use --apply para emitir/renovar certificado."
    fi
    run_fix_ssl || log WARN "SSL nao concluido — servidor pode ficar com cert invalido"
  fi

  if [[ $DO_HARDEN -eq 1 ]]; then
    if [[ $APPLY -eq 0 ]]; then
      log WARN "Hardening em dry-run. Use --apply para gravar htaccess/apache."
    fi
    run_harden
  fi

  if [[ $DO_SCAN -eq 1 && $DO_FIX -eq 1 && $APPLY -eq 1 ]]; then
    log INFO "Re-scan pós-remediação..."
    run_scan
    if [[ $CRITICAL -gt 0 ]]; then
      log ERROR "Ainda há $CRITICAL achados críticos — revise o log."
      exit 2
    fi
    log OK "Re-scan limpo de críticos."
  fi

  if [[ $DO_VERIFY -eq 1 ]]; then
    if [[ $APPLY -eq 1 || $DO_FIX -eq 0 ]]; then
      run_verify || exit 3
    else
      log INFO "Verify pulado em dry-run de --all (use --verify após --apply)"
    fi
  fi

  exit 0
}

main "$@"

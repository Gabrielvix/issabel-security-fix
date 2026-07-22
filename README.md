# Issabel Security Fix

Script de **remediação** e **hardening** para servidores Issabel comprometidos pela campanha de webshell + backdoor `abort` + infecção do `issabelpbx_engine` (C2 `212.83.160.70`).

> Não substitui rebuild completo em incidentes graves. Use como contenção rápida + endurecimento, depois audite e troque credenciais.

## O que corrige

| Persistência | Ação |
|---|---|
| `/var/lib/asterisk/bin/issabelpbx_engine` infectado | Quarentena + restore do engine oficial IssabelFoundation |
| `/etc/rc.local` com `curl \| bash` | Remove IoCs |
| Crontabs root/asterisk (postroot / cmd.txt) | Limpa linhas maliciosas |
| Usuário `abort` / outros UID 0 não listados em `conf/uid0-keep.txt` | Remove (mantém `root`) |
| `/usr/sbin/setuid` SUID | Quarentena |
| SSH `t3rr0r@private` | Remove da authorized_keys |
| Webshells (`Ultimatex.php`, `S!n4.php`, tokien/Yuki, MD5 conhecido, ofuscação) | Quarentena + stub 403 imutável no path |
| `/etc/asterisk/startup.d/postroot.sh` | Quarentena |
| Dialplan (`thanku-outcall`, C2 em `extensions_custom.conf`) | Remove linhas + `dialplan reload` |
| `admin/modules/freepbx_ha/license.php`, `rest_phones/ajax.php` | Quarentena (lista `conf/webshell-paths.txt`) |
| Processos `curl`/PHP ligados ao C2 | `pkill` nos padrões conhecidos |
| Crons em `/etc/crontab`, `/etc/cron.d/*`, usuário `apache` | Limpa IoCs |
| Fail2ban parado / firewall.disable | Reinicia fail2ban (socket) + `amportal firewall` + `fwconfig` |
| C2 na blocklist | `iptables` DROP |

## Hardening incluso

1. Lê a **whitelist do Issabel** em `/var/www/db/iptables.db` (módulo Security → Whitelist)
2. Une com `fail2ban ignoreip`, IP da sessão SSH atual e `conf/extra-allow-ips.txt`
3. **Sempre libera redes locais:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, localhost
4. Restringe por IP:
   - `/admin` (FreePBX/IssabelPBX)
   - `index.php` / `configs.php` / `rest.php` (UI Issabel: firewall, whitelist, fail2ban, etc.)
5. Drop-in Apache: `/etc/httpd/conf.d/issabel-admin-ip-restrict.conf`
6. Bloqueia execução PHP em dirs de cache/upload
7. Cron de re-scan + re-sync da whitelist
8. CLI de escape: `isf-allow-ip` / `--allow-ip`

### Liberar IP pelo terminal (se ficou bloqueado)

```bash
isf-allow-ip 203.0.113.50
# ou
/opt/issabel-security-fix/issabel-security-fix.sh --allow-ip 203.0.113.50 "VPN"
```

## Requisitos

- Root
- Issabel 4/5 (Rocky/CentOS 7–8+)
- Apache 2.4, `sqlite3`, `curl`
- Saída HTTPS para restaurar o engine (GitHub) **ou** arquivo local em `vendor/issabelpbx_engine.clean`

## Uso rápido

```bash
cd /opt/issabel-security-fix   # ou clone do repositório
chmod +x issabel-security-fix.sh

# 1) Diagnóstico
./issabel-security-fix.sh --scan

# 2) Simular limpeza
./issabel-security-fix.sh --fix --dry-run

# 3) Aplicar limpeza
./issabel-security-fix.sh --fix --apply

# 4) Ver IPs que serão liberados no /admin
./issabel-security-fix.sh --show-whitelist

# 5) Endurecer admin (htaccess + apache)
./issabel-security-fix.sh --harden --apply

# Tudo de uma vez
./issabel-security-fix.sh --all --apply
```

## Configuração

Edite antes do harden:

```text
conf/extra-allow-ips.txt   # IPs/CIDRs extras do time
conf/c2-blocklist.txt      # C2 adicionais
conf/webshell-md5.txt      # hashes conhecidos
conf/webshell-names.txt    # nomes de drop
conf/webshell-paths.txt    # caminhos fixos (ex.: license.php falsa)
```

Variáveis de ambiente:

```bash
RESTRICT_MAIN_UI=1   # restringe também /var/www/html inteiro (pode quebrar provisionamento de ramais)
INSTALL_CRONS=0      # não instala crons
WEBROOT=/var/www/html
```

## Segurança operacional (ordem recomendada)

1. Isolar o host / bloquear `212.83.160.70` no perímetro
2. `--scan` → `--fix --dry-run` → `--fix --apply`
3. Conferir que `issabelpbx_engine` voltou a ser o script legítimo
4. `--show-whitelist` e garantir que **seu IP** está na lista
5. `--harden --apply` e testar `https://servidor/admin`
6. Trocar senhas (root, painel, MySQL, SIP/AMI)
7. Conferir UID 0: só `root` (ou nomes em `conf/uid0-keep.txt`)
8. Preferir rebuild se a confiança no host for baixa

## Estrutura

```text
issabel-security-fix.sh
lib/{common,scan,remediate,whitelist,harden,campaign,verify,ssl}.sh
conf/
templates/
docs/
quarantine/          # artefatos removidos (gitignored)
```

## Limitações

- Não reverte todas as alterações possíveis de um rootkit
- Não reescreve todo o dialplan Asterisk nem audita CDR/fraude de chamadas (só remove IoCs conhecidos em `extensions_custom.conf`)
- Restore do engine depende de rede até o GitHub (ou vendor local)
- Restringir `/admin` por IP não protege SIP/AMI — mantenha firewall Issabel + Fail2ban

## Licença

GPL-2.0-or-later (alinhado ao ecossistema Issabel).

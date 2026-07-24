# Issabel Security Fix

Toolkit de **remediação** + **hardening** para servidores Issabel atingidos pela campanha de webshell + backdoor `abort` + `issabelpbx_engine` infectado (C2 `212.83.160.70`).

> Contenção rápida e endurecimento contínuo — **não substitui** rebuild completo após rootkit. Troque credenciais e audite CDR após o incidente.

**Versão atual: 1.6.0** · Repositório: [Gabrielvix/issabel-security-fix](https://github.com/Gabrielvix/issabel-security-fix)

---

## Por que este fix existe

O ataque observado não era só “um PHP malicioso”. A cadeia típica:

1. Webshell na webroot (`Ultimatex.php`, `configs.php` ofuscados, `phpversions.php`, etc.)
2. Persistência em cron / `rc.local` / `startup.d/postroot.sh` baixando `curl|bash` do C2
3. Usuário `abort` (UID 0), login Issabel `atmin`, binário `/usr/sbin/setuid`, chave SSH `t3rr0r@private`
4. **`issabelpbx_engine` trocado** — cada `amportal` reinstalava o malware
5. Dialplan fraudulento (`thanku-outcall`) e toll fraud SIP

Limpar só os PHP **não basta**. Este projeto corta C2, restaura o engine oficial, remove persistência, endurece Apache e (opcionalmente) adiciona OTP break-glass.

---

## Camadas de mitigação (o que impede reinfecção)

| Camada | O que faz | Padrão |
|--------|-----------|--------|
| **1. Apache por IP** | Só IPs da whitelist Issabel acessam a UI (`--disable-web-lock` desliga) | **Sempre ligado** no `--harden` (desligável) |
| **2. Redes locais** | Em modo clássico, libera RFC1918 + localhost (LAN) | Ligado (modo clássico) |
| **3. PHP em uploads** | Engine off + deny em `cache/`, `images/`, `tmp/`, `_cache/`, etc. | Sempre |
| **4. Fail2ban + firewall** | Reinicia fail2ban, remove `firewall.disable`, tenta `amportal firewall` | Sempre no `--fix` |
| **5. Scan horário** | Cron detecta IoCs (engine, webshells, UID 0, C2) | Sempre |
| **6. Engine limpo** | Restore do script oficial IssabelFoundation + verify pós-`amportal chown` | Sempre no `--fix` |
| **7. C2 DROP** | `iptables` INPUT/OUTPUT para IPs em `conf/c2-blocklist.txt` | Sempre |
| **9. Relógio / NTP** | chrony + fallbacks públicos (`conf/time.conf`) — OTP quebra com hora errada | No `--harden` / `--fix-time` / `--all` |

O bloqueio Apache por whitelist é a **barreira principal**. O OTP é recurso **adicional** — quem não ativar mantém o modelo “só IP liberado entra”.

---

## O que a remediação (`--fix`) remove

| Persistência / IoC | Ação |
|---|---|
| `issabelpbx_engine` infectado | Quarentena + restore oficial |
| `/etc/rc.local` com `curl\|bash` | Limpa IoCs |
| Crontabs root/asterisk/apache + `/etc/cron*` | Remove linhas C2/postroot |
| Usuário `abort` / UID 0 extras | Remove (`conf/uid0-keep.txt`) |
| Login Issabel `atmin` (e lista) | Remove de `acl.db` (`conf/acl-remove-users.txt`) |
| `/usr/sbin/setuid` | Quarentena |
| SSH `t3rr0r@private` | Remove de authorized_keys |
| Webshells (nomes, MD5, ofuscação) | Quarentena + stub 403 imutável |
| Paths fixos (`freepbx_ha/license.php`, …) | Quarentena |
| `startup.d/postroot.sh` | Quarentena |
| Dialplan `thanku-outcall` / C2 | Limpa + `dialplan reload` |
| Processos ligados ao C2 | `pkill` |
| Fail2ban / firewall.disable | Restaura defesas |
| C2 blocklist | `iptables` DROP |

---

## Uso rápido

```bash
cd /opt/issabel-security-fix   # ou: git clone …
chmod +x issabel-security-fix.sh

# 1) Diagnóstico
./issabel-security-fix.sh --scan

# 2) Limpeza (simular → aplicar)
./issabel-security-fix.sh --fix --dry-run
./issabel-security-fix.sh --fix --apply

# 3) Hardening Apache (bloqueio por IP) — SEM abrir login público
./issabel-security-fix.sh --harden --apply

# 4) (OPCIONAL) Ativar Break-glass OTP
./issabel-security-fix.sh --enable-breakglass
# equivalente:
./issabel-security-fix.sh --harden --apply --enable-breakglass

# Tudo de uma vez (fix + harden; OTP só se passar --enable-breakglass)
./issabel-security-fix.sh --all --apply
./issabel-security-fix.sh --all --apply --enable-breakglass
```

### Liberar / bloquear IP (escape de lockout)

```bash
isf-allow-ip 203.0.113.50 "VPN"
isf-deny-ip 203.0.113.50
# ou
./issabel-security-fix.sh --allow-ip 203.0.113.50 "VPN"
./issabel-security-fix.sh --show-whitelist
```

### Desativar bloqueio web por IP (cliente que não quer)

Abre `index.php` / `/admin` para qualquer IP. **Menos seguro.** Demais proteções (malware, uploads, C2, fail2ban) continuam.

```bash
./issabel-security-fix.sh --disable-web-lock
# ou
isf-disable-web-lock

# Reativar (recomendado):
./issabel-security-fix.sh --enable-web-lock
# ou
isf-enable-web-lock
```

Estado em `conf/web-lock.conf` (`ENABLED=0|1`). O `--harden` respeita essa flag.

---

## Break-glass OTP (opcional)

Documentação detalhada: [docs/BREAKGLASS.md](docs/BREAKGLASS.md) · IoCs: [docs/IOCs.md](docs/IOCs.md)

### Comportamento

| Situação | Apache | Login |
|----------|--------|-------|
| **OTP desligado** (padrão) | `index.php` + `/admin` + configs só para whitelist | Só quem já está liberado |
| **OTP ligado** | `index.php` público; **`/admin` e configs CONTINUAM bloqueados por IP** | Fora da whitelist explícita: senha + OTP → IP liberado por **10h** |

Whitelist explícita = tabela `whitelist` do Issabel (`iptables.db`) + `conf/extra-allow-ips.txt`.  
**Não** trata RFC1918 como “já confiável” para pular OTP.  
Add/remove no painel sincroniza Apache na hora (`isf-sync-apache` + sudoers); com OTP ligado, IP fora da lista **revoga sessão ativa**.

### Ativar / desativar

```bash
# Ativar (grava conf + reaplica Apache)
./issabel-security-fix.sh --enable-breakglass

# Desativar (volta bloqueio total no Apache)
./issabel-security-fix.sh --disable-breakglass
```

### Cadastrar TOTP

**Terminal:**

```bash
isf-enroll-totp admin
# ou
./issabel-security-fix.sh --enroll-totp admin
```

**Interface web (intuitivo):**  
System → Users → editar usuário → seção **Autenticação em dois fatores (TOTP)** → Gerar novo TOTP → Salvar → escanear QR no autenticador.

O QR usa automaticamente o **domínio/hostname do próprio servidor** (do cliente) + nome do usuário no Authenticator.

O plugin é instalado no `--harden` mesmo com OTP desligado, para você cadastrar tokens **antes** de ativar o break-glass.

---

#TOTP depende do relógio do servidor. No CentOS/RHEL 8 (Issabel), use o chrony:

## Ver o horário atual e se o NTP está ativo
```bash
timedatectl
date
```
## Forçar sincronização imediata (corrige drift grande)
```bash
chronyc -a makestep
systemctl enable --now chronyd
chronyc -a makestep
```
## Configuração

```text
conf/c2-blocklist.txt       # IPs C2
conf/webshell-md5.txt       # hashes conhecidos
conf/webshell-names.txt     # nomes de drop
conf/webshell-paths.txt     # caminhos fixos da campanha
conf/extra-allow-ips.txt    # IPs extras no Apache
conf/breakglass.conf        # ENABLED=0|1, TTL_HOURS=10
conf/web-lock.conf          # bloqueio Apache por IP (ENABLED=1 padrão)
conf/time.conf              # timezone opcional + pools NTP (OTP)
conf/uid0-keep.txt          # usuários UID 0 permitidos (além de root)
conf/acl-remove-users.txt   # logins Issabel (acl.db) a remover (ex.: atmin)
```

Variáveis úteis:

```bash
INSTALL_CRONS=0   # não instalar crons
WEBROOT=/var/www/html
```

---

## Ordem operacional recomendada

1. Isolar host / bloquear `212.83.160.70` no perímetro  
2. `--scan` → `--fix --dry-run` → `--fix --apply`  
3. Conferir engine limpo + `--verify`  
4. `--show-whitelist` e garantir **seu IP**  
5. `--harden --apply` (Apache fechado)  
6. (Opcional) cadastrar TOTP na web/terminal → `--enable-breakglass`  
7. Trocar senhas (root, painel, MySQL, SIP/AMI)  
8. Auditar CDR / `extensions_custom.conf`  
9. Preferir rebuild se a confiança no host for baixa  

---

## Estrutura

```text
issabel-security-fix.sh
lib/{common,scan,remediate,whitelist,harden,campaign,breakglass,verify,ssl,time}.sh
php/breakglass/          # TOTP + política + hook de login
templates/userlist-plugin-totp/   # UI System → Users
conf/
docs/
bin/isf-allow-ip  isf-deny-ip  isf-enroll-totp
quarantine/              # artefatos removidos (gitignored)
```

---

## Limitações

- Não reverte todo rootkit possível  
- Dialplan: remove IoCs conhecidos; não audita CDR automaticamente  
- Restore do engine precisa de GitHub ou `vendor/issabelpbx_engine.clean`  
- Break-glass abre só o login (`index.php`); SIP/AMI continuam responsabilidade do firewall Issabel  
- Preferir reinstalação limpa após compromisso root prolongado  

## Licença

GPL-2.0-or-later (alinhado ao ecossistema Issabel).

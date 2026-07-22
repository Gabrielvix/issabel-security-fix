# Break-glass OTP

Recurso **opcional** do Issabel Security Fix. O padrão do harden é **Apache fechado por whitelist** (máxima contenção). O OTP é um “quebra-vidro” para acesso remoto sem abrir `/admin` para a internet.

## Política

| Item | Valor |
|------|--------|
| Padrão | `ENABLED=0` — sem login público |
| Opt-in | `--enable-breakglass` |
| Quem precisa de OTP | IP ∉ whitelist explícita (`iptables.db` + `extra-allow-ips.txt`) |
| RFC1918 | **Não** isenta de OTP |
| Após OTP OK | Sessão + IP na whitelist por `TTL_HOURS` (padrão **10**) |
| `/admin` | Sempre restrito por IP Apache (mesmo com OTP ligado) |
| `index.php` | Público **somente** com OTP ligado |

## Ativar / desativar

```bash
# Ativa e reaplica Apache
./issabel-security-fix.sh --enable-breakglass

# Desativa e volta bloqueio total (index.php + /admin na whitelist)
./issabel-security-fix.sh --disable-breakglass

# Ou edite conf/breakglass.conf e:
./issabel-security-fix.sh --harden --apply
```

## Cadastrar TOTP

### Terminal

```bash
isf-enroll-totp admin
isf-enroll-totp atmin
```

Mostra secret base32 + URI `otpauth://` para Google Authenticator / FreeOTP / Authy.

### Interface web

1. Entre com um IP já na whitelist  
2. Abra **System → Users** (ex.: `index.php?menu=userlist&action=edit&id_user=1`)  
3. Na seção **Autenticação em dois fatores (TOTP)**:
   - escolha **Gerar novo TOTP**
   - **Salvar**
   - escaneie o QR exibido  
4. Repita para cada administrador  

O plugin é instalado no `--harden` mesmo com break-glass desligado — cadastre tokens **antes** de ativar.

## Fluxo remoto (OTP ligado)

1. Usuário acessa `https://servidor/` (login)  
2. Usuário + senha  
3. Código OTP do autenticador  
4. IP entra na whitelist por 10h (cron expira e re-sincroniza Apache)  

## Segurança

- Fail2ban continua essencial (login público só no modo OTP)  
- Não use break-glass sem TOTP cadastrado nos admins  
- Escape: `isf-allow-ip SEU.IP` ou SSH  
- Desative (`--disable-breakglass`) se não precisar de acesso remoto fora da lista  

# Break-glass OTP

## Política

- **Whitelist explícita** = tabela `whitelist` em `/var/www/db/iptables.db` + `conf/extra-allow-ips.txt`
- **Não** trata redes privadas (RFC1918) como confiáveis para pular OTP
- IP **fora** dessa lista → após senha correta, **OTP obrigatório**
- Após OTP OK → sessão Issabel + IP na whitelist por **10 horas** (configurável)
- Cron a cada 15 min remove entradas expiradas e re-sincroniza o Apache

## Ativar

1. Edite `conf/breakglass.conf` (`ENABLED=1`, `TTL_HOURS=10`)
2. Cadastre TOTP **antes** de sair do IP confiável:

```bash
isf-enroll-totp admin
# ou
./issabel-security-fix.sh --enroll-totp admin
```

3. Aplique harden:

```bash
./issabel-security-fix.sh --harden --apply
```

## Fluxo do usuário remoto

1. Acessa `https://servidor/` (index.php liberado no Apache)
2. Login + senha
3. Tela OTP (app autenticador)
4. IP liberado por 10h em `/admin` e demais endpoints

## Desativar

```bash
# conf/breakglass.conf
ENABLED=0
./issabel-security-fix.sh --harden --apply
```

## Segurança

- Fail2ban continua essencial (login público)
- Não cadastre TOTP só via web sem IP confiável
- Escape: `isf-allow-ip SEU.IP` ou SSH

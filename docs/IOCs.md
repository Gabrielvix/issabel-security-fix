# Notas de incidente (IoCs)

Campanha observada em Issabel/FreePBX-like:

## Indicadores

- C2: `212.83.160.70` (`/r/postroot.sh`, `/t/cmd.txt`, `/r/setuid`, `/r/searchshells.sh`)
- Usuário: `abort` UID 0, home `/dev/null`
- SSH comment: `t3rr0r@private`
- Binário: `/usr/sbin/setuid` (SUID → `/bin/sh`)
- Engine: `/var/lib/asterisk/bin/issabelpbx_engine` substituído
- Webshells: `Ultimatex.php`, `S!n4.php` (MD5 `0e906981a2dc04515baa9ac106c2d93c`)
- Crons: `curl -ks http://212.83.160.70/...`

## Por que o engine é crítico

`amportal` e módulos Issabel invocam `issabelpbx_engine`. O malware recria cron, `rc.local`, usuário, SSH e webshells a cada execução — limpar só PHP não basta.

## Pós-incidente

- Auditar CDR / destinos internacionais
- Rotacionar segredos
- Considerar reinstalação limpa + restore de backup de configuração

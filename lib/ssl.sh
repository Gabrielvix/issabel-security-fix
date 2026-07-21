#!/usr/bin/env bash
# Regeneracao Let's Encrypt + ajuste Apache SSL — Issabel Security Fix
# Dominios: conf/ssl-domains.txt OU autodetect (Apache / Let's Encrypt / hostname)

SSL_DOMAINS_FILE="${FIX_ROOT}/conf/ssl-domains.txt"
SSL_CERT_NAME="${SSL_CERT_NAME:-}"
SSL_CONF="${SSL_CONF:-/etc/httpd/conf.d/ssl.conf}"

# Retorna 1 se a linha e placeholder/exemplo (nao usar em producao)
ssl_is_placeholder() {
  local d="$1"
  [[ "$d" =~ exemplo|example\.com|example\.org|SEU_DOMINIO|yourdomain|localhost ]]
}

ssl_domains_from_file() {
  local d
  [[ -f "$SSL_DOMAINS_FILE" ]] || return 0
  while read -r d; do
    [[ -n "$d" && "$d" != \#* ]] || continue
    ssl_is_placeholder "$d" && continue
    echo "$d"
  done < "$SSL_DOMAINS_FILE" || true
}

ssl_domains_from_apache() {
  local d
  [[ -f "$SSL_CONF" ]] || return 0
  grep -E '^[[:space:]]*ServerName[[:space:]]+' "$SSL_CONF" 2>/dev/null \
    | awk '{print $2}' | sed 's/:.*//' || true
  grep -E '^[[:space:]]*ServerAlias[[:space:]]+' "$SSL_CONF" 2>/dev/null \
    | awk '{$1=""; print $0}' | tr ' ' '\n' | grep -v '^$' | sed 's/:.*//' || true
}

ssl_domains_from_letsencrypt() {
  local dir name
  [[ -d /etc/letsencrypt/live ]] || return 0
  for dir in /etc/letsencrypt/live/*/; do
    [[ -d "$dir" ]] || continue
    name="$(basename "$dir")"
    [[ "$name" == README ]] && continue
    echo "$name"
    # SANs do certificado atual
    if [[ -f "${dir}/cert.pem" ]]; then
      openssl x509 -in "${dir}/cert.pem" -noout -ext subjectAltName 2>/dev/null \
        | grep -oE 'DNS:[^, ]+' | sed 's/^DNS://' || true
    fi
  done
}

ssl_domains_list() {
  local -a domains=()
  local d
  # 1) arquivo do operador (se preenchido com dominios reais)
  while read -r d; do
    [[ -n "$d" ]] && domains+=("$d")
  done < <(ssl_domains_from_file)

  # 2) se vazio: autodetect Apache + LE + hostname
  if [[ ${#domains[@]} -eq 0 ]]; then
    while read -r d; do
      [[ -n "$d" ]] || continue
      ssl_is_placeholder "$d" && continue
      domains+=("$d")
    done < <( { ssl_domains_from_apache; ssl_domains_from_letsencrypt; hostname -f 2>/dev/null; hostname; } | awk 'NF')
  fi

  printf '%s\n' "${domains[@]}" | awk 'NF && $0 !~ /^#/' | sort -u
}

ssl_primary_domain() {
  ssl_domains_list | head -1
}

ssl_privkey_ok() {
  local name="$1"
  local key="/etc/letsencrypt/live/${name}/privkey.pem"
  local cert="/etc/letsencrypt/live/${name}/cert.pem"
  [[ -f "$key" && -f "$cert" ]] || return 1
  local m1 m2
  m1="$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5 2>/dev/null)"
  m2="$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5 2>/dev/null)"
  [[ -n "$m1" && "$m1" == "$m2" ]]
}

update_apache_ssl_paths() {
  local name="$1"
  local full="/etc/letsencrypt/live/${name}/fullchain.pem"
  local key="/etc/letsencrypt/live/${name}/privkey.pem"
  [[ -f "$full" && -f "$key" ]] || return 1
  [[ -f "$SSL_CONF" ]] || return 1

  backup_file "$SSL_CONF"
  sed -i -E "s|^SSLCertificateFile[[:space:]].*|SSLCertificateFile ${full}|" "$SSL_CONF"
  sed -i -E "s|^SSLCertificateKeyFile[[:space:]].*|SSLCertificateKeyFile ${key}|" "$SSL_CONF"

  local primary
  primary="$(ssl_primary_domain)"
  [[ -n "$primary" ]] || primary="$name"

  if ! grep -qE "^ServerName[[:space:]]+" "$SSL_CONF"; then
    sed -i "/<VirtualHost/a ServerName ${primary}" "$SSL_CONF"
  else
    sed -i -E "s|^ServerName[[:space:]].*|ServerName ${primary}|" "$SSL_CONF"
  fi

  local d
  while read -r d; do
    [[ -n "$d" && "$d" != "$primary" ]] || continue
    if ! grep -qE "ServerAlias.*[[:space:]]${d}([[:space:]]|$)" "$SSL_CONF" \
       && ! grep -qE "^ServerAlias[[:space:]]+${d}$" "$SSL_CONF"; then
      if grep -qE '^ServerAlias[[:space:]]+' "$SSL_CONF"; then
        sed -i -E "s|^(ServerAlias[[:space:]].*)|\1 ${d}|" "$SSL_CONF"
      else
        sed -i "/^ServerName[[:space:]]/a ServerAlias ${d}" "$SSL_CONF"
      fi
    fi
  done < <(ssl_domains_list)

  if apachectl configtest >/dev/null 2>&1; then
    systemctl reload httpd >/dev/null 2>&1 || true
    log OK "Apache SSL apontando para /etc/letsencrypt/live/${name}/"
  else
    log ERROR "ssl.conf invalido apos update — revise $SSL_CONF"
    return 1
  fi
}

run_fix_ssl() {
  log INFO "=== SSL / Let's Encrypt ==="
  if ! command -v certbot >/dev/null 2>&1; then
    log ERROR "certbot nao instalado — instale: dnf install certbot python3-certbot-apache"
    return 1
  fi

  local -a domains=()
  local d args=() name
  while read -r d; do
    [[ -n "$d" ]] || continue
    domains+=("$d")
    args+=("-d" "$d")
  done < <(ssl_domains_list)

  if [[ ${#domains[@]} -eq 0 ]]; then
    log ERROR "Nenhum dominio detectado. Preencha conf/ssl-domains.txt com os dominios do cliente."
    return 1
  fi

  name="${SSL_CERT_NAME:-${domains[0]}}"
  if [[ ! -s "$SSL_DOMAINS_FILE" ]] || ! grep -qvE '^[[:space:]]*(#|$)' "$SSL_DOMAINS_FILE" 2>/dev/null; then
    log INFO "ssl-domains.txt vazio — usando autodetect (Apache/LE/hostname)"
  fi
  log INFO "Dominios para o certificado: ${#domains[@]} (cert-name oculto no log; veja conf/ssl-domains ou Apache)"


  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "[dry-run] certbot certonly --apache --expand (${#domains[@]} dominio(s))"
    log INFO "[dry-run] atualizaria $SSL_CONF para o fullchain/privkey emitidos"
    return 0
  fi

  if certbot certonly --apache \
      "${args[@]}" \
      --cert-name "$name" \
      --non-interactive --agree-tos --expand \
      --register-unsafely-without-email \
      --keep-until-expiring 2>&1 | tee /tmp/isf-certbot.log; then
    log OK "Certificado Let's Encrypt OK"
  else
    log ERROR "certbot falhou — veja /tmp/isf-certbot.log"
    return 1
  fi

  if ! ssl_privkey_ok "$name"; then
    log ERROR "privkey/cert nao batem apos emissao"
    return 1
  fi

  update_apache_ssl_paths "$name"
  log OK "=== SSL concluido ==="
}

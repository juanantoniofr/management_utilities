#!/usr/bin/env bash
set -euo pipefail

# Genera cert.pem y key.pem autofirmados para el DHCP Observer.
# Uso:
#   ./generate_certs.sh
#   ./generate_certs.sh --force
#   ./generate_certs.sh --ip 192.168.1.10
#
# Variables opcionales:
#   DHCP_SSL_CERT, DHCP_SSL_KEY, DHCP_CERT_CN, DHCP_CERT_IP, DHCP_CERT_DNS

FORCE=0
EXTRA_IP=""
EXTRA_DNS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    --ip)
      EXTRA_IP="${2:-}"
      shift 2
      ;;
    --dns)
      EXTRA_DNS="${2:-}"
      shift 2
      ;;
    -h|--help)
      sed -n '1,80p' "$0"
      exit 0
      ;;
    *)
      echo "Argumento no reconocido: $1" >&2
      exit 2
      ;;
  esac
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_PATH="${DHCP_SSL_CERT:-$DIR/cert.pem}"
KEY_PATH="${DHCP_SSL_KEY:-$DIR/key.pem}"
CN="${DHCP_CERT_CN:-localhost}"

# Permite pasar IP/DNS extra vía env o flags
if [[ -z "$EXTRA_IP" ]]; then
  EXTRA_IP="${DHCP_CERT_IP:-}"
fi
if [[ -z "$EXTRA_DNS" ]]; then
  EXTRA_DNS="${DHCP_CERT_DNS:-}"
fi

if [[ $FORCE -ne 1 ]]; then
  if [[ -e "$CERT_PATH" || -e "$KEY_PATH" ]]; then
    echo "Ya existen $CERT_PATH o $KEY_PATH. Usa --force para regenerar." >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")"

SAN="DNS:localhost,IP:127.0.0.1"
if [[ -n "$EXTRA_DNS" ]]; then
  SAN+=" ,DNS:$EXTRA_DNS"
fi
if [[ -n "$EXTRA_IP" ]]; then
  SAN+=",IP:$EXTRA_IP"
fi

# Normalizar: quitar espacios accidentales
SAN="${SAN// /}"

DAYS=1460

if openssl req -help 2>&1 | grep -q -- '-addext'; then
  openssl req \
    -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_PATH" \
    -out "$CERT_PATH" \
    -days "$DAYS" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=$SAN"
else
  TMP_CONF="$(mktemp)"
  cat > "$TMP_CONF" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[ dn ]
CN = $CN

[ v3_req ]
subjectAltName = $SAN
EOF
  openssl req \
    -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_PATH" \
    -out "$CERT_PATH" \
    -days "$DAYS" \
    -config "$TMP_CONF"
  rm -f "$TMP_CONF"
fi

chmod 600 "$KEY_PATH"
chmod 644 "$CERT_PATH"

echo "OK: generado $CERT_PATH y $KEY_PATH"
echo "SAN: $SAN"

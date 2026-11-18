#!/usr/bin/env bash
# Change log:
#   Wed Nov 18 14:30 CET 2026 - Initial version: local demo CA, proxy server cert, client cert (mTLS)
#   Wed Nov 18 14:57 CET 2026 - Added classical RSA-2048 certificate for the mock legacy TLS devices (issued in place if missing)
#
# Generates a LOCAL DEMO PKI (self-signed CA, proxy server cert, control-center client cert).
# Short-lived (30 days). Existing certs are kept unless expiring within 7 days or --force is used;
# on regeneration the old set is moved to certs.bak-<timestamp> (rollback option).
# Works in bash and zsh on macOS/Linux.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${QSP_CERT_DIR:-$ROOT/certs}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
FORCE="${1:-}"
DAYS=30

# Return 0 when a valid, non-expiring certificate set already exists - Wed Nov 18 14:30 CET 2026
certs_ok() {
  [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/server.pem" ] && [ -f "$CERT_DIR/client.pem" ] &&
    "$OPENSSL_BIN" x509 -in "$CERT_DIR/server.pem" -noout -checkend 604800 >/dev/null 2>&1 &&
    { [ ! -f "$CERT_DIR/legacy.pem" ] || "$OPENSSL_BIN" x509 -in "$CERT_DIR/legacy.pem" -noout -checkend 604800 >/dev/null 2>&1; }
}

# Issue the classical RSA-2048 server certificate of the mock legacy TLS devices (cwd = cert dir) - Wed Nov 18 14:57 CET 2026
issue_legacy() {
  cat > legacy.ext <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
EOF
  "$OPENSSL_BIN" req -newkey rsa:2048 -nodes -keyout legacy.key -out legacy.csr \
    -subj "/O=QSP Demo Legacy OT/CN=localhost" 2>/dev/null
  "$OPENSSL_BIN" x509 -req -in legacy.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out legacy.pem \
    -days "$DAYS" -sha256 -extfile legacy.ext 2>/dev/null
  rm -f legacy.csr legacy.ext ca.srl
  chmod 600 legacy.key
}

if [ "$FORCE" != "--force" ] && certs_ok; then
  if [ ! -f "$CERT_DIR/legacy.pem" ]; then
    (cd "$CERT_DIR" && umask 077 && issue_legacy)
    echo "[certs] legacy device certificate added to the existing PKI"
  else
    echo "[certs] existing demo certificates are valid - nothing to do (use --force to regenerate)"
  fi
  exit 0
fi

if [ -d "$CERT_DIR" ] && [ -n "$(ls -A "$CERT_DIR" 2>/dev/null)" ]; then
  BAK="${CERT_DIR}.bak-$(date +%Y%m%d%H%M%S)"
  mv "$CERT_DIR" "$BAK"
  echo "[certs] previous certificates moved to $BAK"
fi
mkdir -p "$CERT_DIR"
umask 077
cd "$CERT_DIR"

# Local CA (P-384)
"$OPENSSL_BIN" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout ca.key -out ca.pem \
  -subj "/O=QSP Demo/CN=QSP Demo Local CA" -days "$DAYS" 2>/dev/null

# Server certificate for the proxy listeners (127.0.0.1 / localhost)
cat > server.ext <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
keyUsage=digitalSignature
EOF
"$OPENSSL_BIN" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr \
  -subj "/O=QSP Demo/CN=localhost" 2>/dev/null
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem \
  -days "$DAYS" -extfile server.ext 2>/dev/null

# Client certificate for the SCADA control centre / verifier (mutual TLS)
cat > client.ext <<EOF
extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE
keyUsage=digitalSignature
EOF
"$OPENSSL_BIN" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout client.key -out client.csr \
  -subj "/O=QSP Demo/CN=scada-control-centre" 2>/dev/null
"$OPENSSL_BIN" x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem \
  -days "$DAYS" -extfile client.ext 2>/dev/null

rm -f server.csr client.csr server.ext client.ext ca.srl

# Classical RSA-2048 certificate for the mock legacy TLS devices
issue_legacy
chmod 600 ./*.key
echo "[certs] demo PKI generated in $CERT_DIR (valid $DAYS days)"

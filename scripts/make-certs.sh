#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# scripts/make-certs
# Creates (or reuses) a CA, then issues server & client certs
# using ../keys/tls/san.cnf as the source SAN config.
# Usage: ./scripts/make-certs
#
# Idempotency:
#   - If ../keys/tls/ca.crt and ../keys/tls/ca.key exist, CA is reused.
#   - Server/client certs are regenerated each run (safe).
#   - Pass FORCE_CA=1 to rebuild the CA anyway.
# -------------------------------------------------------------------

# Resolve paths relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../etc/keys/tls"
SAN_SRC="${OUT_DIR}/san.cnf"
FIXED_SAN="${OUT_DIR}/san.fixed.cnf"
CLIENT_EXT="${OUT_DIR}/client_ext.cnf"

# Lifetimes
DAYS_CA=3650      # ~10 years
DAYS_LEAF=825     # reasonable browser-ish max

# CA subject
CA_SUBJ="/C=US/ST=California/L=Los Angeles/O=YourOrg/CN=YourOrg-Dev-CA"

echo "==> Output dir: ${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# Check input SAN
if [[ ! -f "${SAN_SRC}" ]]; then
  echo "ERROR: ${SAN_SRC} not found."
  echo "Create it first (edit SANs there), then re-run this script."
  exit 1
fi

echo "==> Using SAN config: ${SAN_SRC}"

# --- Produce a leaf-safe version of your SAN config -----------------
# - Fix invalid 'typesName' -> 'commonName'
# - Force leaf basicConstraints to CA:false
# - Keep your alt_names as-is
sed -E \
  -e 's/^[[:space:]]*typesName[[:space:]]*=/commonName =/g' \
  -e 's/^[[:space:]]*basicConstraints[[:space:]]*=.*$/basicConstraints = CA:false/g' \
  "${SAN_SRC}" > "${FIXED_SAN}"

echo "==> Wrote fixed leaf SAN config: ${FIXED_SAN}"

# Safety check: fail if typesName still present
if grep -q '^[[:space:]]*typesName[[:space:]]*=' "${FIXED_SAN}"; then
  echo "ERROR: 'typesName' still present in ${FIXED_SAN}. Please correct to 'commonName =' and retry."
  exit 1
fi

# --- Client EKU extension (clientAuth) ------------------------------
cat > "${CLIENT_EXT}" <<'EOF'
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
echo "==> Wrote client EKU ext: ${CLIENT_EXT}"

# --- Generate or reuse CA ------------------------------------------
if [[ "${FORCE_CA:-0}" == "1" ]]; then
  echo "==> FORCE_CA=1 set; rebuilding CA..."
  rm -f "${OUT_DIR}/ca.key" "${OUT_DIR}/ca.crt" "${OUT_DIR}/ca.srl" || true
fi

if [[ -f "${OUT_DIR}/ca.key" && -f "${OUT_DIR}/ca.crt" ]]; then
  echo "==> Reusing existing CA: ${OUT_DIR}/ca.crt"
else
  echo "==> Generating new CA..."
  openssl genrsa -out "${OUT_DIR}/ca.key" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes \
    -key "${OUT_DIR}/ca.key" \
    -sha256 -days "${DAYS_CA}" \
    -subj "${CA_SUBJ}" \
    -out "${OUT_DIR}/ca.crt"
  echo "==> CA created: ${OUT_DIR}/ca.crt"
fi

# --- Server cert (TLS for Hermes/Damocles frontends) ----------------
echo "==> Generating server key/csr/cert..."
openssl genrsa -out "${OUT_DIR}/server.key" 2048 >/dev/null 2>&1

# Use your fixed SAN config for CSR (commonName + subjectAltName, EKUs, etc.)
openssl req -new \
  -key "${OUT_DIR}/server.key" \
  -out "${OUT_DIR}/server.csr" \
  -config "${FIXED_SAN}"

openssl x509 -req \
  -in "${OUT_DIR}/server.csr" \
  -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" -CAcreateserial \
  -out "${OUT_DIR}/server.crt" \
  -days "${DAYS_LEAF}" -sha256 \
  -extfile "${FIXED_SAN}" -extensions v3_req

echo "==> Server cert created: ${OUT_DIR}/server.crt"

# --- Client cert (mTLS client for ForwardRelay) ---------------------
echo "==> Generating client key/csr/cert..."
openssl genrsa -out "${OUT_DIR}/client.key" 2048 >/dev/null 2>&1

# Minimal CSR; CN not critical for client auth
openssl req -new \
  -key "${OUT_DIR}/client.key" \
  -subj "/C=US/ST=California/L=Los Angeles/O=YourOrg/CN=hermes-client" \
  -out "${OUT_DIR}/client.csr"

openssl x509 -req \
  -in "${OUT_DIR}/client.csr" \
  -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" -CAcreateserial \
  -out "${OUT_DIR}/client.crt" \
  -days "${DAYS_LEAF}" -sha256 \
  -extfile "${CLIENT_EXT}"

echo "==> Client cert created: ${OUT_DIR}/client.crt"

# --- Summarize ------------------------------------------------------
echo
echo "✅ Done. Files in ${OUT_DIR}:"
ls -1 "${OUT_DIR}" | sed 's/^/  - /'
echo
echo "Next steps:"
echo "  • Hermes frontend TLS:"
echo "      SSL_SERVER_CERTIFICATE=${OUT_DIR}/server.crt"
echo "      SSL_SERVER_KEY=${OUT_DIR}/server.key"
echo "  • Electrician mTLS to receivers:"
echo "      ELECTRICIAN_TLS_CLIENT_CRT=${OUT_DIR}/client.crt"
echo "      ELECTRICIAN_TLS_CLIENT_KEY=${OUT_DIR}/client.key"
echo "      ELECTRICIAN_TLS_CA=${OUT_DIR}/ca.crt"
echo
echo "Tip: Edit ${SAN_SRC} (add DNS names like 'damocles', 'localhost', etc.) and re-run this script."
echo "     To force a new CA (rotates trust), run: FORCE_CA=1 ./scripts/make-certs"

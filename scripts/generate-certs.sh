#!/bin/bash
# APEX-KV mTLS Certificate Generation Script
# This script generates CA and node certificates for mutual TLS authentication

set -e

CERT_DIR="${1:-./certs}"
NUM_NODES="${2:-3}"
VALIDITY_DAYS="${3:-365}"

echo "=== APEX-KV mTLS Certificate Generator ==="
echo "Certificate directory: $CERT_DIR"
echo "Number of nodes: $NUM_NODES"
echo "Validity: $VALIDITY_DAYS days"
echo

# Create certificate directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA private key and certificate
echo "[1/$(($NUM_NODES + 2))] Generating CA private key..."
openssl genrsa -out ca.key 4096

echo "[2/$(($NUM_NODES + 2))] Generating CA certificate..."
openssl req -new -x509 -days $VALIDITY_DAYS \
    -key ca.key \
    -out ca.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=APEX-KV/OU=Cluster/CN=APEX-KV Root CA"

echo "[3/$(($NUM_NODES + 2))] Creating OpenSSL configuration..."
cat > openssl.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = APEX-KV
OU = Nodes

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate certificates for each node
for i in $(seq 1 $NUM_NODES); do
    NODE_NAME="node$i"
    echo "[$(($i + 2))/$(($NUM_NODES + 2))] Generating certificate for $NODE_NAME..."
    
    # Generate node private key
    openssl genrsa -out ${NODE_NAME}.key 2048
    
    # Update SAN with node-specific IPs
    cat > ${NODE_NAME}.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = APEX-KV
OU = Nodes
CN = $NODE_NAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $NODE_NAME
DNS.3 = ${NODE_NAME}.apex-kv.local
IP.1 = 127.0.0.1
IP.2 = 192.168.1.$((10 + $i))
IP.3 = 10.0.0.$((10 + $i))
EOF
    
    # Generate CSR
    openssl req -new \
        -key ${NODE_NAME}.key \
        -out ${NODE_NAME}.csr \
        -config ${NODE_NAME}.cnf
    
    # Sign certificate with CA
    openssl x509 -req \
        -days $VALIDITY_DAYS \
        -in ${NODE_NAME}.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out ${NODE_NAME}.crt \
        -extensions v3_req \
        -extfile ${NODE_NAME}.cnf
    
    # Verify certificate
    openssl verify -CAfile ca.crt ${NODE_NAME}.crt > /dev/null && \
        echo "  ✓ Certificate verified for $NODE_NAME" || \
        echo "  ✗ Certificate verification failed for $NODE_NAME"
done

# Generate PKCS#12 bundle for each node (optional, for clients)
echo "[$(($NUM_NODES + 3))/$(($NUM_NODES + 4))] Generating PKCS#12 bundles..."
for i in $(seq 1 $NUM_NODES); do
    NODE_NAME="node$i"
    openssl pkcs12 -export \
        -out ${NODE_NAME}.p12 \
        -inkey ${NODE_NAME}.key \
        -in ${NODE_NAME}.crt \
        -certfile ca.crt \
        -passout pass: \
        -password pass:
done

# Set proper permissions
echo "[$(($NUM_NODES + 4))/$(($NUM_NODES + 4))] Setting permissions..."
chmod 600 *.key
chmod 644 *.crt
chmod 644 ca.*

# Display summary
echo
echo "=== Certificate Generation Complete ==="
echo
echo "Generated files in $CERT_DIR:"
ls -la
echo
echo "CA Certificate:"
openssl x509 -in ca.crt -noout -subject -dates
echo
echo "To use these certificates in APEX-KV configuration:"
echo "  tls:"
echo "    enabled: true"
echo "    cert_path: \"$CERT_DIR/node1.crt\""
echo "    key_path: \"$CERT_DIR/node1.key\""
echo "    ca_path: \"$CERT_DIR/ca.crt\""
echo "    verify_peers: true"
echo
echo "⚠️  IMPORTANT: In production, replace these self-signed certificates"
echo "    with certificates from your organization's CA or a trusted CA."
echo

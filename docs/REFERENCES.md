# Generate 2048-bit RSA private key
openssl genrsa -out server.key 2048


openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/C=IN/ST=State/L=City/O=TestOrg/OU=IT/CN=localhost"

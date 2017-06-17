#!/bin/bash
# dump tech details about a cached *.pem file

echo "Content-Type: text/plain"
echo ""
F=cache/${QUERY_STRING//\//}.pem
2>&1 openssl x509 -noout -text -in $F

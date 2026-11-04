#!/bin/sh
# APISIX takes its certificate as text in its route file, so it goes in here at every start.
set -eu
case "$SESSION_SECRET $KEYCLOAK_CLIENT_SECRET" in
  *change-me*) echo "Set real secrets in .env first." >&2; exit 1 ;;
esac
umask 077
indent() { awk '{ print "      " $0 }' "$1"; }
{
  cat /etc/docs-gateway/apisix.yaml
  echo 'ssls:'
  echo "  - snis: [\"$PUBLIC_HOST\"]"
  echo '    cert: |'
  indent /certs/tls.crt
  echo '    key: |'
  indent /certs/tls.key
  echo '#END'
} > /usr/local/apisix/conf/apisix.yaml
exec /docker-entrypoint.sh docker-start

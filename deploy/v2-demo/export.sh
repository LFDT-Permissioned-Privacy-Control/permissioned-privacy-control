#!/bin/sh
# This runs offline as root. Serving mounts receive explicit allowlists only;
# /demo/private (owner DSNs, signing authority and CA key) is never copied.
set -eu
copy_file() {
  service=$1
  item=$2
  if [ -f "/demo/$item" ]; then
    mkdir -p "/exports/$service/$(dirname "$item")"
    cp "/demo/$item" "/exports/$service/$item"
  fi
}
copy_tree() {
  service=$1
  item=$2
  if [ -d "/demo/$item" ]; then
    mkdir -p "/exports/$service/$item"
    cp -R "/demo/$item/." "/exports/$service/$item/"
  fi
}
for service in ops explorer wallet observer reth; do
  mkdir -p "/exports/$service"
done
for service in ops explorer wallet; do
  for file in tls.crt tls.key ca.crt; do copy_file "$service" "$file"; done
done
copy_file wallet wallet.json
copy_tree ops bundles
copy_tree ops ops
copy_tree explorer explorer
copy_tree observer observer
copy_file reth genesis.json
if [ -f /demo/private/engine.jwt ]; then cp /demo/private/engine.jwt /exports/reth/engine.jwt; fi
for service in ops explorer wallet observer reth; do
  chown -R 1000:1000 "/exports/$service"
done
mkdir -p /exports/ops-spool /exports/reth-data
chown 1000:1000 /exports/ops-spool /exports/reth-data

#!/bin/sh
# This runs offline as root. Serving mounts receive explicit allowlists only;
# Owner DSNs, signing authority and CA keys are never copied. The viewer receives
# only the explicitly named public source JSON, on a separate read-only volume.
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
if [ -f /demo/private/authoring/core/draft.json ]; then
  viewer=/exports/configuration-sources
  mkdir -p "$viewer"
  chown 1000:1000 "$viewer"
  stage="$viewer/.stage-$$"
  previous="$viewer/.previous-$$"
  mkdir -p "$stage/core" "$stage/broker"
  for file in draft groups registry execution identity runtime compliance disclosure; do
    cp "/demo/private/authoring/core/$file.json" "$stage/core/$file.json"
  done
  for file in draft groups registry execution identity auth role-context; do
    cp "/demo/private/authoring/broker/$file.json" "$stage/broker/$file.json"
  done
  chown -R 1000:1000 "$stage"
  # A complete folder is exposed at an absent path. Same-name replacement
  # withdraws the old folder first; no rename-over-nonempty-dir is assumed.
  if [ -e "$viewer/current" ]; then mv "$viewer/current" "$previous"; fi
  mv "$stage" "$viewer/current"
  if [ -d "$previous" ]; then rm -rf "$previous"; fi
fi
copy_tree explorer explorer
copy_tree observer observer
copy_file reth genesis.json
if [ -f /demo/private/engine.jwt ]; then cp /demo/private/engine.jwt /exports/reth/engine.jwt; fi
for service in ops explorer wallet observer reth; do
  chown -R 1000:1000 "/exports/$service"
done
mkdir -p /exports/ops-spool /exports/reth-data
chown 1000:1000 /exports/ops-spool /exports/reth-data

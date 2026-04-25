#!/bin/sh
# Thin wrapper that translates BITCOIN_RPC_* / ORD_TAP_* env vars into
# `ord` CLI flags. Keeps the image friendly to PaaS deployments
# (Coolify, Fly, Render, etc.) where args live in env files.
#
# Usage:
#   docker run -e BITCOIN_RPC_URL=... -e BITCOIN_RPC_USER=... \
#              -e BITCOIN_RPC_PASSWORD=... ord-tap          # defaults to `server`
#   docker run ord-tap -- --version                          # pass raw ord args

set -e

GLOBAL=""
[ -n "$BITCOIN_RPC_URL" ]       && GLOBAL="$GLOBAL --bitcoin-rpc-url $BITCOIN_RPC_URL"
[ -n "$BITCOIN_RPC_USER" ]      && GLOBAL="$GLOBAL --bitcoin-rpc-username $BITCOIN_RPC_USER"
[ -n "$BITCOIN_RPC_PASSWORD" ]  && GLOBAL="$GLOBAL --bitcoin-rpc-password $BITCOIN_RPC_PASSWORD"
[ -n "$BITCOIN_DATA_DIR" ]      && GLOBAL="$GLOBAL --bitcoin-data-dir $BITCOIN_DATA_DIR"
[ -n "$BITCOIN_COOKIE_FILE" ]   && GLOBAL="$GLOBAL --cookie-file $BITCOIN_COOKIE_FILE"
[ -n "$ORD_TAP_CHAIN" ]         && GLOBAL="$GLOBAL --chain $ORD_TAP_CHAIN"
[ -n "$ORD_TAP_INDEX" ]         && GLOBAL="$GLOBAL --index $ORD_TAP_INDEX"

# Subcommand: default to `server` if user didn't pass one.
if [ "$#" -eq 0 ] || [ "$1" = "server" ]; then
  [ "$#" -gt 0 ] && shift
  SERVER_ARGS="--http --http-port ${ORD_TAP_HTTP_PORT:-3333}"
  [ -n "$ORD_TAP_HTTP_HOST" ] && SERVER_ARGS="$SERVER_ARGS --http-host $ORD_TAP_HTTP_HOST"
  # shellcheck disable=SC2086
  exec /usr/local/bin/ord $GLOBAL server $SERVER_ARGS "$@"
fi

# Pass-through for other subcommands (`index`, `wallet`, etc.)
# shellcheck disable=SC2086
exec /usr/local/bin/ord $GLOBAL "$@"

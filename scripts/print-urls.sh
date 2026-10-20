#!/usr/bin/env bash
PROXY_PORT="${HOST_PORT_PROXY:-8080}"
UI_PORT="${HOST_PORT_UI:-5173}"
RPC_PORT="${HOST_PORT_RPC:-8545}"

echo ""
echo "========================================="
echo "  Services are starting up..."
echo "========================================="
echo "  App:    http://localhost:${UI_PORT}"
echo "  Admin:  http://localhost:${UI_PORT}/admin/dashboard"
echo "  API:    http://localhost:${PROXY_PORT}"
echo "  RPC:    http://localhost:${RPC_PORT}"
echo "========================================="

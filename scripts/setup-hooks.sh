#!/bin/bash
#
# Setup git hooks for the repository
# This script configures git to use the hooks in scripts/hooks/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HOOKS_DIR="$REPO_ROOT/scripts/hooks"

echo "Setting up git hooks..."

# Configure git to use our hooks directory
git config core.hooksPath scripts/hooks

# Ensure hooks are executable
if [ -d "$HOOKS_DIR" ]; then
    chmod +x "$HOOKS_DIR"/* 2>/dev/null || true
fi

echo "Git hooks configured to use: scripts/hooks/"
echo "Done!"

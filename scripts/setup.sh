#!/bin/bash

set -e

echo "Setting up Open Privacy Suite..."

# Check Go version
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.21+"
    exit 1
fi

echo "✓ Go found: $(go version)"

# Check Node version
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed. Please install Node.js 18+"
    exit 1
fi

echo "✓ Node.js found: $(node --version)"

# Install Go dependencies
echo "Installing Go dependencies..."
go mod download
echo "✓ Go dependencies installed"

# Install frontend dependencies
echo "Installing frontend dependencies..."
cd frontend
npm install
cd ..
echo "✓ Frontend dependencies installed"

# Run database migrations
echo "Running database migrations..."
go run ./cmd/migrate
echo "✓ Database initialized"

echo ""
echo "Setup complete! 🎉"
echo ""
echo "To start the backend:"
echo "  make dev"
echo ""
echo "To start the frontend (in another terminal):"
echo "  cd frontend && npm run dev"
echo ""
echo "To run tests:"
echo "  make test"

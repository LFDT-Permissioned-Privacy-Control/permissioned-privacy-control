#!/bin/bash

set -e

echo "Setting up test databases..."

# Default PostgreSQL connection
PGUSER=${PGUSER:-postgres}
PGHOST=${PGHOST:-localhost}
PGPORT=${PGPORT:-5432}

# Test database names
TEST_DB="privacy_proxy_test"
E2E_DB="privacy_proxy_e2e_test"

# Function to create database if it doesn't exist
create_db_if_not_exists() {
    local dbname=$1
    echo "Checking database: $dbname"
    
    if psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -lqt | cut -d \| -f 1 | grep -qw "$dbname"; then
        echo "✓ Database $dbname already exists"
    else
        echo "Creating database: $dbname"
        createdb -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" "$dbname" || {
            echo "Failed to create $dbname. Trying with postgres connection..."
            psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $dbname;" || {
                echo "Error: Could not create database $dbname"
                echo "Please create it manually: createdb $dbname"
                exit 1
            }
        }
        echo "✓ Created database $dbname"
    fi
}

create_db_if_not_exists "$TEST_DB"
create_db_if_not_exists "$E2E_DB"

echo ""
echo "Test databases ready! ✓"
echo ""
echo "You can now run tests:"
echo "  go test ./internal/... -v"
echo "  go test ./e2e/... -v"

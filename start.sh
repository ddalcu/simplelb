#!/bin/sh

# Create all required directories for unified data structure
mkdir -p /app/data/logs/caddy          # Caddy access/error logs + supervisor logs
mkdir -p /app/data/logs/simplelb        # Application logs + supervisor logs  
mkdir -p /app/data/logs/supervisor     # Supervisor daemon logs
mkdir -p /app/data/caddy/data          # Caddy certificates, SSL data
mkdir -p /app/data/caddy/config        # Configuration snapshots
mkdir -p /app/data/certs               # Management interface TLS certificates

export MANAGEMENT_PORT=${MANAGEMENT_PORT:-81}
export ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
export ADMIN_PASSWORD=${ADMIN_PASSWORD:-password}

echo "Starting Caddy Load Balancer..."
echo "Management Port: $MANAGEMENT_PORT"
echo "Admin Username: $ADMIN_USERNAME"

exec supervisord -c /etc/supervisor/conf.d/supervisord.conf
#!/bin/sh

mkdir -p /var/log/supervisor
mkdir -p /var/log/nginx
mkdir -p /var/log/management-ui
mkdir -p /etc/nginx/conf.d
mkdir -p /app

# Create unified data directory structure
mkdir -p /app/data/nginx
mkdir -p /app/data/logs
mkdir -p /app/data/letsencrypt
mkdir -p /app/data/certbot

cp /etc/nginx/nginx.conf.template /etc/nginx/nginx.conf

export NGINX_PORT=${NGINX_PORT:-80}
export MANAGEMENT_PORT=${MANAGEMENT_PORT:-81}
export ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
export ADMIN_PASSWORD=${ADMIN_PASSWORD:-password}

echo "Starting Nginx Load Balancer..."
echo "Nginx Port: $NGINX_PORT"
echo "Management Port: $MANAGEMENT_PORT"
echo "Admin Username: $ADMIN_USERNAME"

exec supervisord -c /etc/supervisor/conf.d/supervisord.conf
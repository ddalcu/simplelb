#!/bin/sh

# Simple log rotation script for SimpleLB
LOG_DIR="/app/data/logs"
MAX_SIZE="100M"
MAX_FILES=10

# Rotate application logs
if [ -f "$LOG_DIR/simplelb/app.log" ]; then
    if [ $(stat -f%z "$LOG_DIR/simplelb/app.log" 2>/dev/null || stat -c%s "$LOG_DIR/simplelb/app.log" 2>/dev/null || echo 0) -gt 104857600 ]; then
        # Rotate logs
        for i in $(seq $((MAX_FILES-1)) -1 2); do
            [ -f "$LOG_DIR/simplelb/app.log.$((i-1))" ] && mv "$LOG_DIR/simplelb/app.log.$((i-1))" "$LOG_DIR/simplelb/app.log.$i"
        done
        [ -f "$LOG_DIR/simplelb/app.log" ] && mv "$LOG_DIR/simplelb/app.log" "$LOG_DIR/simplelb/app.log.1"
        # Signal application to reopen log file
        touch "$LOG_DIR/simplelb/app.log"
        chmod 644 "$LOG_DIR/simplelb/app.log"
    fi
fi

# Rotate Caddy access logs
if [ -f "$LOG_DIR/caddy/access.log" ]; then
    if [ $(stat -f%z "$LOG_DIR/caddy/access.log" 2>/dev/null || stat -c%s "$LOG_DIR/caddy/access.log" 2>/dev/null || echo 0) -gt 104857600 ]; then
        for i in $(seq $((MAX_FILES-1)) -1 2); do
            [ -f "$LOG_DIR/caddy/access.log.$((i-1))" ] && mv "$LOG_DIR/caddy/access.log.$((i-1))" "$LOG_DIR/caddy/access.log.$i"
        done
        [ -f "$LOG_DIR/caddy/access.log" ] && mv "$LOG_DIR/caddy/access.log" "$LOG_DIR/caddy/access.log.1"
        # Signal Caddy to reopen log files via API
        curl -X POST http://localhost:2019/config/admin/listeners/reload >/dev/null 2>&1 || true
    fi
fi

# Rotate Caddy error logs
if [ -f "$LOG_DIR/caddy/error.log" ]; then
    if [ $(stat -f%z "$LOG_DIR/caddy/error.log" 2>/dev/null || stat -c%s "$LOG_DIR/caddy/error.log" 2>/dev/null || echo 0) -gt 104857600 ]; then
        for i in $(seq $((MAX_FILES-1)) -1 2); do
            [ -f "$LOG_DIR/caddy/error.log.$((i-1))" ] && mv "$LOG_DIR/caddy/error.log.$((i-1))" "$LOG_DIR/caddy/error.log.$i"
        done
        [ -f "$LOG_DIR/caddy/error.log" ] && mv "$LOG_DIR/caddy/error.log" "$LOG_DIR/caddy/error.log.1"
        curl -X POST http://localhost:2019/config/admin/listeners/reload >/dev/null 2>&1 || true
    fi
fi

echo "Log rotation completed at $(date)"
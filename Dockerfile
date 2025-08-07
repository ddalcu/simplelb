FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download

COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o main .

FROM caddy:2-alpine

RUN apk add --no-cache supervisor

COPY --from=builder /app/main /usr/local/bin/
COPY --from=builder /app/templates /app/templates
COPY Caddyfile /etc/caddy/Caddyfile
COPY supervisord.conf /etc/supervisor/conf.d/
COPY start.sh /
COPY logrotate.sh /usr/local/bin/

RUN chmod +x /start.sh /usr/local/bin/main /usr/local/bin/logrotate.sh

# Create unified data directory structure
RUN mkdir -p /app/data/logs/caddy \
    /app/data/logs/simplelb \
    /app/data/logs/supervisor \
    /app/data/caddy/data \
    /app/data/caddy/config \
    /app/data/certs

EXPOSE 80 443 81 2019

CMD ["/start.sh"]
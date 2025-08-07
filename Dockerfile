FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download

COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM nginx:alpine

RUN apk add --no-cache supervisor openssl certbot certbot-nginx

COPY --from=builder /app/main /usr/local/bin/
COPY --from=builder /app/templates /app/templates
COPY nginx.conf.template /etc/nginx/
COPY supervisord.conf /etc/supervisor/conf.d/
COPY start.sh /

RUN chmod +x /start.sh /usr/local/bin/main

# Generate dummy SSL certificates for development
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/dummy.key \
    -out /etc/nginx/ssl/dummy.crt \
    -subj "/C=US/ST=Local/L=Local/O=LoadBalancer/CN=localhost"

# Create unified data directory structure
RUN mkdir -p /app/data/nginx \
    /app/data/logs \
    /app/data/letsencrypt \
    /app/data/certbot

# Set up certificate renewal cron job with unified paths
RUN echo '0 0,12 * * * LETSENCRYPT_DIR=/app/data/letsencrypt /usr/bin/certbot renew --quiet --config-dir /app/data/letsencrypt --work-dir /app/data/letsencrypt --logs-dir /app/data/logs --post-hook "nginx -s reload"' | crontab -

EXPOSE 80 443 81

CMD ["/start.sh"]
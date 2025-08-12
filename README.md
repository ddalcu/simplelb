# 🏠 SimpleLB - Simple Load Balancer for Home Labs

A lightweight, Docker-based load balancer built with **Caddy** and **Go**, featuring automatic SSL certificates and a clean web interface. Perfect for home labs and small deployments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

## 🚀 Quick Start

### Docker Compose (Recommended)
```yaml
services:
  simple-lb:
    build: .
    ports:
      - "80:80"    # HTTP
      - "443:443"  # HTTPS
      - "81:81"    # Management UI
    environment:
      # Authentication
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=your-secure-password
      - ACME_EMAIL=your-email@example.com
      
      # Configuration Management (optional)
      - CONFIG_MODE=initial  # "initial" or "managed"
      
      # Pre-configure load balancers (optional)
      - LB_DOMAINS_api=api.example.com
      - LB_BACKENDS_api=192.168.1.100:8080,192.168.1.101:8080
      - LB_METHOD_api=round_robin
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

### Using Pre-built Image
```yaml
services:
  simple-lb:
    image: ghcr.io/ddalcu/simplelb:latest
    ports:
      - "80:80"    # HTTP
      - "443:443"  # HTTPS
      - "81:81"    # Management UI
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=your-secure-password
      - ACME_EMAIL=your-email@example.com
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

### Docker One-liner (Quick Demo)
```bash
docker run -d --name simplelb \
  -p 80:80 -p 443:443 -p 81:81 \
  -v $(pwd)/data:/app/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=demo123 \
  -e ACME_EMAIL=demo@example.com \
  ghcr.io/ddalcu/simplelb:latest
```

Or build from source:
```bash
git clone https://github.com/ddalcu/simplelb && cd simplelb
docker build -t simplelb . && docker run -d --name simplelb \
  -p 80:80 -p 443:443 -p 81:81 \
  -v $(pwd)/data:/app/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=demo123 \
  -e ACME_EMAIL=demo@example.com \
  simplelb
```

**Then visit:** https://localhost:81 (accept the self-signed certificate warning)

## ⚙️ Environment-Based Configuration

SimpleLB supports automatic load balancer setup through environment variables - perfect for Infrastructure as Code deployments:

### Configuration Modes

- **`CONFIG_MODE=initial`** (default): Environment load balancers applied only if no existing configuration
- **`CONFIG_MODE=managed`**: Always apply environment configuration, UI becomes read-only (GitOps mode)

### Environment Variable Pattern

```bash
# Load balancer named "api"
LB_DOMAINS_api=api.example.com,www.api.example.com
LB_BACKENDS_api=192.168.1.100:8080,192.168.1.101:8080,192.168.1.102:8080
LB_METHOD_api=round_robin

# Load balancer named "webapp" 
LB_DOMAINS_webapp=app.example.com
LB_BACKENDS_webapp=192.168.1.200:3000,192.168.1.201:3000
LB_METHOD_webapp=least_conn
```

### Production Example (Managed Mode)
```yaml
environment:
  - CONFIG_MODE=managed           # Read-only UI
  - LB_DOMAINS_api=api.myapp.com
  - LB_BACKENDS_api=10.0.1.100:8080,10.0.1.101:8080
  - LB_METHOD_api=round_robin
  - LB_DOMAINS_web=myapp.com,www.myapp.com
  - LB_BACKENDS_web=10.0.2.100:3000,10.0.2.101:3000
  - LB_METHOD_web=least_conn
```

## ✨ Features

### 🔧 **Load Balancing**
- Multiple algorithms: Random, Round Robin, Least Connections, First Available, IP Hash, Header Hash, Cookie Hash
- Real-time configuration updates via Caddy's admin API
- Persistent configuration across restarts
- Multi-domain support per load balancer

### 🔒 **Automatic HTTPS**
- Let's Encrypt integration with automatic certificate provisioning
- Background certificate renewal
- HTTP → HTTPS redirects
- Multi-domain support

### 🖥️ **Web Interface**
- Clean, responsive dashboard
- Easy load balancer management
- Real-time log viewing
- Configuration export/import
- No CLI required

### ⚙️ **Configuration Management**
- **Environment Variables**: Automatic load balancer setup via `LB_*` variables
- **Initial Mode**: Environment config applied only if no existing setup
- **Managed Mode**: Infrastructure as Code with read-only UI
- **GitOps Ready**: Perfect for container orchestration and CI/CD

## 📸 Screenshots

### Dashboard Overview
![SimpleLB Dashboard](screenshots/dashboard.png)
*Clean dashboard for managing your load balancers*

### Login Interface
![Login Page](screenshots/login.png)
*Secure HTTPS login with session management*

### Add/Edit Load Balancer
![Edit Load Balancer](screenshots/edit.png)
*Easy form to configure load balancers with multiple algorithms*

### System Logs
![System Logs](screenshots/logs.png)
*View application and Caddy logs in real-time*

### Managed Configuration Mode
![Managed Mode](screenshots/managed-mode.png)
*Infrastructure as Code mode with read-only UI*

### Caddy Configuration
![Caddy Config](screenshots/caddy-config.png)
*Export and view the generated Caddy configuration*


## 📋 How to Use

### Creating Load Balancers

1. **Access Management UI**: Navigate to https://your-server:81
2. **Login**: Use your configured username/password (accept self-signed certificate warning)
3. **Add Load Balancer**: Click "Add Load Balancer" 
4. **Configure Settings**:
   - **Domain**: Enter your domain (e.g., `api.homelab.local`)
   - **Backend Servers**: Add your upstream servers (one per line)
   - **Load Balancing Method**: Choose your preferred algorithm
   - **Hash Key**: For header/cookie-based load balancing (if applicable)

### Backend Server Format

Simple format - one server per line:
```
192.168.1.100:8080
192.168.1.101:8080  
192.168.1.102:8080
```

### Load Balancing Methods

- **Random** (default): Randomly distribute requests
- **Round Robin**: Even distribution across all servers
- **Least Connections**: Routes to server with fewest active connections  
- **First Available**: Always use the first healthy server
- **IP Hash**: Client IP-based routing (session persistence)
- **Header Hash**: Route based on HTTP header value
- **Cookie Hash**: Route based on cookie value

### SSL/HTTPS Setup

For automatic HTTPS:
1. **Domain DNS**: Point your domain to this server's IP
2. **Email Required**: Set `ACME_EMAIL` for Let's Encrypt notifications
3. **Port 443**: Make sure port 443 is accessible from the internet
4. **Wait**: Certificates are provisioned automatically

## 🔧 Configuration

### Environment Variables

#### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Web interface username |
| `ADMIN_PASSWORD` | `password` | Web interface password |
| `MANAGEMENT_PORT` | `81` | Web interface port |
| `SESSION_SECRET` | *auto-generated* | Session encryption key |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` for HTTPS cookies |
| `ACME_EMAIL` | `admin@example.com` | Let's Encrypt email |
| `CADDY_ADMIN_URL` | `http://127.0.0.1:2019` | Caddy Admin API URL |
| `GENERAL_RATE_LIMIT` | `60` | Requests per minute per IP |

#### Configuration Management
| Variable | Options | Description |
|----------|---------|-------------|
| `CONFIG_MODE` | `initial`, `managed` | Configuration management mode |

#### Environment Load Balancers
| Pattern | Required | Description |
|---------|----------|-------------|
| `LB_DOMAINS_{name}` | ✅ | Comma-separated domain list |
| `LB_BACKENDS_{name}` | ✅ | Comma-separated backend servers |
| `LB_METHOD_{name}` | ❌ | Load balancing method (defaults to `random`) |

**Supported Methods**: `random`, `round_robin`, `least_conn`, `first`, `ip_hash`, `header`, `cookie`

### Deployment Scenarios

**🏠 Development/Home Lab** (`CONFIG_MODE=initial`)
```yaml
environment:
  - CONFIG_MODE=initial
  - LB_DOMAINS_dev=dev.homelab.local
  - LB_BACKENDS_dev=192.168.1.100:3000
  # UI remains fully functional for additional configuration
```

**🏢 Production/CI/CD** (`CONFIG_MODE=managed`)
```yaml
environment:
  - CONFIG_MODE=managed  # UI becomes read-only
  - LB_DOMAINS_api=api.company.com
  - LB_BACKENDS_api=10.0.1.100:8080,10.0.1.101:8080
  - LB_METHOD_api=least_conn
  - LB_DOMAINS_web=company.com,www.company.com
  - LB_BACKENDS_web=10.0.2.100:3000,10.0.2.101:3000
  - LB_METHOD_web=round_robin
  # All changes must be made via environment variables
```

### Data Persistence

All data is stored in `/app/data`:
- **Configuration**: Saved automatically and restored on restart
- **SSL Certificates**: Stored in `/app/data/caddy/data/`
- **Logs**: Application and Caddy logs in `/app/data/logs/`
- **Management TLS**: Self-signed certificates in `/app/data/certs/`

## 🔒 Security Features

### Management Interface Security
- **HTTPS Only**: Management interface runs on HTTPS with TLS 1.2+
- **Self-Signed Certificates**: Auto-generated certificates for secure communication
- **Secure Session Cookies**: HTTP-only, secure session management
- **Basic Authentication**: Username/password protection for all endpoints

### TLS Configuration
- **Strong Ciphers**: Modern cipher suites (ECDHE, ChaCha20-Poly1305, AES-GCM)
- **Certificate Validation**: Automatic certificate expiry checking and renewal
- **Secure Headers**: Security headers applied to all responses

### Network Security
- **Isolated Management**: Management interface separate from load balancing traffic
- **Encrypted Communication**: All admin communication encrypted via HTTPS

## 🏗️ Architecture

### System Overview
```mermaid
graph TD
    A["Internet Traffic"] --> B["Caddy Load Balancer\nPorts 80/443"]
    B --> C["Backend Server 1\n192.168.1.100:8080"]
    B --> D["Backend Server 2\n192.168.1.101:8080"]
    B --> E["Backend Server N\n192.168.1.10x:8080"]
    
    F["Management UI\nPort 81"] --> G["SimpleLB App\nGo Application"]
    G --> H["Caddy Admin API\nPort 2019"]
    H --> B
    
    I["Let's Encrypt"] --> B
    B --> J["SSL Certificates\n/app/data/caddy/data"]
    G --> K["Configuration\n/app/data/caddy/config"]
```

### Request Flow
```mermaid
sequenceDiagram
    participant C as Client
    participant LB as Caddy Load Balancer
    participant B1 as Backend 1
    participant B2 as Backend 2
    participant LE as "Let's Encrypt"
    
    Note over C,LE: HTTPS Setup (First Time)
    C->>LB: HTTP Request to domain.com
    LB->>LE: Request SSL Certificate
    LE->>LB: Return Certificate
    LB->>C: Redirect to HTTPS
    
    Note over C,B2: Normal Request Flow
    C->>LB: HTTPS Request
    LB->>LB: Terminate SSL
    LB->>LB: Apply Load Balancing Algorithm
    alt Round Robin
        LB->>B1: Forward Request
        B1->>LB: Response
    else Next in rotation
        LB->>B2: Forward Request
        B2->>LB: Response
    end
    LB->>C: Return Response (SSL)
```

### Configuration Management
```mermaid
graph LR
    A["Web UI"] --> B["Go Application"]
    B --> C["Caddy Admin API"]
    C --> D["Update Caddy Config"]
    D --> E["Save to /app/data/caddy/config/caddy.json"]
    
    F["Container Restart"] --> G["Load Saved Config"]
    G --> C
    
    H["Let's Encrypt"] --> I["Store Certificates"]
    I --> J["/app/data/caddy/data/"]
```

## 📁 Directory Structure

```
/app/data/
├── logs/
│   ├── caddy/          # Caddy access/error logs
│   ├── simplelb/        # Application logs
│   └── supervisor/     # Process management logs
├── caddy/
│   ├── data/          # SSL certificates, TLS data
│   └── config/        # Configuration snapshots
└── certs/             # Management interface TLS certificates
    ├── server.crt     # Self-signed certificate
    └── server.key     # Private key
```

## 🔌 API Documentation

SimpleLB provides a REST API for programmatic management of load balancers.

### Authentication
All API endpoints require HTTP Basic Authentication using your configured admin credentials.

```bash
curl -k -u admin:password https://localhost:81/dashboard
```

**Note**: Use the `-k` flag to accept the self-signed certificate.

### Endpoints

#### Get All Load Balancers
```http
GET /dashboard
```
**Description**: Returns the dashboard page with all load balancers
**Response**: HTML page with load balancer list

#### Get Load Balancer Details
```http
GET /edit/:domain
```
**Description**: Get configuration for a specific load balancer
**Parameters**:
- `domain` (path): Domain name of the load balancer

**Response**:
```json
{
  "domain": "api.homelab.local",
  "method": "round_robin",
  "backends": "192.168.1.100:8080\n192.168.1.101:8080"
}
```

#### Create Load Balancer
```http
POST /add
```
**Description**: Create a new load balancer
**Content-Type**: `application/x-www-form-urlencoded`

**Parameters**:
- `domain` (string): Domain name (e.g., "api.homelab.local")
- `backends` (string): Backend servers, one per line
- `method` (string): Load balancing method ("random", "round_robin", "least_conn", "first", "ip_hash", "header", "cookie")
- `hash_key` (string): Hash key for header/cookie methods (optional)

**Example**:
```bash
curl -k -X POST -u admin:password \
  -d "domain=api.homelab.local" \
  -d "backends=192.168.1.100:8080\n192.168.1.101:8080" \
  -d "method=round_robin" \
  https://localhost:81/add
```

#### Update Load Balancer
```http
POST /edit/:domain
```
**Description**: Update existing load balancer configuration
**Parameters**: Same as create, plus:
- `domain` (path): Existing domain name

#### Delete Load Balancer
```http
POST /delete/:domain
```
**Description**: Delete a load balancer
**Parameters**:
- `domain` (path): Domain name to delete

**Example**:
```bash
curl -k -X POST -u admin:password \
  https://localhost:81/delete/api.homelab.local
```

#### View Logs
```http
GET /logs?type=<log_type>
```
**Description**: View system logs
**Parameters**:
- `type` (query): Log type ("app", "caddy", "caddy-error")

### Load Balancing Methods

| Method | Description | Hash Key Required |
|--------|-------------|------------------|
| `random` | Random distribution (default) | No |
| `round_robin` | Even distribution across servers | No |
| `least_conn` | Route to server with fewest connections | No |
| `first` | Always use first healthy server | No |
| `ip_hash` | Route based on client IP | No |
| `header` | Route based on HTTP header | Yes |
| `cookie` | Route based on cookie value | Yes |

### Hash Key Options
For `header` and `cookie` methods:

**Header Options**:
- `X-Forwarded-For`
- `X-Real-IP`
- `X-User-ID`
- `Authorization`

**Cookie Options**:
- `session_id`
- `user_session`

## 🔍 Monitoring

### Web Interface Logs
- **Application Logs**: View SimpleLB application logs
- **Caddy Access Logs**: See incoming HTTP requests
- **Caddy Error Logs**: Troubleshoot Caddy issues

### Command Line
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f simple-lb

# Check configuration
curl http://localhost:2019/config/
```

## 🛠️ Development

### Local Setup
```bash
# Clone repository
git clone https://github.com/ddalcu/simplelb

# Build and run
docker-compose up --build

# View logs
docker-compose logs -f
```

### Project Structure
```
.
├── main.go                 # Go application
├── templates/              # HTML templates  
│   ├── dashboard.html      # Main interface with integrated logs modal
│   └── login.html          # Login page
├── Dockerfile             # Container build
├── docker-compose.yml     # Service definition
├── supervisord.conf       # Process management
├── start.sh              # Startup script
├── logrotate.sh          # Log rotation
├── Caddyfile             # Caddy configuration
└── .env.example          # Environment template
```

## 🐛 Troubleshooting

### Common Issues

**SSL Certificates not working?**
- Check DNS points to your server
- Verify port 443 is accessible
- Check `ACME_EMAIL` is set
- Look at Caddy error logs

**Load balancer not responding?**
- Verify backend servers are reachable
- Check backend server health
- Review Caddy access logs

**Web interface not accessible?**
- Check port 81 is accessible
- Verify Docker container is running
- Check application logs

### Getting Help
- Check the logs in the web interface
- Use `docker-compose logs -f` for detailed logs
- Verify your configuration in the web UI

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Feel free to:
- Report bugs
- Suggest features  
- Submit pull requests
- Improve documentation

This is a hobby project, so be patient with responses!

---

**Perfect for home labs, development environments, and small deployments** 🏠

*Simple load balancing without the complexity*
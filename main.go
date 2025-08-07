package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type Upstream struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	Weight    int    `json:"weight"`    // Server weight (1-100)
	MaxFails  int    `json:"max_fails"` // Health check max failures
	FailTimeout string `json:"fail_timeout"` // Health check fail timeout
}

type LoadBalancerConfig struct {
	Method      string `json:"method"`       // "round_robin", "least_conn", "ip_hash", "hash"
	HashKey     string `json:"hash_key"`     // For hash method (e.g., "$remote_addr", "$uri")
	EnableCache bool   `json:"enable_cache"` // Enable proxy caching
	CacheTime   string `json:"cache_time"`   // Cache duration (e.g., "1h", "30m")
	SessionSticky bool `json:"session_sticky"` // Session persistence using ip_hash
}

type LoadBalancer struct {
	Domain    string              `json:"domain"`
	Protocol  string              `json:"protocol"`  // "http" or "https"
	SSLEmail  string              `json:"ssl_email"` // Email for Let's Encrypt
	Upstreams []Upstream          `json:"upstreams"`
	Config    LoadBalancerConfig  `json:"config"`    // Advanced configuration
	SSLStatus string              `json:"ssl_status,omitempty"` // "pending", "active", "failed"
}

type Config struct {
	LoadBalancers []LoadBalancer `json:"load_balancers"`
}

var (
	store      = sessions.NewCookieStore([]byte("secret-key"))
	configFile = "/app/data/config.json"
	config     = Config{}
)

// getDefaultLoadBalancerConfig returns optimal default settings
func getDefaultLoadBalancerConfig() LoadBalancerConfig {
	return LoadBalancerConfig{
		Method:        "round_robin", // Best for general use
		HashKey:       "$remote_addr", // Default hash key if needed
		EnableCache:   false,         // Disabled by default for safety
		CacheTime:     "1h",          // Conservative cache time
		SessionSticky: false,         // Disabled by default
	}
}

// getDefaultUpstream returns optimal default upstream settings
func getDefaultUpstream(host, port string) Upstream {
	return Upstream{
		Host:        host,
		Port:        port,
		Weight:      1,   // Equal weight
		MaxFails:    3,   // Industry standard
		FailTimeout: "10s", // Quick recovery
	}
}

// parseIntDefault parses an integer with a default value
func parseIntDefault(s string, defaultVal int) int {
	if val := strings.TrimSpace(s); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

// requestLetsEncryptCertificate requests an SSL certificate from Let's Encrypt
func requestLetsEncryptCertificate(domain, email string) error {
	log.Printf("Requesting Let's Encrypt certificate for domain: %s", domain)
	
	// First, create a temporary nginx config to serve the ACME challenge
	tempConfigPath := "/app/data/nginx/temp-" + strings.ReplaceAll(domain, ".", "_") + ".conf"
	tempConfig := fmt.Sprintf(`
server {
    listen 80;
    server_name %s;
    
    location /.well-known/acme-challenge/ {
        root /app/data/certbot;
        try_files $uri =404;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}
`, domain)
	
	// Create the webroot directory
	os.MkdirAll("/app/data/certbot", 0755)
	
	// Write temporary config
	err := ioutil.WriteFile(tempConfigPath, []byte(tempConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to create temporary nginx config: %v", err)
	}
	
	// Reload nginx with temporary config
	reloadCmd := exec.Command("nginx", "-s", "reload")
	if err := reloadCmd.Run(); err != nil {
		log.Printf("Warning: Failed to reload nginx for ACME challenge: %v", err)
	}
	
	// Run certbot to get the certificate
	certbotCmd := exec.Command("certbot", "certonly", 
		"--webroot", 
		"--webroot-path=/app/data/certbot",
		"--config-dir", "/app/data/letsencrypt",
		"--work-dir", "/app/data/letsencrypt",
		"--logs-dir", "/app/data/logs",
		"--email", email,
		"--agree-tos", 
		"--no-eff-email",
		"--keep-until-expiring",
		"--non-interactive",
		"-d", domain)
	
	output, err := certbotCmd.CombinedOutput()
	log.Printf("Certbot output: %s", string(output))
	
	// Clean up temporary config
	os.Remove(tempConfigPath)
	
	if err != nil {
		return fmt.Errorf("certbot failed: %v\nOutput: %s", err, string(output))
	}
	
	// Check if certificates were created
	certPath := fmt.Sprintf("/app/data/letsencrypt/live/%s/fullchain.pem", domain)
	keyPath := fmt.Sprintf("/app/data/letsencrypt/live/%s/privkey.pem", domain)
	
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found at %s", certPath)
	}
	
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key file not found at %s", keyPath)
	}
	
	log.Printf("Successfully obtained Let's Encrypt certificate for %s", domain)
	return nil
}

func main() {
	loadConfig()
	
	r := gin.New()
	r.Use(gin.Logger())
	
	r.LoadHTMLGlob("/app/templates/*")
	r.Static("/static", "./static")
	
	r.GET("/", showLogin)
	r.POST("/login", handleLogin)
	r.GET("/dashboard", authRequired(), showDashboard)
	r.POST("/add", authRequired(), addLoadBalancer)
	r.GET("/edit/:domain", authRequired(), getLoadBalancer)
	r.POST("/edit/:domain", authRequired(), editLoadBalancer)
	r.DELETE("/delete/:domain", authRequired(), deleteLoadBalancer)
	r.POST("/reload", authRequired(), reloadNginx)
	r.GET("/logs", authRequired(), getNginxLogs)
	r.GET("/config-check", authRequired(), checkNginxConfig)
	r.GET("/config", authRequired(), getConfig)
	r.POST("/config", authRequired(), updateConfig)
	r.GET("/config/backup", authRequired(), backupConfig)
	r.POST("/retry-cert/:domain", authRequired(), retryCertificate)
	r.GET("/logout", handleLogout)
	
	port := os.Getenv("MANAGEMENT_PORT")
	if port == "" {
		port = "81"
	}
	
	log.Printf("Management UI starting on port %s", port)
	r.Run(":" + port)
}

func loadConfig() {
	if data, err := ioutil.ReadFile(configFile); err == nil {
		json.Unmarshal(data, &config)
	}
}

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFile, data, 0644)
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
			return
		}
		c.Next()
	}
}

func showLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	
	expectedUser := os.Getenv("ADMIN_USERNAME")
	expectedPass := os.Getenv("ADMIN_PASSWORD")
	
	if expectedUser == "" {
		expectedUser = "admin"
	}
	if expectedPass == "" {
		expectedPass = "password"
	}
	
	if username == expectedUser && password == expectedPass {
		session, _ := store.Get(c.Request, "session")
		session.Values["authenticated"] = true
		session.Save(c.Request, c.Writer)
		c.Redirect(http.StatusSeeOther, "/dashboard")
	} else {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid credentials"})
	}
}

func showDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{"config": config})
}

func addLoadBalancer(c *gin.Context) {
	domain := c.PostForm("domain")
	protocol := c.DefaultPostForm("protocol", "http")
	sslEmail := c.PostForm("ssl_email")
	upstreamsStr := c.PostForm("upstreams")
	
	// Validate HTTPS requirements
	if protocol == "https" && sslEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email address is required for HTTPS/Let's Encrypt certificates",
			"suggestion": "Please provide a valid email address for certificate notifications",
		})
		return
	}
	
	// Advanced configuration with defaults
	lbConfig := getDefaultLoadBalancerConfig()
	
	// Override defaults with form values if provided
	if method := c.PostForm("method"); method != "" {
		if method == "round_robin" || method == "least_conn" || method == "ip_hash" || method == "hash" {
			lbConfig.Method = method
		}
	}
	if hashKey := c.PostForm("hash_key"); hashKey != "" {
		lbConfig.HashKey = hashKey
	}
	if c.PostForm("enable_cache") == "on" {
		lbConfig.EnableCache = true
	}
	if cacheTime := c.PostForm("cache_time"); cacheTime != "" {
		lbConfig.CacheTime = cacheTime
	}
	if c.PostForm("session_sticky") == "on" {
		lbConfig.SessionSticky = true
		lbConfig.Method = "ip_hash" // Force ip_hash for session persistence
	}
	
	// Validate protocol
	if protocol != "http" && protocol != "https" {
		protocol = "http"
	}
	
	var upstreams []Upstream
	for _, upstream := range strings.Split(upstreamsStr, "\n") {
		upstream = strings.TrimSpace(upstream)
		if upstream != "" {
			parts := strings.Split(upstream, ":")
			if len(parts) >= 2 {
				host := strings.TrimSpace(parts[0])
				port := strings.TrimSpace(parts[1])
				
				// Create upstream with defaults
				us := getDefaultUpstream(host, port)
				
				// Check for weight, max_fails, fail_timeout in format: host:port:weight:max_fails:fail_timeout
				if len(parts) >= 3 {
					if weight := strings.TrimSpace(parts[2]); weight != "" && weight != "0" {
						if w := parseIntDefault(weight, 1); w > 0 && w <= 100 {
							us.Weight = w
						}
					}
				}
				if len(parts) >= 4 {
					if maxFails := strings.TrimSpace(parts[3]); maxFails != "" {
						if mf := parseIntDefault(maxFails, 3); mf > 0 {
							us.MaxFails = mf
						}
					}
				}
				if len(parts) >= 5 {
					if failTimeout := strings.TrimSpace(parts[4]); failTimeout != "" {
						us.FailTimeout = failTimeout
					}
				}
				
				upstreams = append(upstreams, us)
			}
		}
	}
	
	lb := LoadBalancer{
		Domain:    domain,
		Protocol:  protocol,
		SSLEmail:  sslEmail,
		Upstreams: upstreams,
		Config:    lbConfig,
		SSLStatus: "pending", // Will be updated after certificate generation
	}
	
	
	for i, existing := range config.LoadBalancers {
		if existing.Domain == domain {
			config.LoadBalancers[i] = lb
			goto save
		}
	}
	
	config.LoadBalancers = append(config.LoadBalancers, lb)
	
save:
	if err := saveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	// Generate initial nginx config (may use dummy certs for HTTPS)
	generateNginxConfig()
	
	// If HTTPS, request Let's Encrypt certificate in background
	if protocol == "https" && sslEmail != "" {
		go func() {
			log.Printf("Requesting Let's Encrypt certificate for %s", domain)
			
			// Update SSL status to indicate processing
			for i, existing := range config.LoadBalancers {
				if existing.Domain == domain {
					config.LoadBalancers[i].SSLStatus = "requesting"
					saveConfig()
					break
				}
			}
			
			// Request certificate
			if err := requestLetsEncryptCertificate(domain, sslEmail); err != nil {
				log.Printf("Failed to obtain Let's Encrypt certificate for %s: %v", domain, err)
				// Update status to failed
				for i, existing := range config.LoadBalancers {
					if existing.Domain == domain {
						config.LoadBalancers[i].SSLStatus = "failed"
						saveConfig()
						break
					}
				}
			} else {
				log.Printf("Successfully obtained Let's Encrypt certificate for %s", domain)
				// Update status to active and regenerate nginx config
				for i, existing := range config.LoadBalancers {
					if existing.Domain == domain {
						config.LoadBalancers[i].SSLStatus = "active"
						saveConfig()
						generateNginxConfig()
						
						// Reload nginx with new certificate
						reloadCmd := exec.Command("nginx", "-s", "reload")
						if err := reloadCmd.Run(); err != nil {
							log.Printf("Failed to reload nginx after certificate installation: %v", err)
						}
						break
					}
				}
			}
		}()
	}
	
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func getLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")
	
	for _, lb := range config.LoadBalancers {
		if lb.Domain == domain {
			c.JSON(http.StatusOK, lb)
			return
		}
	}
	
	c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
}

func editLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")
	newDomain := c.PostForm("domain")
	protocol := c.DefaultPostForm("protocol", "http")
	sslEmail := c.PostForm("ssl_email")
	upstreamsStr := c.PostForm("upstreams")
	
	// Validate HTTPS requirements
	if protocol == "https" && sslEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email address is required for HTTPS/Let's Encrypt certificates",
			"suggestion": "Please provide a valid email address for certificate notifications",
		})
		return
	}
	
	// Get existing config or use defaults
	var existingConfig LoadBalancerConfig
	for _, lb := range config.LoadBalancers {
		if lb.Domain == domain {
			existingConfig = lb.Config
			break
		}
	}
	if existingConfig.Method == "" {
		existingConfig = getDefaultLoadBalancerConfig()
	}
	
	// Advanced configuration - use existing values as defaults
	lbConfig := existingConfig
	
	// Override with form values if provided
	if method := c.PostForm("method"); method != "" {
		if method == "round_robin" || method == "least_conn" || method == "ip_hash" || method == "hash" {
			lbConfig.Method = method
		}
	}
	if hashKey := c.PostForm("hash_key"); hashKey != "" {
		lbConfig.HashKey = hashKey
	}
	lbConfig.EnableCache = c.PostForm("enable_cache") == "on"
	if cacheTime := c.PostForm("cache_time"); cacheTime != "" {
		lbConfig.CacheTime = cacheTime
	}
	if c.PostForm("session_sticky") == "on" {
		lbConfig.SessionSticky = true
		lbConfig.Method = "ip_hash" // Force ip_hash for session persistence
	} else {
		lbConfig.SessionSticky = false
	}
	
	// Validate protocol
	if protocol != "http" && protocol != "https" {
		protocol = "http"
	}
	
	var upstreams []Upstream
	for _, upstream := range strings.Split(upstreamsStr, "\n") {
		upstream = strings.TrimSpace(upstream)
		if upstream != "" {
			parts := strings.Split(upstream, ":")
			if len(parts) >= 2 {
				host := strings.TrimSpace(parts[0])
				port := strings.TrimSpace(parts[1])
				
				// Create upstream with defaults
				us := getDefaultUpstream(host, port)
				
				// Check for weight, max_fails, fail_timeout in format: host:port:weight:max_fails:fail_timeout
				if len(parts) >= 3 {
					if weight := strings.TrimSpace(parts[2]); weight != "" && weight != "0" {
						if w := parseIntDefault(weight, 1); w > 0 && w <= 100 {
							us.Weight = w
						}
					}
				}
				if len(parts) >= 4 {
					if maxFails := strings.TrimSpace(parts[3]); maxFails != "" {
						if mf := parseIntDefault(maxFails, 3); mf > 0 {
							us.MaxFails = mf
						}
					}
				}
				if len(parts) >= 5 {
					if failTimeout := strings.TrimSpace(parts[4]); failTimeout != "" {
						us.FailTimeout = failTimeout
					}
				}
				
				upstreams = append(upstreams, us)
			}
		}
	}
	
	for i, lb := range config.LoadBalancers {
		if lb.Domain == domain {
			// Preserve existing SSL status if not changing to HTTPS or domain is same
			sslStatus := lb.SSLStatus
			if protocol == "https" && (newDomain != domain || sslEmail != lb.SSLEmail) {
				sslStatus = "pending" // Will need new certificate
			}
			
			config.LoadBalancers[i] = LoadBalancer{
				Domain:    newDomain,
				Protocol:  protocol,
				SSLEmail:  sslEmail,
				Upstreams: upstreams,
				Config:    lbConfig,
				SSLStatus: sslStatus,
			}
			
			if err := saveConfig(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			
			generateNginxConfig()
			
			// If HTTPS and needs new certificate, request it in background
			if protocol == "https" && sslStatus == "pending" && sslEmail != "" {
				go func() {
					log.Printf("Requesting Let's Encrypt certificate for %s (edit)", newDomain)
					
					// Update SSL status to indicate processing
					for j, existing := range config.LoadBalancers {
						if existing.Domain == newDomain {
							config.LoadBalancers[j].SSLStatus = "requesting"
							saveConfig()
							break
						}
					}
					
					// Request certificate
					if err := requestLetsEncryptCertificate(newDomain, sslEmail); err != nil {
						log.Printf("Failed to obtain Let's Encrypt certificate for %s: %v", newDomain, err)
						// Update status to failed
						for j, existing := range config.LoadBalancers {
							if existing.Domain == newDomain {
								config.LoadBalancers[j].SSLStatus = "failed"
								saveConfig()
								break
							}
						}
					} else {
						log.Printf("Successfully obtained Let's Encrypt certificate for %s", newDomain)
						// Update status to active and regenerate nginx config
						for j, existing := range config.LoadBalancers {
							if existing.Domain == newDomain {
								config.LoadBalancers[j].SSLStatus = "active"
								saveConfig()
								generateNginxConfig()
								
								// Reload nginx with new certificate
								reloadCmd := exec.Command("nginx", "-s", "reload")
								if err := reloadCmd.Run(); err != nil {
									log.Printf("Failed to reload nginx after certificate installation: %v", err)
								}
								break
							}
						}
					}
				}()
			}
			
			c.Redirect(http.StatusSeeOther, "/dashboard")
			return
		}
	}
	
	c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
}

func deleteLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")
	
	for i, lb := range config.LoadBalancers {
		if lb.Domain == domain {
			config.LoadBalancers = append(config.LoadBalancers[:i], config.LoadBalancers[i+1:]...)
			break
		}
	}
	
	saveConfig()
	generateNginxConfig()
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func checkNginxConfig(c *gin.Context) {
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": string(output),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"message": string(output),
	})
}

func reloadNginx(c *gin.Context) {
	// First check if config is valid
	testCmd := exec.Command("nginx", "-t")
	testOutput, testErr := testCmd.CombinedOutput()
	
	if testErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Nginx configuration is invalid. Please check your load balancer settings.",
			"details": string(testOutput),
			"fix_suggestion": "Review your domain names and upstream server addresses. Make sure all domains are valid and all upstream servers are in IP:PORT format.",
		})
		return
	}
	
	// If config is valid, proceed with reload
	reloadCmd := exec.Command("nginx", "-s", "reload")
	reloadOutput, reloadErr := reloadCmd.CombinedOutput()
	
	if reloadErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to reload nginx",
			"details": string(reloadOutput),
			"suggestion": "Check nginx logs for more details",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status": "reloaded",
		"message": "Nginx configuration reloaded successfully",
	})
}

func getNginxLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "error")
	lines := c.DefaultQuery("lines", "50")
	
	var logFile string
	switch logType {
	case "access":
		logFile = "/app/data/logs/nginx-access.log"
	case "error":
		logFile = "/app/data/logs/nginx-error.log"
	case "app":
		logFile = "/app/data/logs/app-error.log"
	case "app-access":
		logFile = "/app/data/logs/app-access.log"
	case "letsencrypt":
		logFile = "/app/data/logs/letsencrypt.log"
	default:
		logFile = "/app/data/logs/nginx-error.log"
	}
	
	cmd := exec.Command("tail", "-n", lines, logFile)
	output, err := cmd.Output()
	
	if err != nil {
		// Try fallbacks for different log types
		switch logType {
		case "error":
			// Try supervisor logs as fallback for nginx errors
			supervisorLog := "/var/log/supervisor/supervisord.log"
			cmd = exec.Command("grep", "nginx", supervisorLog)
			if fallbackOutput, fallbackErr := cmd.Output(); fallbackErr == nil {
				output = fallbackOutput
				err = nil
			}
		case "letsencrypt":
			// If Let's Encrypt log doesn't exist, return helpful message
			output = []byte("No Let's Encrypt logs found. This usually means no HTTPS certificates have been requested yet.\n\nTo generate logs:\n1. Create an HTTPS load balancer\n2. Ensure domain points to this server\n3. Wait for certificate generation to complete")
			err = nil
		case "app", "app-access":
			// If app logs don't exist, return helpful message
			output = []byte("Application logs not found. This might indicate the application just started.\n\nTry refreshing in a few moments or check container startup logs.")
			err = nil
		}
	}
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read nginx logs",
			"details": err.Error(),
			"suggestion": "Logs might be redirected to supervisor. Check container logs with 'docker logs'.",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"logs": string(output),
		"type": logType,
		"lines": lines,
	})
}

func getConfig(c *gin.Context) {
	configPath := "/app/data/nginx/loadbalancer.conf"
	
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"content": "# No load balancer configuration found\n# Add load balancers through the UI to generate configuration",
			"exists": false,
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"content": string(content),
		"exists": true,
	})
}

func updateConfig(c *gin.Context) {
	newConfig := c.PostForm("config")
	configPath := "/app/data/nginx/loadbalancer.conf"
	
	// Create backup before updating
	if _, err := os.Stat(configPath); err == nil {
		backupPath := configPath + ".backup." + strings.ReplaceAll(strings.ReplaceAll(os.Getenv("NGINX_PORT"), ":", "-"), " ", "_")
		if backupData, backupErr := ioutil.ReadFile(configPath); backupErr == nil {
			ioutil.WriteFile(backupPath, backupData, 0644)
		}
	}
	
	// Write new config
	err := ioutil.WriteFile(configPath, []byte(newConfig), 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to write configuration file",
			"details": err.Error(),
		})
		return
	}
	
	// Test the new configuration
	testCmd := exec.Command("nginx", "-t")
	testOutput, testErr := testCmd.CombinedOutput()
	
	if testErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid nginx configuration",
			"details": string(testOutput),
			"suggestion": "Check your configuration syntax. The file has been saved but nginx will not reload with invalid configuration.",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status": "saved",
		"message": "Configuration saved and validated successfully",
		"test_output": string(testOutput),
	})
}

func backupConfig(c *gin.Context) {
	configPath := "/app/data/nginx/loadbalancer.conf"
	
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Configuration file not found",
		})
		return
	}
	
	filename := "loadbalancer-" + strings.ReplaceAll(strings.ReplaceAll(os.Getenv("NGINX_PORT"), ":", "-"), " ", "_") + ".conf"
	
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, string(content))
}

func retryCertificate(c *gin.Context) {
	domain := c.Param("domain")
	
	// Find the load balancer
	var lb *LoadBalancer
	for i, existing := range config.LoadBalancers {
		if existing.Domain == domain {
			lb = &config.LoadBalancers[i]
			break
		}
	}
	
	if lb == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
		return
	}
	
	if lb.Protocol != "https" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Load balancer is not configured for HTTPS"})
		return
	}
	
	if lb.SSLEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No email configured for SSL certificate"})
		return
	}
	
	// Update status to pending and save
	lb.SSLStatus = "pending"
	if err := saveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}
	
	log.Printf("Retrying Let's Encrypt certificate for domain: %s", domain)
	
	// Start certificate generation in background
	go func() {
		log.Printf("Requesting Let's Encrypt certificate for %s (retry)", domain)
		
		// Update SSL status to indicate processing
		for i, existing := range config.LoadBalancers {
			if existing.Domain == domain {
				config.LoadBalancers[i].SSLStatus = "requesting"
				saveConfig()
				break
			}
		}
		
		// Request certificate
		if err := requestLetsEncryptCertificate(domain, lb.SSLEmail); err != nil {
			log.Printf("Failed to obtain Let's Encrypt certificate for %s (retry): %v", domain, err)
			// Update status to failed
			for i, existing := range config.LoadBalancers {
				if existing.Domain == domain {
					config.LoadBalancers[i].SSLStatus = "failed"
					saveConfig()
					break
				}
			}
		} else {
			log.Printf("Successfully obtained Let's Encrypt certificate for %s (retry)", domain)
			// Update status to active and regenerate nginx config
			for i, existing := range config.LoadBalancers {
				if existing.Domain == domain {
					config.LoadBalancers[i].SSLStatus = "active"
					saveConfig()
					generateNginxConfig()
					
					// Reload nginx with new certificate
					reloadCmd := exec.Command("nginx", "-s", "reload")
					if err := reloadCmd.Run(); err != nil {
						log.Printf("Failed to reload nginx after certificate installation (retry): %v", err)
					}
					break
				}
			}
		}
	}()
	
	c.JSON(http.StatusOK, gin.H{
		"status": "started",
		"message": "Certificate retry started in background",
		"domain": domain,
	})
}

func handleLogout(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	session.Values["authenticated"] = false
	session.Save(c.Request, c.Writer)
	c.Redirect(http.StatusSeeOther, "/")
}

func generateNginxConfig() {
	tmpl := `
{{range .LoadBalancers}}
# Load balancing method: {{.Config.Method}}{{if .Config.SessionSticky}} (Session Sticky){{end}}
upstream {{.Domain | sanitize}}_backend {
    {{if eq .Config.Method "least_conn"}}least_conn;{{end}}
    {{if eq .Config.Method "ip_hash"}}ip_hash;{{end}}
    {{if eq .Config.Method "hash"}}hash {{.Config.HashKey}} consistent;{{end}}
    
    {{range .Upstreams}}
    server {{.Host}}:{{.Port}}{{if ne .Weight 1}} weight={{.Weight}}{{end}}{{if ne .MaxFails 3}} max_fails={{.MaxFails}}{{end}}{{if ne .FailTimeout "10s"}} fail_timeout={{.FailTimeout}}{{end}};
    {{end}}
}

{{if .Config.EnableCache}}
# Proxy cache configuration for {{.Domain}}
proxy_cache_path /tmp/cache/{{.Domain | sanitize}} levels=1:2 keys_zone={{.Domain | sanitize}}_cache:10m max_size=100m inactive={{.Config.CacheTime}};
{{end}}

server {
    {{if eq .Protocol "https"}}
    listen 443 ssl;
    {{else}}
    listen 80;
    {{end}}
    server_name {{.Domain}};

    {{if eq .Protocol "https"}}
    # SSL configuration
    {{if eq .SSLStatus "active"}}
    # Let's Encrypt certificates
    ssl_certificate /app/data/letsencrypt/live/{{.Domain}}/fullchain.pem;
    ssl_certificate_key /app/data/letsencrypt/live/{{.Domain}}/privkey.pem;
    {{else}}
    # Fallback to dummy certificate (development/pending)
    ssl_certificate /etc/nginx/ssl/dummy.crt;
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
    {{end}}
    
    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    {{end}}

    # ACME challenge location for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /app/data/certbot;
        try_files $uri =404;
    }

    location / {
        proxy_pass http://{{.Domain | sanitize}}_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        {{if eq .Protocol "https"}}
        proxy_set_header X-Forwarded-Proto https;
        {{else}}
        proxy_set_header X-Forwarded-Proto http;
        {{end}}
        
        {{if .Config.EnableCache}}
        # Caching configuration
        proxy_cache {{.Domain | sanitize}}_cache;
        proxy_cache_valid 200 302 {{.Config.CacheTime}};
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
        proxy_cache_revalidate on;
        proxy_cache_lock on;
        add_header X-Cache-Status $upstream_cache_status;
        {{end}}
        
        # Timeouts and buffers
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}

{{if eq .Protocol "https"}}
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name {{.Domain}};
    
    # ACME challenge location for Let's Encrypt (must be served over HTTP)
    location /.well-known/acme-challenge/ {
        root /app/data/certbot;
        try_files $uri =404;
    }
    
    # Redirect all other requests to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}
{{end}}
{{end}}
`

	funcMap := template.FuncMap{
		"replace": strings.ReplaceAll,
		"sanitize": func(domain string) string {
			// Replace dots with underscores and remove any invalid characters
			sanitized := strings.ReplaceAll(domain, ".", "_")
			sanitized = strings.ReplaceAll(sanitized, "-", "_")
			// Remove any non-alphanumeric characters except underscores
			result := ""
			for _, char := range sanitized {
				if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' {
					result += string(char)
				}
			}
			// Ensure it doesn't start with a number
			if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
				result = "lb_" + result
			}
			// Handle empty result
			if result == "" {
				result = "default_lb"
			}
			return result
		},
	}

	t, err := template.New("nginx").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		log.Printf("Template error: %v", err)
		return
	}

	os.MkdirAll("/app/data/nginx", 0755)
	
	// Create cache directories for load balancers with caching enabled
	for _, lb := range config.LoadBalancers {
		if lb.Config.EnableCache {
			cacheDir := "/tmp/cache"
			if err := os.MkdirAll(cacheDir, 0755); err != nil {
				log.Printf("Failed to create cache directory %s: %v", cacheDir, err)
			} else {
				log.Printf("Created cache directory: %s", cacheDir)
			}
		}
	}
	
	file, err := os.Create("/app/data/nginx/loadbalancer.conf")
	if err != nil {
		log.Printf("File creation error: %v", err)
		return
	}
	defer file.Close()

	err = t.Execute(file, config)
	if err != nil {
		log.Printf("Template execution error: %v", err)
	}
}
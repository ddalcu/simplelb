// Package main implements SimpleLB - a minimal web interface for managing
// Caddy load balancers via the Caddy Admin API.
// No config files, no parsing - pure API calls.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

// Configuration constants
const (
	DefaultManagementPort = "81"
	DefaultAdminUsername  = "admin"
	DefaultAdminPassword  = "password"
	CaddyAdminURL         = "http://127.0.0.1:2019"
	RequestTimeout        = 30 * time.Second
	SessionName           = "simple-lb-session"
	
	// Rate limiting defaults
	DefaultRateLimit = 60    // requests per minute
)

// Simple UI request structure (protocol and ssl email removed; automatic HTTPS is global)
type LoadBalancerRequest struct {
	Domain   string `json:"domain"`
	Backends string `json:"backends"`
	Method   string `json:"method"`
	HashKey  string `json:"hash_key,omitempty"`
}

// Caddy typed structures for the subset we use
type SelectionPolicy struct {
	Policy string `json:"policy,omitempty"`
	Header string `json:"header,omitempty"`
	Cookie string `json:"cookie,omitempty"`
}

type LoadBalancing struct {
	SelectionPolicy *SelectionPolicy `json:"selection_policy,omitempty"`
}

type Upstream struct {
	Dial string `json:"dial"`
}

type Handle struct {
	Handler       string         `json:"handler"`
	Upstreams     []Upstream     `json:"upstreams,omitempty"`
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`
}

type Match struct {
	Host []string `json:"host,omitempty"`
}

type CaddyRoute struct {
	Match  []Match  `json:"match,omitempty"`
	Handle []Handle `json:"handle,omitempty"`
}

// Application holds the application state
// Simple rate limiter for tracking per-IP rate limits
type IPRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	rate     rate.Limit
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(rateLimit rate.Limit) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rateLimit,
	}
}

// GetLimiter returns a rate limiter for the given IP
func (rl *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, 30) // Allow burst of 30 requests
		rl.limiters[ip] = limiter
	}
	return limiter
}

type Application struct {
	store      *sessions.CookieStore
	httpClient *http.Client
	logger     *slog.Logger
	limiter    *IPRateLimiter
}

// NewApplication creates a new application instance
func NewApplication() *Application {
	// Set up file logging for the application
	logFile, err := os.OpenFile("/app/data/logs/simplelb/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fall back to stdout if file logging fails
		logFile = os.Stdout
	}

	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Get session secret from environment or use a default (not recommended for production)
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "default-secret-key-change-this-in-production"
		logger.Warn("Using default session secret - set SESSION_SECRET environment variable for production")
	}

	store := sessions.NewCookieStore([]byte(sessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
		Secure:   os.Getenv("SESSION_COOKIE_SECURE") == "1",
	}

	// Rate limiting configuration
	rateLimit := DefaultRateLimit
	if envRate := getEnv("GENERAL_RATE_LIMIT", ""); envRate != "" {
		if parsed := parseInt(envRate, DefaultRateLimit); parsed > 0 {
			rateLimit = parsed
		}
	}

	// Create rate limiter (rate per minute, with 4x slower refill)
	limiter := NewIPRateLimiter(rate.Limit(rateLimit) / 60.0 / 4.0)

	logger.Info("Rate limiting configured", "requests_per_minute", rateLimit)

	return &Application{
		store:      store,
		httpClient: &http.Client{Timeout: RequestTimeout},
		logger:     logger,
		limiter:    limiter,
	}
}

// CaddyAPI helper methods
func (app *Application) callCaddyAPI(method, path string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	baseURL := getEnv("CADDY_ADMIN_URL", CaddyAdminURL)
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := app.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Caddy API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Caddy API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (app *Application) getCaddyConfig() (map[string]interface{}, error) {
	respBody, err := app.callCaddyAPI("GET", "/config/", nil)
	if err != nil {
		return nil, err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(respBody, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}

// Simplified casting helpers
func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func asArray(v interface{}) []interface{} {
	if a, ok := v.([]interface{}); ok {
		return a
	}
	return nil
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Get routes directly from Caddy HTTP server routes endpoint
func (app *Application) getCaddyRoutes() ([]CaddyRoute, error) {
	respBody, err := app.callCaddyAPI("GET", "/config/apps/http/servers/main/routes", nil)
	if err != nil {
		return []CaddyRoute{}, nil
	}
	var routes []CaddyRoute
	if err := json.Unmarshal(respBody, &routes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal routes: %w", err)
	}
	return routes, nil
}

func (app *Application) getLoadBalancers() ([]map[string]interface{}, error) {
	routes, err := app.getCaddyRoutes()
	if err != nil {
		return nil, err
	}
	var loadBalancers []map[string]interface{}
	for _, route := range routes {
		if lb := app.parseRouteToLoadBalancer(route); lb != nil {
			loadBalancers = append(loadBalancers, lb)
		}
	}
	return loadBalancers, nil
}

// Extract domains from route match - supports multiple hosts
func (app *Application) parseRouteToLoadBalancer(route CaddyRoute) map[string]interface{} {
	if len(route.Match) == 0 || len(route.Match[0].Host) == 0 {
		return nil
	}
	hosts := route.Match[0].Host
	if len(route.Handle) == 0 || route.Handle[0].Handler != "reverse_proxy" {
		return nil
	}
	var backends []string
	for _, u := range route.Handle[0].Upstreams {
		if strings.TrimSpace(u.Dial) != "" {
			backends = append(backends, u.Dial)
		}
	}
	method := "random"
	if lb := route.Handle[0].LoadBalancing; lb != nil && lb.SelectionPolicy != nil && strings.TrimSpace(lb.SelectionPolicy.Policy) != "" {
		method = lb.SelectionPolicy.Policy
	}
	return map[string]interface{}{
		"domain":   hosts[0],                       // Primary domain for compatibility
		"domains":  hosts,                          // All domains
		"backends": backends,
		"method":   method,
	}
}

func (app *Application) initializeCaddyConfig() error {
	// Try to load saved configuration first
	savedConfig, err := app.loadSavedConfig()
	if err == nil && savedConfig != nil {
		app.logger.Info("Loading saved configuration")
		configJSON, err := json.Marshal(savedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal saved config: %w", err)
		}

		_, err = app.callCaddyAPI("POST", "/load", configJSON)
		if err != nil {
			app.logger.Warn("Failed to load saved config, initializing fresh", "error", err)
		} else {
			app.logger.Info("Saved configuration loaded successfully")
			return nil
		}
	} else {
		app.logger.Info("No saved config found, initializing fresh", "error", err)
	}

	// Attempt to set a minimal, modern config that enables both HTTP and HTTPS
	// with automatic HTTPS (default). If Caddy already has config, this may fail, which is acceptable.
	initial := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"main": map[string]interface{}{
						"listen": []string{":80", ":443"},
						"routes": []interface{}{},
					},
				},
				"https_port":     443,
				"http_port":      80,
				"grace_period":   "5s",
				"shutdown_delay": "5s",
			},
			"tls": map[string]interface{}{
				"automation": map[string]interface{}{
					"policies": func() []interface{} {
						email := strings.TrimSpace(os.Getenv("ACME_EMAIL"))
						issuer := map[string]interface{}{"module": "acme"}
						if email != "" {
							issuer["email"] = email
						}
						return []interface{}{
							map[string]interface{}{
								"issuers": []interface{}{issuer},
							},
						}
					}(),
				},
			},
		},
		"logging": map[string]interface{}{
			"logs": map[string]interface{}{
				"default": map[string]interface{}{
					"writer": map[string]interface{}{
						"output":   "file",
						"filename": "/app/data/logs/caddy/error.log",
					},
					"level": "INFO",
				},
				"access": map[string]interface{}{
					"writer": map[string]interface{}{
						"output":   "file",
						"filename": "/app/data/logs/caddy/access.log",
					},
					"encoder": map[string]interface{}{
						"format": "json",
					},
				},
			},
		},
	}

	configJSON, err := json.Marshal(initial)
	if err != nil {
		return fmt.Errorf("failed to marshal initial config: %w", err)
	}
	if _, err := app.callCaddyAPI("POST", "/load", configJSON); err != nil {
		app.logger.Warn("Failed to load initial config (may already be configured)", "error", err)
	}
	return nil
}

func (app *Application) createLoadBalancer(req LoadBalancerRequest) error {
	// Ensure Caddy config is initialized
	if err := app.initializeCaddyConfig(); err != nil {
		return fmt.Errorf("failed to initialize Caddy config: %w", err)
	}

	// Parse domains (comma-delimited)
	domainList := strings.Split(strings.TrimSpace(req.Domain), ",")
	var hosts []string
	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			hosts = append(hosts, domain)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("at least one domain is required")
	}

	// Parse backends
	backendLines := strings.Split(strings.TrimSpace(req.Backends), "\n")
	var upstreams []map[string]interface{}

	for _, line := range backendLines {
		line = strings.TrimSpace(line)
		if line != "" {
			upstreams = append(upstreams, map[string]interface{}{
				"dial": line,
			})
		}
	}

	if len(upstreams) == 0 {
		return fmt.Errorf("at least one backend is required")
	}

	// Build typed handler and route (Caddy Automatic HTTPS handles redirects)
	handler := Handle{Handler: "reverse_proxy", Upstreams: make([]Upstream, 0, len(upstreams))}
	for _, u := range upstreams {
		handler.Upstreams = append(handler.Upstreams, Upstream{Dial: u["dial"].(string)})
	}
	if req.Method != "random" && req.Method != "" {
		sp := &SelectionPolicy{Policy: req.Method}
		if (req.Method == "header" || req.Method == "cookie") && req.HashKey != "" {
			if req.Method == "header" {
				sp.Header = req.HashKey
			} else {
				sp.Cookie = req.HashKey
			}
		}
		handler.LoadBalancing = &LoadBalancing{SelectionPolicy: sp}
	}
	route := CaddyRoute{
		Match:  []Match{{Host: hosts}},
		Handle: []Handle{handler},
	}

	routeJSON, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("failed to marshal route: %w", err)
	}
	if _, err := app.callCaddyAPI("POST", "/config/apps/http/servers/main/routes", routeJSON); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	// Save configuration to make it persistent
	if err := app.saveConfig(); err != nil {
		app.logger.Warn("Failed to save config", "error", err)
	}

	// Log the creation
	app.logger.Info("Load balancer created",
		"domains", strings.Join(hosts, ", "),
		"method", req.Method,
		"backends", len(upstreams))

	return nil
}

// Find route index by domain - handles multiple hosts
func (app *Application) deleteLoadBalancer(domain string) error {
	routes, err := app.getCaddyRoutes()
	if err != nil {
		return err
	}

	var indices []int
	for i, route := range routes {
		if len(route.Match) > 0 && len(route.Match[0].Host) > 0 {
			// Check if the domain is in the host list
			for _, host := range route.Match[0].Host {
				if host == domain {
					indices = append(indices, i)
					break // Found the route, no need to check other hosts
				}
			}
		}
	}
	if len(indices) == 0 {
		return fmt.Errorf("load balancer not found")
	}

	sort.Sort(sort.Reverse(sort.IntSlice(indices)))
	for _, idx := range indices {
		if _, err := app.callCaddyAPI("DELETE", fmt.Sprintf("/config/apps/http/servers/main/routes/%d", idx), nil); err != nil {
			return fmt.Errorf("failed to delete route %d: %w", idx, err)
		}
	}

	if err := app.saveConfig(); err != nil {
		app.logger.Warn("Failed to save config after deletion", "error", err)
	}
	return nil
}

// saveConfig saves the current Caddy configuration to disk for persistence
func (app *Application) saveConfig() error {
	// Snapshot current Caddy config and write to a fixed path
	resp, err := app.callCaddyAPI("GET", "/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}
	// Pretty print JSON for readability
	var cfg any
	if err := json.Unmarshal(resp, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	formatted, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format config: %w", err)
	}
	if err := os.MkdirAll("/app/data/caddy/config", 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	if err := os.WriteFile("/app/data/caddy/config/caddy.json", formatted, 0644); err != nil {
		return fmt.Errorf("failed to write config snapshot: %w", err)
	}
	app.logger.Info("Configuration snapshot saved", "path", "/app/data/caddy/config/caddy.json")
	return nil
}

// loadSavedConfig loads the saved Caddy configuration from disk
func (app *Application) loadSavedConfig() (map[string]interface{}, error) {
	configPath := "/app/data/caddy/config/caddy.json"

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no saved config found")
	}

	// Read config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config map[string]interface{}
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	app.logger.Info("Loaded saved configuration from disk", "path", configPath)
	return config, nil
}

// Middleware
func (app *Application) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := app.store.Get(c.Request, SessionName)
		if err != nil {
			app.logger.Error("Failed to get session", "error", err)
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
			return
		}

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (app *Application) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		// HSTS only for HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// HTTP Handlers
func (app *Application) ShowLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func (app *Application) HandleLogin(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")

	expectedUser := getEnv("ADMIN_USERNAME", DefaultAdminUsername)
	expectedPass := getEnv("ADMIN_PASSWORD", DefaultAdminPassword)

	if username == expectedUser && password == expectedPass {
		session, err := app.store.Get(c.Request, SessionName)
		if err != nil {
			app.logger.Error("Failed to get session", "error", err)
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{"error": "Session error"})
			return
		}

		session.Values["authenticated"] = true
		if err := session.Save(c.Request, c.Writer); err != nil {
			app.logger.Error("Failed to save session", "error", err)
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{"error": "Session error"})
			return
		}

		c.Redirect(http.StatusSeeOther, "/dashboard")
	} else {
		app.logger.Warn("Failed login attempt", "username", username, "ip", c.ClientIP())
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid credentials"})
	}
}

func (app *Application) ShowDashboard(c *gin.Context) {
	loadBalancers, err := app.getLoadBalancers()
	if err != nil {
		app.logger.Error("Failed to get load balancers", "error", err)
		loadBalancers = []map[string]interface{}{}
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{"loadBalancers": loadBalancers})
}

func (app *Application) AddLoadBalancer(c *gin.Context) {
	req := LoadBalancerRequest{
		Domain:   strings.TrimSpace(c.PostForm("domain")),
		Backends: strings.TrimSpace(c.PostForm("backends")),
		Method:   c.DefaultPostForm("method", "random"),
		HashKey:  strings.TrimSpace(c.PostForm("hash_key")),
	}

	// Basic validation - check each domain in comma-delimited list
	if req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}
	
	// Validate each domain
	domains := strings.Split(strings.TrimSpace(req.Domain), ",")
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.Contains(domain, ".") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain format: " + domain})
			return
		}
	}

	if req.Backends == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one backend required"})
		return
	}

	if err := app.createLoadBalancer(req); err != nil {
		app.logger.Error("Failed to create load balancer", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create load balancer"})
		return
	}

	app.logger.Info("Created load balancer", "domain", req.Domain)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) GetLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")

	// Find the load balancer
	loadBalancers, err := app.getLoadBalancers()
	if err != nil {
		app.logger.Error("Failed to get load balancers", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get load balancers"})
		return
	}

	for _, lb := range loadBalancers {
		if lbDomain, ok := lb["domain"].(string); ok && lbDomain == domain {
			// Convert backends array to string
			backends := []string{}
			if backendsArray, ok := lb["backends"].([]string); ok {
				backends = backendsArray
			}

			// Convert domains array to comma-separated string  
			domainString := domain // fallback to primary domain
			if domainsArray, ok := lb["domains"].([]string); ok && len(domainsArray) > 0 {
				domainString = strings.Join(domainsArray, ", ")
			}

			response := map[string]interface{}{
				"domain":   domainString,
				"method":   lb["method"],
				"backends": strings.Join(backends, "\n"),
			}

			c.JSON(http.StatusOK, response)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
}

func (app *Application) UpdateLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")

	req := LoadBalancerRequest{
		Domain:   strings.TrimSpace(c.PostForm("domain")),
		Backends: strings.TrimSpace(c.PostForm("backends")),
		Method:   c.DefaultPostForm("method", "random"),
		HashKey:  strings.TrimSpace(c.PostForm("hash_key")),
	}

	// Basic validation
	if req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain is required"})
		return
	}
	
	// Validate each domain  
	domains := strings.Split(strings.TrimSpace(req.Domain), ",")
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.Contains(domain, ".") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain format: " + domain})
			return
		}
	}

	if req.Backends == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one backend required"})
		return
	}

	// Replace: delete old, create new
	if err := app.deleteLoadBalancer(domain); err != nil {
		app.logger.Error("Delete failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update failed"})
		return
	}

	if err := app.createLoadBalancer(req); err != nil {
		app.logger.Error("Create failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update failed"})
		return
	}

	app.logger.Info("Updated load balancer", "domain", req.Domain)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) DeleteLoadBalancer(c *gin.Context) {
	domain := c.Param("domain")

	if err := app.deleteLoadBalancer(domain); err != nil {
		app.logger.Error("Failed to delete load balancer", "error", err, "domain", domain)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete load balancer: %v", err)})
		return
	}

	app.logger.Info("Deleted load balancer", "domain", domain)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) HandleLogout(c *gin.Context) {
	session, err := app.store.Get(c.Request, SessionName)
	if err != nil {
		app.logger.Error("Failed to get session during logout", "error", err)
	} else {
		session.Values["authenticated"] = false
		session.Save(c.Request, c.Writer)
	}
	c.Redirect(http.StatusSeeOther, "/")
}

func (app *Application) GetLogsData(c *gin.Context) {
	logType := c.DefaultQuery("type", "app")

	var logs string
	var logName string

	switch logType {
	case "app":
		logName = "Application Logs"
		// Show recent application activity and instructions
		logs = app.getApplicationLogs()
	case "caddy":
		logName = "Caddy Access Logs"
		logs = app.getCaddyLogs("access")
	case "caddy-error":
		logName = "Caddy Error Logs"
		logs = app.getCaddyLogs("error")
	default:
		logName = "Application Logs"
		logs = app.getApplicationLogs()
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":    logs,
		"logName": logName,
		"logType": logType,
	})
}

func (app *Application) ExportConfig(c *gin.Context) {
	config, err := app.getCaddyConfig()
	if err != nil {
		app.logger.Error("Failed to get Caddy config for export", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export configuration"})
		return
	}

	// Format JSON for readability
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		app.logger.Error("Failed to marshal config for export", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to format configuration"})
		return
	}

	app.logger.Info("Configuration exported")
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(configJSON))
}

func (app *Application) ImportConfig(c *gin.Context) {
	configData := strings.TrimSpace(c.PostForm("config"))
	if configData == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Configuration data is required"})
		return
	}

	// Validate JSON
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configData), &config); err != nil {
		app.logger.Warn("Invalid JSON in import request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON configuration"})
		return
	}

	// Load the configuration into Caddy
	if _, err := app.callCaddyAPI("POST", "/load", []byte(configData)); err != nil {
		app.logger.Error("Failed to load imported config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration into Caddy"})
		return
	}

	// Save the new configuration
	if err := app.saveConfig(); err != nil {
		app.logger.Warn("Failed to save imported config", "error", err)
		// Don't fail the request, just log the warning
	}

	app.logger.Info("Configuration imported successfully")
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) getApplicationLogs() string {
	// Try to read from multiple possible log sources
	logSources := []string{
		"/app/data/logs/simplelb/app.log",
		"/app/data/logs/simplelb/app-stdout.log",
		"/app/data/logs/simplelb/app-stderr.log",
	}

	for _, logFile := range logSources {
		if logs, err := app.getTailLogs(logFile, 1000); err == nil {
			return logs
		}
	}

	// If no log files found, return basic info with instructions
	return fmt.Sprintf(`=== APPLICATION LOGS ===

No application log file found at standard locations:
%s

Current Status:
- SimpleLB Management Interface: Running on port %s
- Session Store: Active
- Time: %s

To enable file logging, set up log output in the application or use:
docker logs --tail 1000 -f <container-name>

Load Balancers Status:
%s`,
		strings.Join(logSources, "\n"),
		getEnv("MANAGEMENT_PORT", DefaultManagementPort),
		time.Now().Format("2006-01-02 15:04:05"),
		app.getLoadBalancerStatus())
}

func (app *Application) getLoadBalancerStatus() string {
	loadBalancers, err := app.getLoadBalancers()
	if err != nil {
		return "- Error retrieving load balancers"
	}

	if len(loadBalancers) == 0 {
		return "- No load balancers configured"
	}

	var status []string
	for _, lb := range loadBalancers {
		if domain, ok := lb["domain"].(string); ok {
			status = append(status, fmt.Sprintf("- %s", domain))
		}
	}
	return strings.Join(status, "\n")
}

func (app *Application) getCaddyLogs(logType string) string {
	logFiles := map[string][]string{
		"access": {"/app/data/logs/caddy/access.log", "/app/data/logs/caddy/caddy-stdout.log"},
		"error":  {"/app/data/logs/caddy/error.log", "/app/data/logs/caddy/caddy-stderr.log"},
	}

	files := logFiles[logType]
	if files == nil {
		files = logFiles["error"]
	}

	for _, logFile := range files {
		if logs, err := app.getTailLogs(logFile, 1000); err == nil {
			return fmt.Sprintf("=== CADDY %s LOGS ===\nFile: %s\n\n%s",
				strings.ToUpper(logType), logFile, logs)
		}
	}

	return fmt.Sprintf("=== CADDY %s LOGS ===\n\nNo log files found at: %s\n\nConfigure Caddy logging to enable %s logs.",
		strings.ToUpper(logType), strings.Join(files, ", "), logType)
}

func (app *Application) getTailLogs(filename string, lines int) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}
	if stat.Size() == 0 {
		return "Log file is empty", nil
	}

	// Read approximately the last 64KB to collect up to the requested number of lines
	const approxBytes = 64 * 1024
	var start int64
	if stat.Size() > approxBytes {
		start = stat.Size() - approxBytes
	}
	if _, err := f.Seek(start, 0); err != nil {
		return "", fmt.Errorf("failed to seek: %w", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read log file: %w", err)
	}
	parts := strings.Split(string(data), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n"), nil
}

// generateSelfSignedCert generates a self-signed certificate for the management interface
func generateSelfSignedCert(certPath, keyPath string) error {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"SimpleLB"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost", "simple-lb"},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// setupTLS sets up TLS certificates for the management interface
func (app *Application) setupTLS() (string, string, error) {
	certDir := "/app/data/certs"
	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")

	// Create certificates directory
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Check if certificates already exist and are still valid
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// Check if certificate is still valid (not expired)
			certData, err := os.ReadFile(certPath)
			if err == nil {
				block, _ := pem.Decode(certData)
				if block != nil {
					cert, err := x509.ParseCertificate(block.Bytes)
					if err == nil && time.Now().Before(cert.NotAfter) {
						app.logger.Info("Using existing TLS certificate", "path", certPath)
						return certPath, keyPath, nil
					}
				}
			}
		}
	}

	// Generate new certificate
	app.logger.Info("Generating new TLS certificate for management interface")
	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		return "", "", err
	}

	app.logger.Info("TLS certificate generated successfully", "cert", certPath, "key", keyPath)
	return certPath, keyPath, nil
}

// Utility functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseInt parses an integer from string with fallback to default
func parseInt(s string, defaultValue int) int {
	if parsed := 0; len(s) > 0 {
		if n, err := fmt.Sscanf(s, "%d", &parsed); n == 1 && err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultValue
}

// getClientIP extracts the real client IP address from the request
func getClientIP(c *gin.Context) string {
	// Check X-Real-IP header first (common with proxies)
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}
	// Check X-Forwarded-For header (may contain multiple IPs)
	if ips := c.GetHeader("X-Forwarded-For"); ips != "" {
		// Take the first IP (original client)
		if parts := strings.Split(ips, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Fall back to remote address
	if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
		return ip
	}
	return c.Request.RemoteAddr
}

// RateLimitMiddleware creates a rate limiting middleware for all requests
func (app *Application) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)
		limiter := app.limiter.GetLimiter(ip)
		
		if !limiter.Allow() {
			app.logger.Warn("Rate limit exceeded", "ip", ip, "path", c.Request.URL.Path)
			
			// Different response format for HTML vs API endpoints
			if c.Request.URL.Path == "/" || c.Request.URL.Path == "/login" {
				c.HTML(http.StatusTooManyRequests, "login.html", gin.H{
					"error": "Rate limit exceeded. Please wait before trying again.",
				})
			} else {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded. Please try again later.",
				})
			}
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	app := NewApplication()

	// Initialize/restore Caddy configuration on startup (with retry)
	go func() {
		// Wait a bit for Caddy to start, then try to restore config
		time.Sleep(5 * time.Second)

		for i := 0; i < 5; i++ {
			if err := app.initializeCaddyConfig(); err != nil {
				app.logger.Warn("Failed to initialize Caddy config, retrying", "attempt", i+1, "error", err)
				time.Sleep(2 * time.Second)
			} else {
				app.logger.Info("Caddy configuration initialized successfully on startup")
				break
			}
		}
	}()

	// Set up Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), app.SecurityHeaders())

	r.LoadHTMLGlob("/app/templates/*")
	r.Static("/static", "/app/static")

	// Routes with rate limiting (50 requests per minute per IP)
	r.GET("/", app.RateLimitMiddleware(), app.ShowLogin)
	r.POST("/login", app.RateLimitMiddleware(), app.HandleLogin)
	r.GET("/dashboard", app.RateLimitMiddleware(), app.AuthRequired(), app.ShowDashboard)
	r.POST("/add", app.RateLimitMiddleware(), app.AuthRequired(), app.AddLoadBalancer)
	r.GET("/edit/:domain", app.RateLimitMiddleware(), app.AuthRequired(), app.GetLoadBalancer)
	r.POST("/edit/:domain", app.RateLimitMiddleware(), app.AuthRequired(), app.UpdateLoadBalancer)
	r.POST("/delete/:domain", app.RateLimitMiddleware(), app.AuthRequired(), app.DeleteLoadBalancer)
	r.GET("/export", app.RateLimitMiddleware(), app.AuthRequired(), app.ExportConfig)
	r.POST("/import", app.RateLimitMiddleware(), app.AuthRequired(), app.ImportConfig)
	r.GET("/api/logs", app.RateLimitMiddleware(), app.AuthRequired(), app.GetLogsData)
	r.GET("/logout", app.RateLimitMiddleware(), app.HandleLogout)

	// Get port
	port := getEnv("MANAGEMENT_PORT", DefaultManagementPort)

	// Setup TLS certificates for management interface
	certPath, keyPath, err := app.setupTLS()
	if err != nil {
		app.logger.Error("Failed to setup TLS", "error", err)
		os.Exit(1)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Start server with graceful shutdown
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConfig,
	}

	// Start HTTPS server in goroutine
	go func() {
		app.logger.Info("Starting HTTPS management server", "port", port, "cert", certPath)
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			app.logger.Error("Failed to start HTTPS server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	app.logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		app.logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	app.logger.Info("Server stopped")
}

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
	"database/sql"
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
	_ "modernc.org/sqlite"
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
	DefaultRateLimit = 60 // requests per minute

	// Configuration modes
	ConfigModeInitial = "initial" // Apply config only if no existing load balancers
	ConfigModeManaged = "managed" // Always apply config, UI read-only
)

// Simple UI request structure (protocol and ssl email removed; automatic HTTPS is global)
type LoadBalancerRequest struct {
	Domain   string `json:"domain"`
	Backends string `json:"backends"`
	Method   string `json:"method"`
	HashKey  string `json:"hash_key,omitempty"`
}

// Environment-based load balancer configuration
type EnvironmentLoadBalancer struct {
	Name     string
	Domains  string
	Backends string
	Method   string
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
// Simple rate limiter for tracking per-IP rate limits with cleanup
type IPRateLimiter struct {
	limiters   map[string]*ipLimiterEntry
	mu         sync.RWMutex
	rate       rate.Limit
	maxEntries int
}

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(rateLimit rate.Limit) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters:   make(map[string]*ipLimiterEntry),
		rate:       rateLimit,
		maxEntries: 10000, // Limit to 10k IPs max
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// GetLimiter returns a rate limiter for the given IP
func (rl *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	entry, exists := rl.limiters[ip]
	if exists {
		entry.lastSeen = time.Now()
		rl.mu.RUnlock()
		return entry.limiter
	}
	rl.mu.RUnlock()

	// Need to create new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check again in case another goroutine created it
	if entry, exists := rl.limiters[ip]; exists {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	// Prevent memory exhaustion
	if len(rl.limiters) >= rl.maxEntries {
		// Remove oldest entries
		rl.evictOldest()
	}

	limiter := rate.NewLimiter(rl.rate, 30)
	rl.limiters[ip] = &ipLimiterEntry{
		limiter:  limiter,
		lastSeen: time.Now(),
	}
	return limiter
}

// cleanup removes old unused limiters to prevent memory leaks
func (rl *IPRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute) // Remove IPs not seen for 30 minutes

		for ip, entry := range rl.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// evictOldest removes the oldest 20% of entries
func (rl *IPRateLimiter) evictOldest() {
	if len(rl.limiters) == 0 {
		return
	}

	// Find oldest entries
	type ipTime struct {
		ip   string
		time time.Time
	}

	var entries []ipTime
	for ip, entry := range rl.limiters {
		entries = append(entries, ipTime{ip: ip, time: entry.lastSeen})
	}

	// Sort by time (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].time.Before(entries[j].time)
	})

	// Remove oldest 20%
	toRemove := len(entries) / 5
	if toRemove < 100 {
		toRemove = 100 // Remove at least 100
	}

	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(rl.limiters, entries[i].ip)
	}
}

type Config struct {
	AdminUsername     string
	AdminPassword     string
	ManagementPort    string
	SessionSecret     string
	SessionSecure     bool
	CaddyAdminURL     string
	GeneralRateLimit  int
	ConfigMode        string
}

type Application struct {
	store      *sessions.CookieStore
	httpClient *http.Client
	logger     *slog.Logger
	limiter    *IPRateLimiter
	db         *sql.DB
	config     *Config
}

// LoadBalancer represents a load balancer configuration in the database
type LoadBalancer struct {
	ID               int        `json:"id"`
	Name             string     `json:"name"`
	Domains          string     `json:"domains"`  // JSON array of domains
	Backends         string     `json:"backends"` // JSON array of backends
	Method           string     `json:"method"`
	HashKey          string     `json:"hash_key,omitempty"`
	Status           string     `json:"status"`            // configured, active, inactive
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Source           string     `json:"source"`         // environment, ui, api
	CaddyDeployed    bool       `json:"caddy_deployed"` // whether it's currently deployed to Caddy
}

// LoadBalancerStatus represents different states of a load balancer
const (
	StatusConfigured = "configured" // Configured in database
	StatusActive     = "active"     // Deployed to Caddy and active
	StatusInactive   = "inactive"   // Temporarily disabled

	SourceEnvironment = "environment"
	SourceUI          = "ui"
	SourceAPI         = "api"
)

// initDatabase initializes the SQLite database and creates tables
func initDatabase() (*sql.DB, error) {
	// Ensure data directory exists
	if err := os.MkdirAll("/app/data", 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite", "/app/data/simplelb.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create tables
	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create database tables: %w", err)
	}

	return db, nil
}

// createTables creates the necessary database tables
func createTables(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS load_balancers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		domains TEXT NOT NULL,
		backends TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT 'random',
		hash_key TEXT,
		status TEXT NOT NULL DEFAULT 'configured',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		source TEXT NOT NULL DEFAULT 'ui',
		caddy_deployed BOOLEAN NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_load_balancers_name ON load_balancers(name);
	CREATE INDEX IF NOT EXISTS idx_load_balancers_status ON load_balancers(status);
	CREATE INDEX IF NOT EXISTS idx_load_balancers_source ON load_balancers(source);

	CREATE TRIGGER IF NOT EXISTS update_load_balancers_updated_at 
	AFTER UPDATE ON load_balancers
	BEGIN
		UPDATE load_balancers SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
	END;
	`

	_, err := db.Exec(query)
	return err
}

// Database helper methods for LoadBalancer

// GetAllLoadBalancers returns all load balancers from the database
func (app *Application) GetAllLoadBalancers() ([]LoadBalancer, error) {
	query := `
	SELECT id, name, domains, backends, method, COALESCE(hash_key, ''), 
	       status, created_at, updated_at, source, caddy_deployed
	FROM load_balancers 
	ORDER BY created_at DESC
	`

	rows, err := app.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var loadBalancers []LoadBalancer
	for rows.Next() {
		var lb LoadBalancer

		err := rows.Scan(
			&lb.ID, &lb.Name, &lb.Domains, &lb.Backends, &lb.Method, &lb.HashKey,
			&lb.Status, &lb.CreatedAt, &lb.UpdatedAt, &lb.Source, &lb.CaddyDeployed,
		)
		if err != nil {
			return nil, err
		}

		loadBalancers = append(loadBalancers, lb)
	}

	return loadBalancers, rows.Err()
}

// GetLoadBalancerByName returns a load balancer by name
func (app *Application) GetLoadBalancerByName(name string) (*LoadBalancer, error) {
	query := `
	SELECT id, name, domains, backends, method, COALESCE(hash_key, ''), 
	       status, created_at, updated_at, source, caddy_deployed
	FROM load_balancers 
	WHERE name = ?
	`

	var lb LoadBalancer

	err := app.db.QueryRow(query, name).Scan(
		&lb.ID, &lb.Name, &lb.Domains, &lb.Backends, &lb.Method, &lb.HashKey,
		&lb.Status, &lb.CreatedAt, &lb.UpdatedAt, &lb.Source, &lb.CaddyDeployed,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &lb, nil
}

// CreateLoadBalancer creates a new load balancer in the database
func (app *Application) CreateLoadBalancer(lb *LoadBalancer) error {
	query := `
	INSERT INTO load_balancers (name, domains, backends, method, hash_key, status, source, caddy_deployed)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := app.db.Exec(query, lb.Name, lb.Domains, lb.Backends, lb.Method, lb.HashKey, lb.Status, lb.Source, lb.CaddyDeployed)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	lb.ID = int(id)
	return nil
}

// UpdateLoadBalancerDB updates an existing load balancer in the database
func (app *Application) UpdateLoadBalancerDB(lb *LoadBalancer) error {
	query := `
	UPDATE load_balancers 
	SET domains = ?, backends = ?, method = ?, hash_key = ?, status = ?, caddy_deployed = ?
	WHERE name = ?
	`

	_, err := app.db.Exec(query, lb.Domains, lb.Backends, lb.Method, lb.HashKey, lb.Status, lb.CaddyDeployed, lb.Name)
	return err
}

// DeleteLoadBalancerDB deletes a load balancer by name from the database
func (app *Application) DeleteLoadBalancerDB(name string) error {
	query := `DELETE FROM load_balancers WHERE name = ?`
	_, err := app.db.Exec(query, name)
	return err
}

// GetActiveLoadBalancers returns load balancers that are deployed to Caddy
func (app *Application) GetActiveLoadBalancers() ([]LoadBalancer, error) {
	query := `
	SELECT id, name, domains, backends, method, COALESCE(hash_key, ''), 
	       status, created_at, updated_at, source, caddy_deployed
	FROM load_balancers 
	WHERE caddy_deployed = 1
	ORDER BY created_at DESC
	`

	rows, err := app.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var loadBalancers []LoadBalancer
	for rows.Next() {
		var lb LoadBalancer

		err := rows.Scan(
			&lb.ID, &lb.Name, &lb.Domains, &lb.Backends, &lb.Method, &lb.HashKey,
			&lb.Status, &lb.CreatedAt, &lb.UpdatedAt, &lb.Source, &lb.CaddyDeployed,
		)
		if err != nil {
			return nil, err
		}

		loadBalancers = append(loadBalancers, lb)
	}

	return loadBalancers, rows.Err()
}

func loadConfig() *Config {
	sessionSecure := os.Getenv("SESSION_COOKIE_SECURE") == "1"
	
	// Parse rate limit with fallback
	rateLimit := DefaultRateLimit
	if envRate := getEnv("GENERAL_RATE_LIMIT", ""); envRate != "" {
		if parsed := parseInt(envRate, DefaultRateLimit); parsed > 0 {
			rateLimit = parsed
		}
	}
	
	return &Config{
		AdminUsername:     getEnv("ADMIN_USERNAME", DefaultAdminUsername),
		AdminPassword:     getEnv("ADMIN_PASSWORD", DefaultAdminPassword),
		ManagementPort:    getEnv("MANAGEMENT_PORT", DefaultManagementPort),
		SessionSecret:     getEnv("SESSION_SECRET", "default-secret-key-change-this-in-production"),
		SessionSecure:     sessionSecure,
		CaddyAdminURL:     getEnv("CADDY_ADMIN_URL", CaddyAdminURL),
		GeneralRateLimit:  rateLimit,
		ConfigMode:        strings.ToLower(strings.TrimSpace(getEnv("CONFIG_MODE", ConfigModeInitial))),
	}
}

// NewApplication creates a new application instance
func NewApplication() *Application {
	config := loadConfig()

	// Initialize database first
	db, err := initDatabase()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize database: %v", err))
	}

	// Set up file logging for the application
	logFile, err := os.OpenFile("/app/data/logs/simplelb/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fall back to stdout if file logging fails
		logFile = os.Stdout
	}

	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if config.SessionSecret == "default-secret-key-change-this-in-production" {
		logger.Warn("Using default session secret - set SESSION_SECRET environment variable for production")
	}

	store := sessions.NewCookieStore([]byte(config.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
		Secure:   config.SessionSecure,
	}

	// Create rate limiter (rate per minute, with 4x slower refill)
	limiter := NewIPRateLimiter(rate.Limit(config.GeneralRateLimit) / 60.0 / 4.0)

	logger.Info("Rate limiting configured", "requests_per_minute", config.GeneralRateLimit)

	// Create simple HTTP client
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	return &Application{
		store:      store,
		httpClient: &http.Client{
			Timeout:   RequestTimeout,
			Transport: transport,
		},
		logger:     logger,
		limiter:    limiter,
		db:         db,
		config:     config,
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

	baseURL := app.config.CaddyAdminURL
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



// parseEnvironmentLoadBalancers discovers and parses LB_* environment variables
func (app *Application) parseEnvironmentLoadBalancers() ([]EnvironmentLoadBalancer, error) {
	var loadBalancers []EnvironmentLoadBalancer
	nameMap := make(map[string]*EnvironmentLoadBalancer)

	envCount := 0
	lbCount := 0

	// Scan all environment variables for LB_ patterns
	for _, env := range os.Environ() {
		envCount++
		if strings.HasPrefix(env, "LB_") {
			lbCount++
		}
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// Look for LB_DOMAINS_, LB_BACKENDS_, LB_METHOD_ patterns
		if strings.HasPrefix(key, "LB_DOMAINS_") {
			name := strings.TrimPrefix(key, "LB_DOMAINS_")
			if name == "" {
				continue
			}

			if nameMap[name] == nil {
				nameMap[name] = &EnvironmentLoadBalancer{Name: name}
			}
			nameMap[name].Domains = strings.TrimSpace(value)
		} else if strings.HasPrefix(key, "LB_BACKENDS_") {
			name := strings.TrimPrefix(key, "LB_BACKENDS_")
			if name == "" {
				continue
			}

			if nameMap[name] == nil {
				nameMap[name] = &EnvironmentLoadBalancer{Name: name}
			}
			nameMap[name].Backends = strings.TrimSpace(value)
		} else if strings.HasPrefix(key, "LB_METHOD_") {
			name := strings.TrimPrefix(key, "LB_METHOD_")
			if name == "" {
				continue
			}

			if nameMap[name] == nil {
				nameMap[name] = &EnvironmentLoadBalancer{Name: name}
			}
			nameMap[name].Method = strings.TrimSpace(value)
		}
	}


	// Validate and collect load balancers
	for name, lb := range nameMap {
		// Validate required fields
		if lb.Domains == "" {
			app.logger.Warn("Skipping load balancer: missing domains", "name", name)
			continue
		}
		if lb.Backends == "" {
			app.logger.Warn("Skipping load balancer: missing backends", "name", name)
			continue
		}

		// Store all environment load balancers in database
		// They can be deployed later via the UI

		// Set default method if not specified
		if lb.Method == "" {
			lb.Method = "random"
		}

		loadBalancers = append(loadBalancers, *lb)
	}

	return loadBalancers, nil
}


// Get routes directly from Caddy HTTP server routes endpoint

func (app *Application) initializeCaddyConfig() error {
	app.logger.Info("Initializing Caddy configuration", "mode", app.config.ConfigMode)

	// Parse environment load balancers
	envLoadBalancers, err := app.parseEnvironmentLoadBalancers()
	if err != nil {
		app.logger.Error("Failed to parse environment load balancers", "error", err)
		return fmt.Errorf("failed to parse environment load balancers: %w", err)
	}

	// Handle configuration based on mode
	switch app.config.ConfigMode {
	case ConfigModeManaged:
		// In managed mode, always apply environment configuration
		app.logger.Info("Managed mode: applying environment configuration", "load_balancer_count", len(envLoadBalancers))
		return app.applyEnvironmentConfiguration(envLoadBalancers)

	case ConfigModeInitial:
		// In initial mode, try to load saved config first
		if app.loadSavedConfigIfExists() {
			// Saved config loaded successfully, only apply environment config if no load balancers exist
			existingLBs, err := app.GetAllLoadBalancers()
			if err != nil {
				app.logger.Warn("Failed to check existing load balancers", "error", err)
			} else if len(existingLBs) == 0 && len(envLoadBalancers) > 0 {
				app.logger.Info("No existing load balancers found, applying initial environment configuration", "count", len(envLoadBalancers))
				return app.applyEnvironmentLoadBalancers(envLoadBalancers)
			} else if len(existingLBs) > 0 {
				app.logger.Info("Existing load balancers found, skipping environment configuration", "existing_count", len(existingLBs))
			}
			return nil
		}

		// No saved config, initialize fresh and apply environment config
		if err := app.initializeFreshCaddyConfig(); err != nil {
			return err
		}

		if len(envLoadBalancers) > 0 {
			app.logger.Info("Applying initial environment configuration", "count", len(envLoadBalancers))
			// Store in database
			if err := app.applyEnvironmentLoadBalancers(envLoadBalancers); err != nil {
				return err
			}
			
			// Deploy to Caddy
			for _, envLB := range envLoadBalancers {
				req := LoadBalancerRequest{
					Domain:   envLB.Domains,
					Backends: envLB.Backends,
					Method:   envLB.Method,
				}
				if err := app.createLoadBalancerInternal(req); err != nil {
					app.logger.Error("Failed to deploy load balancer to Caddy", "name", envLB.Name, "error", err)
				} else {
					app.logger.Info("Deployed load balancer to Caddy", "name", envLB.Name)
					// Mark as deployed in database
					if lb, err := app.GetLoadBalancerByName(envLB.Name); err == nil && lb != nil {
						lb.CaddyDeployed = true
						if err := app.UpdateLoadBalancerDB(lb); err != nil {
							app.logger.Error("Failed to update deployment status", "name", envLB.Name, "error", err)
						}
					}
				}
			}
		}

		return nil
	}

	return fmt.Errorf("unknown configuration mode: %s", app.config.ConfigMode)
}

// loadSavedConfigIfExists attempts to load saved configuration and returns true if successful
func (app *Application) loadSavedConfigIfExists() bool {
	savedConfig, err := app.loadSavedConfig()
	if err != nil || savedConfig == nil {
		app.logger.Info("No saved config found, will initialize fresh", "error", err)
		return false
	}

	app.logger.Info("Loading saved configuration")
	configJSON, err := json.Marshal(savedConfig)
	if err != nil {
		app.logger.Warn("Failed to marshal saved config", "error", err)
		return false
	}

	_, err = app.callCaddyAPI("POST", "/load", configJSON)
	if err != nil {
		app.logger.Warn("Failed to load saved config", "error", err)
		return false
	}

	app.logger.Info("Saved configuration loaded successfully")
	return true
}


// initializeFreshCaddyConfig sets up a minimal base Caddy configuration
func (app *Application) initializeFreshCaddyConfig() error {
	// Always listen on both HTTP and HTTPS ports
	// First ensure wildcard certificate exists for HTTPS
	if err := app.ensureWildcardCertificate(); err != nil {
		app.logger.Error("Failed to ensure wildcard certificate", "error", err)
		return fmt.Errorf("failed to ensure wildcard certificate: %w", err)
	}

	// Configure server to listen on both ports
	serverConfig := map[string]interface{}{
		"listen": []string{":80", ":443"},
		"routes": []interface{}{},
		"automatic_https": map[string]interface{}{
			"disable_redirects": true,  // Don't automatically redirect HTTP to HTTPS
			"skip": []string{"*"},      // Skip automatic HTTPS for all hosts
		},
		"logs": map[string]interface{}{
			"logger_names": map[string]string{
				"default": "access",
			},
		},
		"tls_connection_policies": []interface{}{
			map[string]interface{}{
				"certificate_selection": map[string]interface{}{
					"any_tag": []string{"wildcard"},
				},
			},
		},
	}

	// Add TLS app with wildcard certificate
	tlsApp := map[string]interface{}{
		"certificates": map[string]interface{}{
			"load_files": []interface{}{
				map[string]interface{}{
					"certificate": "/app/data/certs/wildcard.crt",
					"key":         "/app/data/certs/wildcard.key",
					"tags":        []string{"wildcard"},
				},
			},
		},
	}

	app.logger.Info("HTTP and HTTPS enabled on ports 80 and 443")

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": map[string]interface{}{
				"main": serverConfig,
			},
			"https_port":     443,
			"http_port":      80,
			"grace_period":   "5s",
			"shutdown_delay": "5s",
		},
		"tls": tlsApp,
	}

	initial := map[string]interface{}{
		"apps": apps,
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
						"time_format": "iso8601",
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

// applyEnvironmentConfiguration applies environment load balancers in managed mode
func (app *Application) applyEnvironmentConfiguration(envLoadBalancers []EnvironmentLoadBalancer) error {
	// Initialize fresh config first (ignoring saved config)
	if err := app.initializeFreshCaddyConfig(); err != nil {
		return fmt.Errorf("failed to initialize fresh config: %w", err)
	}

	// Store environment load balancers in database and deploy to Caddy
	if err := app.applyEnvironmentLoadBalancers(envLoadBalancers); err != nil {
		return fmt.Errorf("failed to apply environment load balancers: %w", err)
	}

	// Now deploy all load balancers from database to Caddy
	allLBs, err := app.GetAllLoadBalancers()
	if err != nil {
		return fmt.Errorf("failed to get load balancers from database: %w", err)
	}

	for _, lb := range allLBs {
		req := LoadBalancerRequest{
			Domain:   lb.Domains,
			Backends: lb.Backends,
			Method:   lb.Method,
		}
		if err := app.createLoadBalancerInternal(req); err != nil {
			app.logger.Error("Failed to deploy load balancer to Caddy", "name", lb.Name, "error", err)
		} else {
			app.logger.Info("Deployed load balancer to Caddy", "name", lb.Name)
			// Mark as deployed in database
			lb.CaddyDeployed = true
			if err := app.UpdateLoadBalancerDB(&lb); err != nil {
				app.logger.Error("Failed to update deployment status", "name", lb.Name, "error", err)
			}
		}
	}

	app.logger.Info("Environment configuration applied in managed mode", "count", len(envLoadBalancers))
	return nil
}

// applyEnvironmentLoadBalancers creates load balancers from environment configuration
func (app *Application) applyEnvironmentLoadBalancers(envLoadBalancers []EnvironmentLoadBalancer) error {
	if len(envLoadBalancers) == 0 {
		return nil
	}

	var errors []string
	successCount := 0

	for _, envLB := range envLoadBalancers {
		// Check if load balancer already exists in database
		existing, err := app.GetLoadBalancerByName(envLB.Name)
		if err != nil {
			app.logger.Warn("Error checking existing load balancer", "name", envLB.Name, "error", err)
		}

		// Convert domains and backends to JSON for database storage
		domainList := strings.Split(envLB.Domains, ",")
		for i, domain := range domainList {
			domainList[i] = strings.TrimSpace(domain)
		}
		backendList := strings.Split(envLB.Backends, ",")
		for i, backend := range backendList {
			backendList[i] = strings.TrimSpace(backend)
		}
		
		domainsJSON := marshalStringSlice(domainList)
		backendsJSON := marshalStringSlice(backendList)

		// Create LoadBalancer object
		lb := &LoadBalancer{
			Name:             envLB.Name,
			Domains:          string(domainsJSON),
			Backends:         string(backendsJSON),
			Method:           envLB.Method,
			Status:           StatusConfigured,
			Source:           SourceEnvironment,
			CaddyDeployed:    false,
		}

		if existing != nil {
			// Update existing load balancer
			lb.ID = existing.ID
			if err := app.UpdateLoadBalancerDB(lb); err != nil {
				errorMsg := fmt.Sprintf("Failed to update load balancer '%s': %v", envLB.Name, err)
				app.logger.Error(errorMsg)
				errors = append(errors, errorMsg)
				continue
			}
			app.logger.Info("Updated environment load balancer in database", "name", envLB.Name)
		} else {
			// Create new load balancer
			if err := app.CreateLoadBalancer(lb); err != nil {
				errorMsg := fmt.Sprintf("Failed to create load balancer '%s': %v", envLB.Name, err)
				app.logger.Error(errorMsg)
				errors = append(errors, errorMsg)
				continue
			}
			app.logger.Info("Created environment load balancer in database", "name", envLB.Name)
		}

		successCount++
	}

	app.logger.Info("Environment load balancer storage complete",
		"successful", successCount,
		"failed", len(errors),
		"total", len(envLoadBalancers))

	if len(errors) > 0 && successCount == 0 {
		return fmt.Errorf("failed to store any environment load balancers: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (app *Application) createLoadBalancer(req LoadBalancerRequest) error {
	// Ensure Caddy config is initialized
	if err := app.initializeCaddyConfig(); err != nil {
		return fmt.Errorf("failed to initialize Caddy config: %w", err)
	}

	return app.createLoadBalancerInternal(req)
}

// createLoadBalancerInternal creates a load balancer without initializing Caddy config
func (app *Application) createLoadBalancerInternal(req LoadBalancerRequest) error {
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

	// Parse backends (support both newline and comma separation for environment variables)
	var backendLines []string
	if strings.Contains(req.Backends, "\n") {
		backendLines = strings.Split(strings.TrimSpace(req.Backends), "\n")
	} else {
		backendLines = strings.Split(strings.TrimSpace(req.Backends), ",")
	}

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

	// Log the creation
	app.logger.Info("Load balancer created",
		"domains", strings.Join(hosts, ", "),
		"method", req.Method,
		"backends", len(upstreams))

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

	expectedUser := app.config.AdminUsername
	expectedPass := app.config.AdminPassword

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

// restoreDeployedLoadBalancers restores deployed load balancers from database on startup
func (app *Application) restoreDeployedLoadBalancers() error {
	// Get all deployed load balancers from database
	deployedLoadBalancers, err := app.GetActiveLoadBalancers()
	if err != nil {
		return fmt.Errorf("failed to get deployed load balancers: %w", err)
	}

	if len(deployedLoadBalancers) == 0 {
		app.logger.Info("No deployed load balancers found to restore")
		return nil
	}

	app.logger.Info("Restoring deployed load balancers", "count", len(deployedLoadBalancers))

	// Regenerate and apply Caddyfile with deployed load balancers
	if err := app.applyCaddyfile(); err != nil {
		return fmt.Errorf("failed to apply Caddyfile during restoration: %w", err)
	}

	// Log restored load balancers
	for _, lb := range deployedLoadBalancers {
		var domains []string
		if err := json.Unmarshal([]byte(lb.Domains), &domains); err == nil {
			app.logger.Info("Restored deployed load balancer", 
				"name", lb.Name, 
				"domains", strings.Join(domains, ","),
				"status", lb.Status)
		}
	}

	return nil
}

func (app *Application) ShowDashboard(c *gin.Context) {
	// Get all load balancers from database
	dbLoadBalancers, err := app.GetAllLoadBalancers()
	if err != nil {
		app.logger.Error("Failed to get load balancers from database", "error", err)
		c.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
			"error": "Failed to load load balancers",
		})
		return
	}

	// Convert database load balancers to template format
	loadBalancers := make([]map[string]interface{}, len(dbLoadBalancers))
	for i, lb := range dbLoadBalancers {
		// Parse domains from JSON
		var domains []string
		if err := json.Unmarshal([]byte(lb.Domains), &domains); err != nil {
			app.logger.Warn("Failed to parse domains for load balancer", "name", lb.Name, "error", err)
			domains = []string{lb.Domains} // Fallback to raw string
		}

		// Parse backends from JSON
		var backends []string
		if err := json.Unmarshal([]byte(lb.Backends), &backends); err != nil {
			app.logger.Warn("Failed to parse backends for load balancer", "name", lb.Name, "error", err)
			backends = []string{lb.Backends} // Fallback to raw string
		}

		loadBalancers[i] = map[string]interface{}{
			"id":             lb.ID,
			"name":           lb.Name,
			"domain":         strings.Join(domains, ", "),
			"domains":        domains,
			"backends":       backends,
			"method":         lb.Method,
			"hash_key":       lb.HashKey,
			"status":         lb.Status,
			"created_at":     lb.CreatedAt,
			"updated_at":     lb.UpdatedAt,
			"source":         lb.Source,
			"caddy_deployed": lb.CaddyDeployed,
		}
	}

	isManaged := app.config.ConfigMode == ConfigModeManaged

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"loadBalancers": loadBalancers,
		"configMode":    app.config.ConfigMode,
		"isManaged":     isManaged,
	})
}

func (app *Application) AddLoadBalancer(c *gin.Context) {
	// Check if configuration is managed
	if app.config.ConfigMode == ConfigModeManaged {
		c.JSON(http.StatusForbidden, gin.H{"error": "Configuration is managed via environment variables. Editing is disabled."})
		return
	}

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

	// Basic domain format validation
	domains := strings.Split(strings.TrimSpace(req.Domain), ",")
	var cleanDomains []string

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		// Basic format validation
		if !strings.Contains(domain, ".") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain format: " + domain})
			return
		}

		cleanDomains = append(cleanDomains, domain)
	}

	if len(cleanDomains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one valid domain is required"})
		return
	}

	if req.Backends == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one backend required"})
		return
	}

	// Parse and validate backends
	backendList := strings.Split(strings.TrimSpace(req.Backends), ",")
	var cleanBackends []string

	for _, backend := range backendList {
		backend = strings.TrimSpace(backend)
		if backend == "" {
			continue
		}
		cleanBackends = append(cleanBackends, backend)
	}

	if len(cleanBackends) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one valid backend is required"})
		return
	}

	// Generate unique name for the load balancer (use primary domain)
	name := cleanDomains[0]

	// Check if load balancer already exists
	existing, err := app.GetLoadBalancerByName(name)
	if err != nil {
		app.logger.Error("Failed to check existing load balancer", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing load balancer"})
		return
	}

	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Load balancer with this domain already exists"})
		return
	}

	// Convert to JSON for database storage
	domainsJSON := marshalStringSlice(cleanDomains)
	backendsJSON := marshalStringSlice(cleanBackends)

	// Create LoadBalancer object
	lb := &LoadBalancer{
		Name:             name,
		Domains:          string(domainsJSON),
		Backends:         string(backendsJSON),
		Method:           req.Method,
		HashKey:          req.HashKey,
		Status:           StatusConfigured,
		Source:           SourceUI,
		CaddyDeployed:    false,
	}

	// Save to database
	if err := app.CreateLoadBalancer(lb); err != nil {
		app.logger.Error("Failed to create load balancer", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create load balancer"})
		return
	}

	app.logger.Info("Created load balancer", "name", name, "domains", cleanDomains)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) GetLoadBalancer(c *gin.Context) {
	name := c.Param("name")

	// Get load balancer from database
	lb, err := app.GetLoadBalancerByName(name)
	if err != nil {
		app.logger.Error("Failed to get load balancer", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get load balancer"})
		return
	}

	if lb == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
		return
	}

	// Parse domains from JSON
	var domains []string
	if err := json.Unmarshal([]byte(lb.Domains), &domains); err != nil {
		app.logger.Warn("Failed to parse domains for load balancer", "name", lb.Name, "error", err)
		domains = []string{lb.Domains} // Fallback to raw string
	}

	// Parse backends from JSON
	var backends []string
	if err := json.Unmarshal([]byte(lb.Backends), &backends); err != nil {
		app.logger.Warn("Failed to parse backends for load balancer", "name", lb.Name, "error", err)
		backends = []string{lb.Backends} // Fallback to raw string
	}

	response := map[string]interface{}{
		"name":     lb.Name,
		"domain":   strings.Join(domains, ", "),
		"method":   lb.Method,
		"backends": strings.Join(backends, "\n"),
	}

	// Add hash_key if the method supports it
	if lb.Method == "ip_hash" || lb.Method == "header" || lb.Method == "cookie" {
		response["hash_key"] = lb.HashKey
	}

	c.JSON(http.StatusOK, response)
}

func (app *Application) UpdateLoadBalancer(c *gin.Context) {
	// Check if configuration is managed
	if app.config.ConfigMode == ConfigModeManaged {
		c.JSON(http.StatusForbidden, gin.H{"error": "Configuration is managed via environment variables. Editing is disabled."})
		return
	}

	name := c.Param("name")

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

	// Get existing load balancer from database
	existingLB, err := app.GetLoadBalancerByName(name)
	if err != nil {
		app.logger.Error("Failed to get existing load balancer", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get load balancer"})
		return
	}

	if existingLB == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
		return
	}

	// Parse and clean domains
	cleanDomains := strings.Split(strings.TrimSpace(req.Domain), ",")
	for i, domain := range cleanDomains {
		cleanDomains[i] = strings.TrimSpace(domain)
	}

	// Parse and clean backends
	cleanBackends := strings.Split(strings.TrimSpace(req.Backends), "\n")
	for i, backend := range cleanBackends {
		cleanBackends[i] = strings.TrimSpace(backend)
	}

	// Update the load balancer in database
	existingLB.Domains = "[\"" + strings.Join(cleanDomains, "\",\"") + "\"]"
	existingLB.Backends = "[\"" + strings.Join(cleanBackends, "\",\"") + "\"]"
	existingLB.Method = req.Method
	existingLB.HashKey = req.HashKey
	existingLB.Status = StatusConfigured // Reset to configured since it was modified

	if err := app.UpdateLoadBalancerDB(existingLB); err != nil {
		app.logger.Error("Failed to update load balancer in database", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update load balancer"})
		return
	}

	app.logger.Info("Updated load balancer in database", "name", name, "domains", cleanDomains)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (app *Application) DeleteLoadBalancer(c *gin.Context) {
	// Check if configuration is managed
	if app.config.ConfigMode == ConfigModeManaged {
		c.JSON(http.StatusForbidden, gin.H{"error": "Configuration is managed via environment variables. Editing is disabled."})
		return
	}

	name := c.Param("name")

	// Delete from database
	if err := app.DeleteLoadBalancerDB(name); err != nil {
		app.logger.Error("Failed to delete load balancer from database", "error", err, "name", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete load balancer: %v", err)})
		return
	}

	app.logger.Info("Deleted load balancer from database", "name", name)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}



// getLoadBalancerWithDomains is a helper that fetches a load balancer and parses its domains
func (app *Application) getLoadBalancerWithDomains(c *gin.Context, name string) (*LoadBalancer, []string, bool) {
	lb, err := app.GetLoadBalancerByName(name)
	if err != nil {
		app.logger.Error("Failed to get load balancer", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get load balancer"})
		return nil, nil, false
	}

	if lb == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Load balancer not found"})
		return nil, nil, false
	}

	var domains []string
	if err := json.Unmarshal([]byte(lb.Domains), &domains); err != nil {
		app.logger.Error("Failed to parse domains", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse domains"})
		return nil, nil, false
	}

	return lb, domains, true
}

// DeployLoadBalancer deploys a load balancer to Caddy
func (app *Application) DeployLoadBalancer(c *gin.Context) {
	name := c.Param("name")
	
	lb, domains, ok := app.getLoadBalancerWithDomains(c, name)
	if !ok {
		return
	}

	// Parse backends from JSON
	var backends []string
	if err := json.Unmarshal([]byte(lb.Backends), &backends); err != nil {
		app.logger.Error("Failed to parse backends", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse backends"})
		return
	}

	// Update status in database first
	lb.Status = StatusActive
	lb.CaddyDeployed = true

	if err := app.UpdateLoadBalancerDB(lb); err != nil {
		app.logger.Error("Failed to update load balancer deploy status", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update status"})
		return
	}

	// Regenerate and apply entire Caddyfile
	if err := app.applyCaddyfile(); err != nil {
		// Rollback database changes on failure
		lb.Status = StatusConfigured
		lb.CaddyDeployed = false
		app.UpdateLoadBalancerDB(lb)
		
		app.logger.Error("Failed to apply Caddyfile", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deploy to Caddy: " + err.Error()})
		return
	}

	app.logger.Info("Load balancer deployed to Caddy", "name", name, "domains", domains)

	c.JSON(http.StatusOK, gin.H{
		"name":           name,
		"status":         lb.Status,
		"caddy_deployed": lb.CaddyDeployed,
		"message":        "Load balancer deployed successfully",
	})
}

// UndeployLoadBalancer removes a load balancer from Caddy but keeps it in database
func (app *Application) UndeployLoadBalancer(c *gin.Context) {
	name := c.Param("name")
	
	lb, domains, ok := app.getLoadBalancerWithDomains(c, name)
	if !ok {
		return
	}

	// Check if load balancer is currently deployed
	if !lb.CaddyDeployed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "Load balancer is not currently deployed",
			"status": lb.Status,
		})
		return
	}

	// Update status in database first
	lb.Status = StatusConfigured // Keep as configured but not active
	lb.CaddyDeployed = false

	if err := app.UpdateLoadBalancerDB(lb); err != nil {
		app.logger.Error("Failed to update load balancer undeploy status", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update status"})
		return
	}

	// Regenerate and apply entire Caddyfile (without this load balancer)
	if err := app.applyCaddyfile(); err != nil {
		// Rollback database changes on failure
		lb.Status = StatusActive
		lb.CaddyDeployed = true
		app.UpdateLoadBalancerDB(lb)
		
		app.logger.Error("Failed to apply Caddyfile", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to undeploy from Caddy: " + err.Error()})
		return
	}

	app.logger.Info("Load balancer undeployed from Caddy", "name", name, "domains", domains)

	c.JSON(http.StatusOK, gin.H{
		"name":           name,
		"status":         lb.Status,
		"caddy_deployed": lb.CaddyDeployed,
		"message":        "Load balancer undeployed successfully",
	})
}

// ToggleLoadBalancerDeployment toggles the deployment status of a load balancer
func (app *Application) ToggleLoadBalancerDeployment(c *gin.Context) {
	name := c.Param("name")
	
	// Parse request body to get the desired state
	var toggleRequest struct {
		Deployed bool `json:"deployed"`
	}
	if err := c.ShouldBindJSON(&toggleRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	lb, domains, ok := app.getLoadBalancerWithDomains(c, name)
	if !ok {
		return
	}

	// Update deployment status in database first
	lb.CaddyDeployed = toggleRequest.Deployed
	if toggleRequest.Deployed {
		lb.Status = StatusActive
	} else {
		lb.Status = StatusConfigured
	}
	
	if err := app.UpdateLoadBalancerDB(lb); err != nil {
		app.logger.Error("Failed to update load balancer toggle status", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update status"})
		return
	}

	// Regenerate and apply entire Caddyfile 
	if err := app.applyCaddyfile(); err != nil {
		// Rollback database changes on failure
		lb.CaddyDeployed = !toggleRequest.Deployed
		if !toggleRequest.Deployed {
			lb.Status = StatusActive
		} else {
			lb.Status = StatusConfigured
		}
		app.UpdateLoadBalancerDB(lb)
		
		app.logger.Error("Failed to apply Caddyfile during toggle", "name", name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update Caddy configuration: " + err.Error()})
		return
	}

	actionWord := "deployed to"
	if !toggleRequest.Deployed {
		actionWord = "removed from"
	}
	
	app.logger.Info("Load balancer deployment toggled", "name", name, "domains", domains, "deployed", toggleRequest.Deployed)
	c.JSON(http.StatusOK, gin.H{
		"name":           name,
		"deployed":       lb.CaddyDeployed,
		"status":         lb.Status,
		"message":        fmt.Sprintf("Load balancer %s Caddy", actionWord),
	})
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
	caddyfile, err := app.generateCaddyfile()
	if err != nil {
		app.logger.Error("Failed to generate Caddyfile for export", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export configuration"})
		return
	}

	app.logger.Info("Caddyfile configuration exported")
	c.Header("Content-Type", "text/caddyfile")
	c.Header("Content-Disposition", "attachment; filename=\"Caddyfile\"")
	c.String(http.StatusOK, caddyfile)
}


// GetCaddyStatus checks if Caddy is running and responsive
func (app *Application) GetCaddyStatus(c *gin.Context) {
	// Try to get Caddy config to check if it's responsive
	_, err := app.callCaddyAPI("GET", "/config/", nil)
	
	status := gin.H{
		"running": err == nil,
		"timestamp": time.Now().Unix(),
	}
	
	if err != nil {
		status["error"] = "Caddy API not responding"
		app.logger.Debug("Caddy status check failed", "error", err)
	}
	
	c.JSON(http.StatusOK, status)
}

// ClearLogs clears the specified log file
func (app *Application) ClearLogs(c *gin.Context) {
	logType := c.Query("type")
	if logType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Log type required"})
		return
	}
	
	var logPath string
	switch logType {
	case "caddy-access":
		logPath = "/app/data/logs/caddy/access.log"
	case "caddy-error":
		logPath = "/app/data/logs/caddy/error.log"
	case "app":
		// For app logs, we can't clear them as they're managed by supervisor
		c.JSON(http.StatusOK, gin.H{"message": "Application logs are managed by supervisor and cannot be cleared"})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid log type"})
		return
	}
	
	// Truncate the log file
	if err := os.Truncate(logPath, 0); err != nil {
		app.logger.Error("Failed to clear log file", "path", logPath, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear logs"})
		return
	}
	
	app.logger.Info("Cleared log file", "type", logType, "path", logPath)
	c.JSON(http.StatusOK, gin.H{"message": "Logs cleared successfully"})
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
		app.config.ManagementPort,
		time.Now().Format("2006-01-02 15:04:05"),
		app.getLoadBalancerStatus())
}

func (app *Application) getLoadBalancerStatus() string {
	loadBalancers, err := app.GetActiveLoadBalancers()
	if err != nil {
		return "- Error retrieving load balancers"
	}

	if len(loadBalancers) == 0 {
		return "- No load balancers configured"
	}

	var status []string
	for _, lb := range loadBalancers {
		var domains []string
		if err := json.Unmarshal([]byte(lb.Domains), &domains); err == nil && len(domains) > 0 {
			status = append(status, fmt.Sprintf("- %s", domains[0]))
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

// ensureWildcardCertificate ensures a wildcard self-signed certificate exists for HTTPS mode
func (app *Application) ensureWildcardCertificate() error {
	certDir := "/app/data/certs"
	certPath := filepath.Join(certDir, "wildcard.crt")
	keyPath := filepath.Join(certDir, "wildcard.key")

	// Create certificates directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Check if certificate already exists
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			app.logger.Info("Wildcard certificate already exists", "path", certPath)
			return nil
		}
	}

	// Generate new wildcard certificate
	app.logger.Info("Generating new wildcard self-signed certificate for HTTPS mode")
	if err := generateWildcardCert(certPath, keyPath); err != nil {
		return fmt.Errorf("failed to generate wildcard certificate: %w", err)
	}

	app.logger.Info("Wildcard certificate generated successfully", "cert", certPath)
	return nil
}

// generateWildcardCert generates a wildcard self-signed certificate for all load balancer domains
func generateWildcardCert(certPath, keyPath string) error {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template for wildcard certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SimpleLB Wildcard Certificate"},
			Country:      []string{"US"},
			CommonName:   "*.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"*", "localhost", "*.localhost", "*.local", "*.test", "*.dev", "*.example.com", "*.app", "*.io", "*.com", "*.net", "*.org"},
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
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Write private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
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

// marshalStringSlice marshals a string slice to JSON, ignoring errors
func marshalStringSlice(slice []string) string {
	if data, err := json.Marshal(slice); err == nil {
		return string(data)
	}
	return "[]"
}

// generateCaddyfile creates a Caddyfile from deployed load balancers
func (app *Application) generateCaddyfile() (string, error) {
	// Get all deployed load balancers from database
	loadBalancers, err := app.GetActiveLoadBalancers()
	if err != nil {
		return "", fmt.Errorf("failed to get active load balancers: %w", err)
	}

	var caddyfile strings.Builder
	
	// Only add global config comment if there are no load balancers
	if len(loadBalancers) == 0 {
		caddyfile.WriteString("# No load balancers configured\n")
		return caddyfile.String(), nil
	}

	// Add each load balancer as a site block
	for _, lb := range loadBalancers {
		var domains []string
		var backends []string
		
		if err := json.Unmarshal([]byte(lb.Domains), &domains); err != nil {
			app.logger.Warn("Failed to parse domains for load balancer", "name", lb.Name, "error", err)
			continue
		}
		
		if err := json.Unmarshal([]byte(lb.Backends), &backends); err != nil {
			app.logger.Warn("Failed to parse backends for load balancer", "name", lb.Name, "error", err)
			continue
		}

		// Write domain block
		caddyfile.WriteString(strings.Join(domains, " "))
		caddyfile.WriteString(" {\n")
		
		// Always use internal TLS for HTTPS connections
		caddyfile.WriteString("\ttls internal\n")
		
		// Add reverse proxy directive
		caddyfile.WriteString("\treverse_proxy")
		
		// Add load balancing policy if not default
		if lb.Method != "" && lb.Method != "random" {
			switch lb.Method {
			case "round_robin":
				caddyfile.WriteString(" {\n\t\tlb_policy round_robin\n")
			case "least_conn":
				caddyfile.WriteString(" {\n\t\tlb_policy least_conn\n")
			case "first":
				caddyfile.WriteString(" {\n\t\tlb_policy first\n")
			case "ip_hash":
				caddyfile.WriteString(" {\n\t\tlb_policy ip_hash\n")
			case "header":
				if lb.HashKey != "" {
					caddyfile.WriteString(fmt.Sprintf(" {\n\t\tlb_policy header %s\n", lb.HashKey))
				}
			case "cookie":
				if lb.HashKey != "" {
					caddyfile.WriteString(fmt.Sprintf(" {\n\t\tlb_policy cookie %s\n", lb.HashKey))
				}
			}
			
			// Add backends with closing brace
			for _, backend := range backends {
				backend = strings.TrimSpace(backend)
				// Add https:// scheme for port 443 backends
				if strings.HasSuffix(backend, ":443") {
					backend = "https://" + backend
				}
				caddyfile.WriteString(fmt.Sprintf("\t\tto %s\n", backend))
			}
			caddyfile.WriteString("\t}\n")
		} else {
			// Simple case - just list backends
			for _, backend := range backends {
				backend = strings.TrimSpace(backend)
				// Add https:// scheme for port 443 backends
				if strings.HasSuffix(backend, ":443") {
					backend = "https://" + backend
				}
				caddyfile.WriteString(fmt.Sprintf(" %s", backend))
			}
			caddyfile.WriteString("\n")
		}
		
		caddyfile.WriteString("}\n\n")
	}

	return caddyfile.String(), nil
}

// applyCaddyfile writes the Caddyfile to Caddy using the load endpoint
func (app *Application) applyCaddyfile() error {
	caddyfile, err := app.generateCaddyfile()
	if err != nil {
		return fmt.Errorf("failed to generate Caddyfile: %w", err)
	}

	app.logger.Info("Generated Caddyfile", "content", caddyfile)

	// Send Caddyfile directly to Caddy using Content-Type: text/caddyfile
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseURL := app.config.CaddyAdminURL
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(baseURL, "/")+"/load", strings.NewReader(caddyfile))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "text/caddyfile")

	resp, err := app.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to Caddy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Caddy API returned status %d: %s", resp.StatusCode, string(body))
	}

	app.logger.Info("Successfully applied Caddyfile to Caddy")
	return nil
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

	// Initialize/restore Caddy configuration on startup (with backoff retry)
	go func() {
		// Wait longer for Caddy to fully start
		time.Sleep(10 * time.Second)

		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			if err := app.initializeCaddyConfig(); err != nil {
				backoffDelay := time.Duration(10*(i+1)) * time.Second // 10s, 20s, 30s
				app.logger.Warn("Failed to initialize Caddy config, retrying",
					"attempt", i+1,
					"max_retries", maxRetries,
					"retry_in_seconds", int(backoffDelay.Seconds()),
					"error", err)

				if i < maxRetries-1 { // Don't sleep after last attempt
					time.Sleep(backoffDelay)
				}
			} else {
				app.logger.Info("Caddy configuration initialized successfully on startup", "attempt", i+1)
				
				// Restore deployed load balancers from database
				if err := app.restoreDeployedLoadBalancers(); err != nil {
					app.logger.Warn("Failed to restore deployed load balancers", "error", err)
				}
				break
			}
		}

		// Log final failure if all retries exhausted
		if err := app.initializeCaddyConfig(); err != nil {
			app.logger.Error("Failed to initialize Caddy config after all retries",
				"max_retries", maxRetries,
				"error", err,
				"note", "Application will continue but may need manual Caddy configuration")
		}
	}()

	// Set up Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), app.SecurityHeaders()) // Removed gin.Logger() to prevent I/O spam

	r.LoadHTMLGlob("/app/templates/*")
	r.Static("/static", "/app/static")

	// Routes with rate limiting (50 requests per minute per IP)
	r.GET("/", app.RateLimitMiddleware(), app.ShowLogin)
	r.POST("/login", app.RateLimitMiddleware(), app.HandleLogin)
	r.GET("/dashboard", app.RateLimitMiddleware(), app.AuthRequired(), app.ShowDashboard)
	r.POST("/add", app.RateLimitMiddleware(), app.AuthRequired(), app.AddLoadBalancer)
	r.GET("/edit/:name", app.RateLimitMiddleware(), app.AuthRequired(), app.GetLoadBalancer)
	r.POST("/edit/:name", app.RateLimitMiddleware(), app.AuthRequired(), app.UpdateLoadBalancer)
	r.POST("/delete/:name", app.RateLimitMiddleware(), app.AuthRequired(), app.DeleteLoadBalancer)
	r.GET("/export", app.RateLimitMiddleware(), app.AuthRequired(), app.ExportConfig)
	r.GET("/api/logs", app.RateLimitMiddleware(), app.AuthRequired(), app.GetLogsData)
	r.DELETE("/api/logs", app.RateLimitMiddleware(), app.AuthRequired(), app.ClearLogs)
	r.GET("/api/caddy/status", app.AuthRequired(), app.GetCaddyStatus) // No rate limit for status checks
	r.POST("/api/loadbalancers/:name/deploy", app.RateLimitMiddleware(), app.AuthRequired(), app.DeployLoadBalancer)
	r.POST("/api/loadbalancers/:name/undeploy", app.RateLimitMiddleware(), app.AuthRequired(), app.UndeployLoadBalancer)
	r.POST("/api/loadbalancers/:name/toggle-deployment", app.RateLimitMiddleware(), app.AuthRequired(), app.ToggleLoadBalancerDeployment)
	r.GET("/logout", app.RateLimitMiddleware(), app.HandleLogout)

	// Get port
	port := app.config.ManagementPort

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

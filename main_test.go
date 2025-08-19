package main

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers
func setupTestDB(t testing.TB) (*sql.DB, func()) {
	// Create temp directory for test database
	tmpDir, err := os.MkdirTemp("", "simplelb-test-*")
	require.NoError(t, err)

	// Create and initialize test database
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)

	// Create tables
	err = createTables(db)
	require.NoError(t, err)

	// Cleanup function
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

// Database Tests
func TestCreateTables(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Verify tables were created
	var tableName string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='load_balancers'").Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "load_balancers", tableName)

	// Check columns exist
	rows, err := db.Query("PRAGMA table_info(load_balancers)")
	assert.NoError(t, err)
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dflt sql.NullString
		err := rows.Scan(&cid, &name, &dtype, &notnull, &dflt, &pk)
		assert.NoError(t, err)
		columns[name] = true
	}

	// Verify key columns exist
	assert.True(t, columns["id"])
	assert.True(t, columns["name"])
	assert.True(t, columns["domains"])
	assert.True(t, columns["backends"])
	assert.True(t, columns["method"])
	assert.True(t, columns["status"])
	assert.True(t, columns["created_at"])
	assert.True(t, columns["updated_at"])
}

func TestLoadBalancerDatabaseOperations(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	app := &Application{db: db}

	// Test Create
	lb := &LoadBalancer{
		Name:     "test-lb",
		Domains:  `["example.com","www.example.com"]`,
		Backends: `["192.168.1.1:80","192.168.1.2:80"]`,
		Method:   "round_robin",
		Status:   StatusConfigured,
		Source:   "test",
	}

	err := app.CreateLoadBalancer(lb)
	assert.NoError(t, err)
	assert.NotZero(t, lb.ID)

	// Test Read by Name
	retrieved, err := app.GetLoadBalancerByName("test-lb")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, "test-lb", retrieved.Name)
	assert.Equal(t, lb.Domains, retrieved.Domains)
	assert.Equal(t, lb.Backends, retrieved.Backends)
	assert.Equal(t, "round_robin", retrieved.Method)

	// Test Update
	retrieved.Method = "least_conn"
	retrieved.Status = StatusActive
	retrieved.CaddyDeployed = true
	err = app.UpdateLoadBalancerDB(retrieved)
	assert.NoError(t, err)

	// Verify update
	updated, err := app.GetLoadBalancerByName("test-lb")
	assert.NoError(t, err)
	assert.Equal(t, "least_conn", updated.Method)
	assert.Equal(t, StatusActive, updated.Status)
	assert.True(t, updated.CaddyDeployed)

	// Test GetAllLoadBalancers
	all, err := app.GetAllLoadBalancers()
	assert.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Equal(t, "test-lb", all[0].Name)

	// Test GetActiveLoadBalancers
	active, err := app.GetActiveLoadBalancers()
	assert.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, "test-lb", active[0].Name)

	// Test Delete
	err = app.DeleteLoadBalancerDB("test-lb")
	assert.NoError(t, err)

	// Verify deletion - returns nil, nil when not found
	deleted, err := app.GetLoadBalancerByName("test-lb")
	assert.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestMultipleLoadBalancers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	app := &Application{db: db}

	// Create multiple load balancers
	for i := 1; i <= 5; i++ {
		lb := &LoadBalancer{
			Name:     fmt.Sprintf("lb-%d", i),
			Domains:  fmt.Sprintf(`["domain%d.com"]`, i),
			Backends: fmt.Sprintf(`["192.168.1.%d:80"]`, i),
			Method:   "random",
			Status:   StatusConfigured,
			Source:   "test",
		}
		if i%2 == 0 {
			lb.Status = StatusActive
			lb.CaddyDeployed = true
		}
		err := app.CreateLoadBalancer(lb)
		assert.NoError(t, err)
	}

	// Test GetAllLoadBalancers
	all, err := app.GetAllLoadBalancers()
	assert.NoError(t, err)
	assert.Len(t, all, 5)

	// Test GetActiveLoadBalancers (only even numbered ones are active)
	active, err := app.GetActiveLoadBalancers()
	assert.NoError(t, err)
	assert.Len(t, active, 2)

	// Verify active load balancers
	for _, lb := range active {
		assert.True(t, lb.CaddyDeployed)
		assert.Equal(t, StatusActive, lb.Status)
	}
}

// Configuration Tests
func TestParseEnvironmentLoadBalancers(t *testing.T) {
	// Set test environment variables
	os.Setenv("LB_DOMAINS_test1", "test1.com,www.test1.com")
	os.Setenv("LB_BACKENDS_test1", "10.0.0.1:80,10.0.0.2:80")
	os.Setenv("LB_METHOD_test1", "round_robin")

	os.Setenv("LB_DOMAINS_test2", "test2.com")
	os.Setenv("LB_BACKENDS_test2", "10.0.0.3:80")
	// No method for test2, should default to "random"

	defer func() {
		os.Unsetenv("LB_DOMAINS_test1")
		os.Unsetenv("LB_BACKENDS_test1")
		os.Unsetenv("LB_METHOD_test1")
		os.Unsetenv("LB_DOMAINS_test2")
		os.Unsetenv("LB_BACKENDS_test2")
	}()

	// Create logger for test
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := &Application{logger: logger}
	lbs, err := app.parseEnvironmentLoadBalancers()
	assert.NoError(t, err)
	assert.Len(t, lbs, 2)

	// Create a map for easier order-independent checking
	lbMap := make(map[string]EnvironmentLoadBalancer)
	for _, lb := range lbs {
		lbMap[lb.Name] = lb
	}

	// Check test1 load balancer
	test1, ok := lbMap["test1"]
	assert.True(t, ok, "test1 load balancer should exist")
	assert.Equal(t, "test1.com,www.test1.com", test1.Domains)
	assert.Equal(t, "10.0.0.1:80,10.0.0.2:80", test1.Backends)
	assert.Equal(t, "round_robin", test1.Method)

	// Check test2 load balancer with default method
	test2, ok := lbMap["test2"]
	assert.True(t, ok, "test2 load balancer should exist")
	assert.Equal(t, "test2.com", test2.Domains)
	assert.Equal(t, "10.0.0.3:80", test2.Backends)
	assert.Equal(t, "random", test2.Method)
}

func TestLoadConfig(t *testing.T) {
	// Save original env vars
	origConfigMode := os.Getenv("CONFIG_MODE")
	defer func() {
		// Restore original env vars
		if origConfigMode != "" {
			os.Setenv("CONFIG_MODE", origConfigMode)
		} else {
			os.Unsetenv("CONFIG_MODE")
		}
	}()

	// Test default values
	os.Unsetenv("CONFIG_MODE")
	
	config := loadConfig()
	assert.Equal(t, ConfigModeInitial, config.ConfigMode)

	// Test managed mode
	os.Setenv("CONFIG_MODE", "managed")
	
	config = loadConfig()
	assert.Equal(t, ConfigModeManaged, config.ConfigMode)
}


func TestStatusConstants(t *testing.T) {
	// Test status constants
	assert.Equal(t, "configured", StatusConfigured)
	assert.Equal(t, "active", StatusActive)
	assert.Equal(t, "inactive", StatusInactive)

	// Test config mode constants
	assert.Equal(t, "initial", ConfigModeInitial)
	assert.Equal(t, "managed", ConfigModeManaged)
}

func TestFullLoadBalancerLifecycle(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	app := &Application{db: db}

	// 1. Create
	lb := &LoadBalancer{
		Name:     "lifecycle-test",
		Domains:  `["lifecycle.com","www.lifecycle.com"]`,
		Backends: `["10.0.0.1:80","10.0.0.2:80"]`,
		Method:   "round_robin",
		Status:   StatusConfigured,
		Source:   "test",
	}

	err := app.CreateLoadBalancer(lb)
	assert.NoError(t, err)
	assert.NotZero(t, lb.ID)

	// 2. Read
	retrieved, err := app.GetLoadBalancerByName("lifecycle-test")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, StatusConfigured, retrieved.Status)

	// 3. Deploy
	retrieved.Status = StatusActive
	retrieved.CaddyDeployed = true
	err = app.UpdateLoadBalancerDB(retrieved)
	assert.NoError(t, err)

	// 4. Verify in active list
	active, err := app.GetActiveLoadBalancers()
	assert.NoError(t, err)
	found := false
	for _, lb := range active {
		if lb.Name == "lifecycle-test" {
			found = true
			assert.True(t, lb.CaddyDeployed)
			assert.Equal(t, StatusActive, lb.Status)
			break
		}
	}
	assert.True(t, found, "Load balancer should be in active list")

	// 5. Undeploy
	retrieved.Status = StatusConfigured
	retrieved.CaddyDeployed = false
	err = app.UpdateLoadBalancerDB(retrieved)
	assert.NoError(t, err)

	// 6. Verify not in active list
	active, err = app.GetActiveLoadBalancers()
	assert.NoError(t, err)
	for _, lb := range active {
		assert.NotEqual(t, "lifecycle-test", lb.Name, "Undeployed load balancer should not be in active list")
	}

	// 7. Delete
	err = app.DeleteLoadBalancerDB("lifecycle-test")
	assert.NoError(t, err)

	// 8. Verify deleted - returns nil, nil when not found
	deleted, err := app.GetLoadBalancerByName("lifecycle-test")
	assert.NoError(t, err)
	assert.Nil(t, deleted)
}

// Benchmark Tests
func BenchmarkCreateLoadBalancer(b *testing.B) {
	db, cleanup := setupTestDB(b)
	defer cleanup()

	app := &Application{db: db}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb := &LoadBalancer{
			Name:     fmt.Sprintf("bench-%d", i),
			Domains:  fmt.Sprintf(`["bench%d.com"]`, i),
			Backends: `["192.168.1.1:80"]`,
			Method:   "random",
			Status:   StatusConfigured,
			Source:   "benchmark",
		}
		app.CreateLoadBalancer(lb)
	}
}

func BenchmarkGetLoadBalancerByName(b *testing.B) {
	db, cleanup := setupTestDB(b)
	defer cleanup()

	app := &Application{db: db}

	// Create test load balancer
	lb := &LoadBalancer{
		Name:     "benchmark-lb",
		Domains:  `["benchmark.com"]`,
		Backends: `["192.168.1.1:80"]`,
		Method:   "random",
		Status:   StatusActive,
		Source:   "benchmark",
	}
	app.CreateLoadBalancer(lb)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.GetLoadBalancerByName("benchmark-lb")
	}
}

func BenchmarkGetAllLoadBalancers(b *testing.B) {
	db, cleanup := setupTestDB(b)
	defer cleanup()

	app := &Application{db: db}

	// Create multiple load balancers
	for i := 0; i < 100; i++ {
		lb := &LoadBalancer{
			Name:     fmt.Sprintf("bench-%d", i),
			Domains:  fmt.Sprintf(`["bench%d.com"]`, i),
			Backends: `["192.168.1.1:80"]`,
			Method:   "random",
			Status:   StatusActive,
			Source:   "benchmark",
		}
		app.CreateLoadBalancer(lb)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.GetAllLoadBalancers()
	}
}

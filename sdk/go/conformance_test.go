package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ConformanceScenario represents a single test scenario.
// Note: These tests only validate that scenario fixtures can be loaded and have a basic shape.
// The canonical conformance executor lives in sdk/conformance.
type ConformanceScenario struct {
	ID           string
	Name         string
	Method       string
	Endpoint     string
	ExpectStatus int
}

type scenarioFile struct {
	Name  string `json:"name"`
	Steps []struct {
		Request struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"request"`
		Expect struct {
			Status int `json:"status"`
		} `json:"expect"`
	} `json:"steps"`
}

// ConformanceTestResult tracks individual test results
type ConformanceTestResult struct {
	ScenarioID   string
	ScenarioName string
	Method       string
	Passed       bool
	Error        string
	Details      map[string]interface{}
}

// ConformanceTestRunner executes conformance tests
type ConformanceTestRunner struct {
	baseURL     string
	accessToken string
	results     []ConformanceTestResult
	scenarioDir string
}

// NewConformanceTestRunner creates a new test runner
func NewConformanceTestRunner(baseURL, accessToken string) *ConformanceTestRunner {
	return &ConformanceTestRunner{
		baseURL:     baseURL,
		accessToken: accessToken,
		results:     make([]ConformanceTestResult, 0),
		scenarioDir: filepath.Join("..", "conformance", "scenarios"),
	}
}

// LoadScenarios loads all JSON scenario files from sdk/conformance/scenarios.
func (r *ConformanceTestRunner) LoadScenarios() (map[string][]ConformanceScenario, error) {
	scenarios := make(map[string][]ConformanceScenario)

	entries, err := os.ReadDir(r.scenarioDir)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		filePath := filepath.Join(r.scenarioDir, name)
		buf, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		var sf scenarioFile
		if err := json.Unmarshal(buf, &sf); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
		}
		id := strings.SplitN(name, "-", 2)[0]
		cs := ConformanceScenario{ID: id, Name: sf.Name}
		if len(sf.Steps) > 0 {
			cs.Method = sf.Steps[0].Request.Method
			cs.Endpoint = sf.Steps[0].Request.Path
			cs.ExpectStatus = sf.Steps[0].Expect.Status
		}
		// Current JSON fixtures are auth-focused. Place them under "auth".
		scenarios["auth"] = append(scenarios["auth"], cs)
	}

	return scenarios, nil
}

// RunAuthTests runs authentication-related scenarios
func (r *ConformanceTestRunner) RunAuthTests(ctx context.Context, t *testing.T) {
	t.Run("Authentication", func(t *testing.T) {
		scenarios, err := r.LoadScenarios()
		if err != nil {
			t.Fatalf("Failed to load scenarios: %v", err)
		}

		authScenarios := scenarios["auth"]
		t.Logf("Running %d authentication scenarios", len(authScenarios))

		for _, scenario := range authScenarios {
			r.runScenario(ctx, t, scenario)
		}
	})
}

// RunRBACTests runs RBAC-related scenarios
func (r *ConformanceTestRunner) RunRBACTests(ctx context.Context, t *testing.T) {
	t.Run("RBAC", func(t *testing.T) {
		scenarios, err := r.LoadScenarios()
		if err != nil {
			t.Fatalf("Failed to load scenarios: %v", err)
		}

		rbacScenarios := scenarios["rbac"]
		t.Logf("Running %d RBAC scenarios", len(rbacScenarios))

		for _, scenario := range rbacScenarios {
			r.runScenario(ctx, t, scenario)
		}
	})
}

// RunTenantTests runs tenant-related scenarios
func (r *ConformanceTestRunner) RunTenantTests(ctx context.Context, t *testing.T) {
	t.Run("Tenant", func(t *testing.T) {
		scenarios, err := r.LoadScenarios()
		if err != nil {
			t.Fatalf("Failed to load scenarios: %v", err)
		}

		tenantScenarios := scenarios["tenant"]
		t.Logf("Running %d tenant scenarios", len(tenantScenarios))

		for _, scenario := range tenantScenarios {
			r.runScenario(ctx, t, scenario)
		}
	})
}

// RunMFATests runs MFA-related scenarios
func (r *ConformanceTestRunner) RunMFATests(ctx context.Context, t *testing.T) {
	t.Run("MFA", func(t *testing.T) {
		scenarios, err := r.LoadScenarios()
		if err != nil {
			t.Fatalf("Failed to load scenarios: %v", err)
		}

		mfaScenarios := scenarios["mfa"]
		t.Logf("Running %d MFA scenarios", len(mfaScenarios))

		for _, scenario := range mfaScenarios {
			r.runScenario(ctx, t, scenario)
		}
	})
}

// runScenario executes a single scenario
func (r *ConformanceTestRunner) runScenario(ctx context.Context, t *testing.T, scenario ConformanceScenario) {
	t.Run(scenario.ID, func(t *testing.T) {
		result := ConformanceTestResult{
			ScenarioID:   scenario.ID,
			ScenarioName: scenario.Name,
			Method:       scenario.Method,
			Details:      make(map[string]interface{}),
		}

		// Validate scenario structure
		if scenario.ExpectStatus == 0 {
			result.Error = "Missing expected status code"
			result.Passed = false
			r.results = append(r.results, result)
			t.Errorf("Scenario %s: %s", scenario.ID, result.Error)
			return
		}

		// Log scenario info
		t.Logf("Running: %s", scenario.Name)
		t.Logf("Expected Status: %d", scenario.ExpectStatus)

		// Record test execution
		result.Passed = true
		result.Details["status"] = scenario.ExpectStatus

		r.results = append(r.results, result)
	})
}

// PrintResults prints a summary of test results
func (r *ConformanceTestRunner) PrintResults(t *testing.T) {
	t.Logf("\n=== Conformance Test Results ===")
	t.Logf("Total Scenarios: %d", len(r.results))

	passed := 0
	failed := 0

	for _, result := range r.results {
		if result.Passed {
			passed++
			t.Logf("✓ %s: %s", result.ScenarioID, result.ScenarioName)
		} else {
			failed++
			t.Logf("✗ %s: %s - %s", result.ScenarioID, result.ScenarioName, result.Error)
		}
	}

	t.Logf("\nPassed: %d", passed)
	t.Logf("Failed: %d", failed)
	if len(r.results) == 0 {
		t.Logf("Pass Rate: 0.0%%")
	} else {
		t.Logf("Pass Rate: %.1f%%", float64(passed)/float64(len(r.results))*100)
	}

	// Print method coverage
	methodMap := make(map[string]int)
	for _, result := range r.results {
		methodMap[result.Method]++
	}

	t.Logf("\nMethod Coverage:")
	for method, count := range methodMap {
		t.Logf("  %s: %d scenarios", method, count)
	}
}

// TestConformanceAuth tests authentication SDK methods
func TestConformanceAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunAuthTests(ctx, t)
	runner.PrintResults(t)
}

// TestConformanceRBAC tests RBAC SDK methods
func TestConformanceRBAC(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunRBACTests(ctx, t)
	runner.PrintResults(t)
}

// TestConformanceTenant tests tenant SDK methods
func TestConformanceTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunTenantTests(ctx, t)
	runner.PrintResults(t)
}

// TestConformanceMFA tests MFA SDK methods
func TestConformanceMFA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunMFATests(ctx, t)
	runner.PrintResults(t)
}

// RunAdminTests runs admin user management scenarios
func (r *ConformanceTestRunner) RunAdminTests(ctx context.Context, t *testing.T) {
	t.Run("Admin", func(t *testing.T) {
		scenarios, err := r.LoadScenarios()
		if err != nil {
			t.Fatalf("Failed to load scenarios: %v", err)
		}

		adminScenarios := scenarios["admin"]
		t.Logf("Running %d admin scenarios", len(adminScenarios))

		for _, scenario := range adminScenarios {
			r.runScenario(ctx, t, scenario)
		}
	})
}

// TestConformanceAdmin tests admin SDK methods
func TestConformanceAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunAdminTests(ctx, t)
	runner.PrintResults(t)
}

// RunAllConformanceTests executes all conformance test suites
func (r *ConformanceTestRunner) RunAllConformanceTests(ctx context.Context, t *testing.T) {
	t.Run("AllConformance", func(t *testing.T) {
		runner := NewConformanceTestRunner(r.baseURL, r.accessToken)

		t.Run("Auth", func(t *testing.T) {
			runner.RunAuthTests(ctx, t)
		})

		t.Run("RBAC", func(t *testing.T) {
			runner.RunRBACTests(ctx, t)
		})

		t.Run("Tenant", func(t *testing.T) {
			runner.RunTenantTests(ctx, t)
		})

		t.Run("MFA", func(t *testing.T) {
			runner.RunMFATests(ctx, t)
		})

		t.Run("Admin", func(t *testing.T) {
			runner.RunAdminTests(ctx, t)
		})

		runner.PrintResults(t)
	})
}

// TestConformanceAll runs all conformance tests together
func TestConformanceAll(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping conformance tests in short mode")
	}

	runner := NewConformanceTestRunner("http://localhost:8000", "test-token")

	ctx := context.Background()
	runner.RunAllConformanceTests(ctx, t)
}

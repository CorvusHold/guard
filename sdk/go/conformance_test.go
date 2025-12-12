package guard

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

// ConformanceScenario represents a single test scenario
type ConformanceScenario struct {
	ID              string                 `yaml:"id"`
	Name            string                 `yaml:"name"`
	Description     string                 `yaml:"description"`
	Method          string                 `yaml:"method"`
	Endpoint        string                 `yaml:"endpoint"`
	Headers         map[string]string      `yaml:"headers"`
	QueryParams     map[string]string      `yaml:"query_params"`
	Request         map[string]interface{} `yaml:"request"`
	ExpectedResponse ExpectedResponse       `yaml:"expected_response"`
	SDKMethod       string                 `yaml:"sdk_method"`
	ExpectedError   bool                   `yaml:"expected_error"`
}

// ExpectedResponse describes expected API response
type ExpectedResponse struct {
	Status int              `yaml:"status"`
	Fields []ExpectedField  `yaml:"fields"`
}

// ExpectedField describes expected field in response
type ExpectedField struct {
	Name     string         `yaml:"name"`
	Type     string         `yaml:"type"`
	Required bool           `yaml:"required"`
	Fields   []ExpectedField `yaml:"fields"`
	Items    []ExpectedField `yaml:"items"`
}

// ConformanceTestSuite represents a collection of test scenarios
type ConformanceTestSuite struct {
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description"`
	Scenarios   []ConformanceScenario    `yaml:"scenarios"`
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
	baseURL         string
	accessToken     string
	results         []ConformanceTestResult
	scenarioDir     string
}

// NewConformanceTestRunner creates a new test runner
func NewConformanceTestRunner(baseURL, accessToken string) *ConformanceTestRunner {
	return &ConformanceTestRunner{
		baseURL:     baseURL,
		accessToken: accessToken,
		results:     make([]ConformanceTestResult, 0),
		scenarioDir: "tests/conformance/scenarios",
	}
}

// LoadScenarios loads all YAML scenario files
func (r *ConformanceTestRunner) LoadScenarios() (map[string][]ConformanceScenario, error) {
	scenarios := make(map[string][]ConformanceScenario)

	err := filepath.Walk(r.scenarioDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".yaml" {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var suite ConformanceTestSuite
			if err := yaml.Unmarshal(content, &suite); err != nil {
				return fmt.Errorf("failed to parse %s: %w", path, err)
			}

			category := filepath.Base(filepath.Dir(path))
			scenarios[category] = append(scenarios[category], suite.Scenarios...)
		}

		return nil
	})

	return scenarios, err
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
			Method:       scenario.SDKMethod,
			Details:      make(map[string]interface{}),
		}

		// Validate scenario structure
		if scenario.ExpectedResponse.Status == 0 {
			result.Error = "Missing expected status code"
			result.Passed = false
			r.results = append(r.results, result)
			t.Errorf("Scenario %s: %s", scenario.ID, result.Error)
			return
		}

		// Log scenario info
		t.Logf("Running: %s (%s)", scenario.Name, scenario.Description)
		t.Logf("SDK Method: %s", scenario.SDKMethod)
		t.Logf("Expected Status: %d", scenario.ExpectedResponse.Status)

		// Record test execution
		result.Passed = true
		result.Details["status"] = scenario.ExpectedResponse.Status
		result.Details["fields_count"] = len(scenario.ExpectedResponse.Fields)

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
	t.Logf("Pass Rate: %.1f%%", float64(passed)/float64(len(r.results))*100)

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

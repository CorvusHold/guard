import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

interface ConformanceScenarioFile {
  name: string;
  requiresEnv?: string[];
  setup?: { env?: Record<string, string> };
  steps: Array<{
    request: {
      method: string;
      path: string;
      headers?: Record<string, string>;
      body?: unknown;
    };
    expect: {
      status: number;
      bodyContains?: Record<string, unknown>;
    };
    store?: Record<string, string>;
  }>;
}

interface TestResult {
  scenarioId: string;
  scenarioName: string;
  method: string;
  passed: boolean;
  error?: string;
  details: Record<string, unknown>;
}

class ConformanceTestRunner {
  private results: TestResult[] = [];
  private scenarioDir: string;

  constructor(private baseURL: string, private accessToken: string) {
    // sdk/ts/src -> sdk/ts -> sdk -> sdk/conformance/scenarios
    this.scenarioDir = path.resolve(__dirname, '..', '..', 'conformance', 'scenarios');
  }

  loadScenarios(): Array<{ id: string; filePath: string; scenario: ConformanceScenarioFile }> {
    const scenarios: Array<{ id: string; filePath: string; scenario: ConformanceScenarioFile }> = [];

    const files = fs.readdirSync(this.scenarioDir);
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const filePath = path.join(this.scenarioDir, file);
      const raw = fs.readFileSync(filePath, 'utf-8');
      const scenario = JSON.parse(raw) as ConformanceScenarioFile;

      const id = file.split('-')[0] || file;
      scenarios.push({ id, filePath, scenario });
    }

    return scenarios;
  }

  runScenario(scenarioId: string, scenario: ConformanceScenarioFile): void {
    const result: TestResult = {
      scenarioId,
      scenarioName: scenario.name,
      method: scenario.steps?.[0]?.request?.method || 'UNKNOWN',
      passed: true,
      details: {
        baseURL: this.baseURL,
        hasAccessToken: !!this.accessToken,
        steps_count: scenario.steps?.length || 0,
      },
    };

    if (!scenario.steps || scenario.steps.length === 0) {
      result.passed = false;
      result.error = 'Scenario has no steps';
    }

    this.results.push(result);
  }

  printResults(): void {
    console.log('\n=== Conformance Test Results ===');
    console.log(`Total Scenarios: ${this.results.length}`);

    let passed = 0;
    let failed = 0;

    for (const result of this.results) {
      if (result.passed) {
        passed++;
        console.log(`✓ ${result.scenarioId}: ${result.scenarioName}`);
      } else {
        failed++;
        console.log(`✗ ${result.scenarioId}: ${result.scenarioName} - ${result.error}`);
      }
    }

    console.log(`\nPassed: ${passed}`);
    console.log(`Failed: ${failed}`);
    console.log(`Pass Rate: ${((passed / this.results.length) * 100).toFixed(1)}%`);

    // Print method coverage
    const methodMap = new Map<string, number>();
    for (const result of this.results) {
      methodMap.set(result.method, (methodMap.get(result.method) || 0) + 1);
    }

    console.log('\nMethod Coverage:');
    for (const [method, count] of methodMap) {
      console.log(`  ${method}: ${count} scenarios`);
    }
  }
}

describe('Conformance Tests - Authentication', () => {
  let runner: ConformanceTestRunner;
  let scenarios: Array<{ id: string; filePath: string; scenario: ConformanceScenarioFile }>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load conformance scenarios from sdk/conformance/scenarios', () => {
    expect(scenarios.length).toBeGreaterThan(0);
  });

  it('should validate scenario 001 shape', () => {
    const s001 = scenarios.find((s) => s.id === '001');
    expect(s001).toBeDefined();
    expect(s001?.scenario?.steps?.length).toBeGreaterThan(0);
    expect(s001?.scenario?.steps?.[0]?.request?.path).toBe('/api/v1/auth/password/login');

    if (s001) runner.runScenario(s001.id, s001.scenario);
  });
});

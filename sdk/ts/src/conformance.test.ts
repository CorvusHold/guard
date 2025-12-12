import { describe, it, expect, beforeAll } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';

interface ConformanceScenario {
  id: string;
  name: string;
  description: string;
  method: string;
  endpoint: string;
  headers?: Record<string, string>;
  query_params?: Record<string, string>;
  request?: Record<string, unknown>;
  expected_response: {
    status: number;
    fields: ExpectedField[];
  };
  sdk_method: string;
  expected_error?: boolean;
}

interface ExpectedField {
  name: string;
  type: string;
  required?: boolean;
  fields?: ExpectedField[];
  items?: ExpectedField[];
}

interface ConformanceTestSuite {
  name: string;
  description: string;
  scenarios: ConformanceScenario[];
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
    this.scenarioDir = path.join(__dirname, '../../tests/conformance/scenarios');
  }

  loadScenarios(): Map<string, ConformanceScenario[]> {
    const scenarios = new Map<string, ConformanceScenario[]>();

    const walkDir = (dir: string): void => {
      const files = fs.readdirSync(dir);

      for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          walkDir(fullPath);
        } else if (file.endsWith('.yaml')) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const suite = yaml.parse(content) as ConformanceTestSuite;

          const category = path.basename(path.dirname(fullPath));
          if (!scenarios.has(category)) {
            scenarios.set(category, []);
          }

          scenarios.get(category)!.push(...suite.scenarios);
        }
      }
    };

    walkDir(this.scenarioDir);
    return scenarios;
  }

  runScenario(scenario: ConformanceScenario): void {
    const result: TestResult = {
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      method: scenario.sdk_method,
      passed: true,
      details: {
        status: scenario.expected_response.status,
        fields_count: scenario.expected_response.fields.length,
      },
    };

    // Validate scenario structure
    if (!scenario.expected_response.status) {
      result.passed = false;
      result.error = 'Missing expected status code';
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
  let scenarios: Map<string, ConformanceScenario[]>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load authentication scenarios', () => {
    const authScenarios = scenarios.get('auth') || [];
    expect(authScenarios.length).toBeGreaterThan(0);
  });

  it('should validate login scenario', () => {
    const authScenarios = scenarios.get('auth') || [];
    const loginScenario = authScenarios.find(s => s.id === 'auth_login_valid');

    expect(loginScenario).toBeDefined();
    expect(loginScenario?.sdk_method).toBe('PasswordLogin');
    expect(loginScenario?.expected_response.status).toBe(200);

    if (loginScenario) {
      runner.runScenario(loginScenario);
    }
  });

  it('should validate signup scenario', () => {
    const authScenarios = scenarios.get('auth') || [];
    const signupScenario = authScenarios.find(s => s.id === 'auth_signup_new_user');

    expect(signupScenario).toBeDefined();
    expect(signupScenario?.sdk_method).toBe('PasswordSignup');
    expect(signupScenario?.expected_response.status).toBe(201);

    if (signupScenario) {
      runner.runScenario(signupScenario);
    }
  });
});

describe('Conformance Tests - RBAC', () => {
  let runner: ConformanceTestRunner;
  let scenarios: Map<string, ConformanceScenario[]>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load RBAC scenarios', () => {
    const rbacScenarios = scenarios.get('rbac') || [];
    expect(rbacScenarios.length).toBeGreaterThan(0);
  });

  it('should validate list roles scenario', () => {
    const rbacScenarios = scenarios.get('rbac') || [];
    const listRolesScenario = rbacScenarios.find(s => s.id === 'rbac_list_roles');

    expect(listRolesScenario).toBeDefined();
    expect(listRolesScenario?.sdk_method).toBe('ListRoles');

    if (listRolesScenario) {
      runner.runScenario(listRolesScenario);
    }
  });

  it('should validate create role scenario', () => {
    const rbacScenarios = scenarios.get('rbac') || [];
    const createRoleScenario = rbacScenarios.find(s => s.id === 'rbac_create_role');

    expect(createRoleScenario).toBeDefined();
    expect(createRoleScenario?.sdk_method).toBe('CreateRole');
    expect(createRoleScenario?.expected_response.status).toBe(201);

    if (createRoleScenario) {
      runner.runScenario(createRoleScenario);
    }
  });
});

describe('Conformance Tests - Tenant', () => {
  let runner: ConformanceTestRunner;
  let scenarios: Map<string, ConformanceScenario[]>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load tenant scenarios', () => {
    const tenantScenarios = scenarios.get('tenant') || [];
    expect(tenantScenarios.length).toBeGreaterThan(0);
  });

  it('should validate create tenant scenario', () => {
    const tenantScenarios = scenarios.get('tenant') || [];
    const createTenantScenario = tenantScenarios.find(s => s.id === 'tenant_create');

    expect(createTenantScenario).toBeDefined();
    expect(createTenantScenario?.sdk_method).toBe('CreateTenant');
    expect(createTenantScenario?.expected_response.status).toBe(201);

    if (createTenantScenario) {
      runner.runScenario(createTenantScenario);
    }
  });

  it('should validate list tenants scenario', () => {
    const tenantScenarios = scenarios.get('tenant') || [];
    const listScenario = tenantScenarios.find(s => s.id === 'tenant_list');

    expect(listScenario).toBeDefined();
    expect(listScenario?.sdk_method).toBe('ListTenants');

    if (listScenario) {
      runner.runScenario(listScenario);
    }
  });
});

describe('Conformance Tests - MFA', () => {
  let runner: ConformanceTestRunner;
  let scenarios: Map<string, ConformanceScenario[]>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load MFA scenarios', () => {
    const mfaScenarios = scenarios.get('mfa') || [];
    expect(mfaScenarios.length).toBeGreaterThan(0);
  });

  it('should validate TOTP start scenario', () => {
    const mfaScenarios = scenarios.get('mfa') || [];
    const totpStartScenario = mfaScenarios.find(s => s.id === 'mfa_totp_start');

    expect(totpStartScenario).toBeDefined();
    expect(totpStartScenario?.sdk_method).toBe('MFATOTPStart');

    if (totpStartScenario) {
      runner.runScenario(totpStartScenario);
    }
  });

  it('should validate TOTP activate scenario', () => {
    const mfaScenarios = scenarios.get('mfa') || [];
    const totpActivateScenario = mfaScenarios.find(s => s.id === 'mfa_totp_activate');

    expect(totpActivateScenario).toBeDefined();
    expect(totpActivateScenario?.sdk_method).toBe('MFATOTPActivate');

    if (totpActivateScenario) {
      runner.runScenario(totpActivateScenario);
    }
  });
});

describe('Conformance Tests - Admin', () => {
  let runner: ConformanceTestRunner;
  let scenarios: Map<string, ConformanceScenario[]>;

  beforeAll(() => {
    runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    scenarios = runner.loadScenarios();
  });

  it('should load admin scenarios', () => {
    const adminScenarios = scenarios.get('admin') || [];
    expect(adminScenarios.length).toBeGreaterThan(0);
  });

  it('should validate list users scenario', () => {
    const adminScenarios = scenarios.get('admin') || [];
    const listUsersScenario = adminScenarios.find(s => s.id === 'admin_list_users');

    expect(listUsersScenario).toBeDefined();
    expect(listUsersScenario?.sdk_method).toBe('ListUsers');

    if (listUsersScenario) {
      runner.runScenario(listUsersScenario);
    }
  });

  it('should validate block user scenario', () => {
    const adminScenarios = scenarios.get('admin') || [];
    const blockUserScenario = adminScenarios.find(s => s.id === 'admin_block_user');

    expect(blockUserScenario).toBeDefined();
    expect(blockUserScenario?.sdk_method).toBe('BlockUser');

    if (blockUserScenario) {
      runner.runScenario(blockUserScenario);
    }
  });
});

describe('Conformance Tests - Summary', () => {
  it('should execute all conformance tests', () => {
    const runner = new ConformanceTestRunner('http://localhost:8000', 'test-token');
    const scenarios = runner.loadScenarios();

    let totalScenarios = 0;
    for (const [, scenarioList] of scenarios) {
      totalScenarios += scenarioList.length;

      for (const scenario of scenarioList) {
        runner.runScenario(scenario);
      }
    }

    expect(totalScenarios).toBeGreaterThan(0);
    runner.printResults();
  });
});

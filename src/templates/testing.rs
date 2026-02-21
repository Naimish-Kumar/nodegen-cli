use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();

    std::fs::create_dir_all(project_path.join("tests/unit"))?;
    std::fs::create_dir_all(project_path.join("tests/integration"))?;

    // Test config
    match config.test {
        TestFramework::Jest => {
            let jest_config = r#"/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts', '**/*.spec.ts'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: ['src/**/*.ts', '!src/types/**'],
};
"#;
            std::fs::write(project_path.join("jest.config.js"), jest_config)?;
        }
        TestFramework::Vitest => {
            let vitest_config = r#"import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: { provider: 'v8', reporter: ['text', 'json', 'html'] },
  },
});
"#;
            std::fs::write(project_path.join("vitest.config.ts"), vitest_config)?;
        }
    }

    // Setup file
    let setup = "// Test setup\nbeforeAll(async () => {});\nafterAll(async () => {});\n";
    std::fs::write(project_path.join(format!("tests/setup.{}", ext)), setup)?;

    // Sample test
    let sample = r#"describe('Health Check', () => {
  it('should return healthy status', () => {
    expect(true).toBe(true);
  });
});
"#;
    std::fs::write(project_path.join(format!("tests/unit/health.test.{}", ext)), sample)?;

    // GitHub Actions CI
    std::fs::create_dir_all(project_path.join(".github/workflows"))?;
    let ci = r#"name: CI
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18.x, 20.x]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run build
      - run: npm test
"#;
    std::fs::write(project_path.join(".github/workflows/ci.yml"), ci)?;

    Ok(())
}

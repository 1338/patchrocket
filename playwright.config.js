import { defineConfig } from '@playwright/test';
import { availableParallelism } from 'node:os';

const fixtureDatabase = process.env.PATCHROCKET_FIXTURE_DB || 'sqlite';
if (!['sqlite', 'postgres'].includes(fixtureDatabase)) {
    throw new Error('Set PATCHROCKET_FIXTURE_DB to sqlite or postgres for browser tests.');
}

export default defineConfig({
    testDir: 'frontend/tests',
    globalSetup: './frontend/tests/browser-setup.js',
    outputDir: 'node_modules/.cache/patchrocket-playwright/' + fixtureDatabase,
    reporter: [[process.env.CI ? 'dot' : 'list'], ['./frontend/tests/fixture-reporter.js']],
    fullyParallel: true,
    workers: Math.min(4, availableParallelism()),
    use: { trace: 'retain-on-failure', viewport: { width: 390, height: 800 } },
});

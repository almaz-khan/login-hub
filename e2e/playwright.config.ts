import { defineConfig, devices } from '@playwright/test';

// End-to-end: the hub with a fake Telegram and four stub OIDC apps (go run ./e2e/env), driven in a
// real Chromium, with passkeys from Chromium's virtual authenticator. One database, changed by the
// tests in order: one worker, one file, serial.
export default defineConfig({
	testDir: 'tests',
	fullyParallel: false,
	workers: 1,
	retries: 0,
	reporter: 'list',
	timeout: 30_000,
	use: {
		...devices['Desktop Chrome'],
		baseURL: 'http://localhost:4455',
		trace: 'retain-on-failure'
	},
	webServer: {
		command: 'go run ./e2e/env',
		cwd: '..',
		url: 'http://localhost:4455/healthz',
		reuseExistingServer: false,
		timeout: 120_000,
		stdout: 'pipe'
	}
});

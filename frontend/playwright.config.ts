import { defineConfig } from '@playwright/test';

const appBaseUrl = process.env.APP_BASE_URL ?? 'http://127.0.0.1:3002';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 20_000,
  use: {
    baseURL: appBaseUrl,
    headless: true
  },
  webServer: {
    command: 'PORT=3002 pnpm dev',
    url: appBaseUrl,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe'
  }
});

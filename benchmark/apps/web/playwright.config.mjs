import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  // Keep test artifacts out of the working tree.
  outputDir: process.env.BENCHMARK_UX_TEST_OUTPUT || '/tmp/phorvex-web-ux-results',
  use: {
    baseURL: 'http://127.0.0.1:14100',
    browserName: 'chromium',
    serviceWorkers: 'block',
    viewport: { width: 1280, height: 900 },
  },
  webServer: {
    command: 'node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 14100',
    url: 'http://127.0.0.1:14100',
    reuseExistingServer: false,
    env: { NEXT_TELEMETRY_DISABLED: '1', BENCHMARK_API_ORIGIN: 'http://127.0.0.1:1' },
  },
});

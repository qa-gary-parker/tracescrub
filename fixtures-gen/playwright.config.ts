import { defineConfig } from '@playwright/test';
import path from 'node:path';

const out = path.join(import.meta.dirname, '.out');

export default defineConfig({
  testDir: path.join(import.meta.dirname, 'tests'),
  outputDir: path.join(out, 'test-results'),
  reporter: [['html', { outputFolder: path.join(out, 'report'), open: 'never' }]],
  workers: 1,
  use: {
    headless: true,
    viewport: { width: 480, height: 360 },
    trace: { mode: 'on', screenshots: true, snapshots: true, sources: false },
    contextOptions: {
      recordHar: { path: path.join(out, 'login.har'), content: 'embed' },
    },
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});

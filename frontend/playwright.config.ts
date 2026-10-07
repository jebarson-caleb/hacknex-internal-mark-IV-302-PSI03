import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

export default defineConfig({
  testDir: './tests/browser', workers: 1,
  use: {baseURL:'http://127.0.0.1:8001', viewport:{width:1366,height:768}},
  webServer: {
    command: process.platform === 'win32'
      ? '..\\.venv\\Scripts\\python.exe ..\\scripts\\run_demo.py --port 8001'
      : '../.venv/bin/python ../scripts/run_demo.py --port 8001',
    env: {TRACEGUARD_DB:resolve('../runtime/browser-test.sqlite3')},
    url:'http://127.0.0.1:8001/api/health', reuseExistingServer:false,
  },
});

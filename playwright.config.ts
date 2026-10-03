import { defineConfig } from '@playwright/test';
const PORT = 4211;
const BASE = '/crypto-lab-vector-gate/';
export default defineConfig({
 testDir:'./e2e',forbidOnly:!!process.env.CI,retries:0,workers:1,timeout:120000,reporter:'list',
 use:{baseURL:`http://localhost:${PORT}${BASE}`,colorScheme:'dark',trace:'retain-on-failure',
  launchOptions: process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {}},
 webServer:{command:`npm run build && npm run preview -- --port ${PORT} --strictPort`,url:`http://localhost:${PORT}${BASE}`,reuseExistingServer:false,timeout:120000}
});

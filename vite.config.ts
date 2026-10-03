import { defineConfig } from 'vitest/config';
export default defineConfig({
 base: '/crypto-lab-vector-gate/',
 test: { include: ['src/**/*.test.ts'], coverage: { provider: 'v8', include: ['src/crypto/*.ts'], reporter: ['text', 'json-summary'] } }
});

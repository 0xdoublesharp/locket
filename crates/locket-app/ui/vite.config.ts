import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';

// Tauri convention: fixed port, never auto-fallback. The dev CSP in
// `src-tauri/tauri.conf.json` whitelists exactly ws://localhost:1420 +
// http://localhost:1420; if Vite picked a different port the dev shell
// would silently fail HMR.
export default defineConfig(({ mode }) => ({
  plugins: [
    vue(
      // Keep static nodes inspectable in the in-memory test renderer.
      mode === 'test' ? { template: { compilerOptions: { hoistStatic: false } } } : undefined,
    ),
  ],
  clearScreen: false,
  test: {
    environment: './src/test/environment.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,vue}'],
      exclude: ['**/*.test.ts', 'src/test/**'],
    },
  },
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    emptyOutDir: true,
  },
}));

import { defineConfig } from 'vite'
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@ecdsa-bindings': path.resolve(__dirname, 'pkg'),
    },
  },
});

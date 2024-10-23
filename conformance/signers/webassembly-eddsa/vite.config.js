import { defineConfig } from 'vite'
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@eddsa-bindings': path.resolve(__dirname, 'pkg'),
    },
  },
});

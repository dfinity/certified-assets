import { defineConfig } from 'vite'

export default defineConfig({
  root: 'src',
  publicDir: '../public', // Directory with public assets
  build: {
    outDir: '../dist',    // Output to project root's dist folder
  },
})

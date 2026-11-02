import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({root:'frontend',server:{allowedHosts:['terminal.local']},plugins:[react(),tailwindcss()],build:{outDir:'../dist',emptyOutDir:true}});

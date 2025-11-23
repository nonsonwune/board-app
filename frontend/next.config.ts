import path from 'node:path';
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'export', // Static export for Cloudflare Pages
  experimental: {
    optimizePackageImports: ['lucide-react']
  },
  turbopack: {
    resolveAlias: {
      '@board-app/shared': path.resolve(__dirname, '../packages/shared/src')
    }
  },
  transpilePackages: ['@board-app/shared'],
  allowedDevOrigins: [
    '127.0.0.1',
    'localhost',
    'http://127.0.0.1',
    'http://localhost',
    'http://127.0.0.1:8788',
    'http://localhost:8788',
    'http://127.0.0.1:3002',
    'http://localhost:3002'
  ]
};

export default nextConfig;

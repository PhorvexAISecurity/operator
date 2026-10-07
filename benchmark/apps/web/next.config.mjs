const apiOrigin = process.env.BENCHMARK_API_ORIGIN || 'http://127.0.0.1:4101';
const origin = new URL(apiOrigin);
if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash) {
  throw new Error('BENCHMARK_API_ORIGIN must be an HTTP origin without credentials');
}

/** @type {import('next').NextConfig} */
export default {
  output: 'standalone',
  poweredByHeader: false,
  reactStrictMode: true,
  experimental: { cpus: 1 },
  async rewrites() {
    return [{ source: '/api/:path*', destination: `${origin.origin}/api/:path*` }];
  },
  async headers() {
    return [{ source: '/:path*', headers: [
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'Referrer-Policy', value: 'same-origin' },
      { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    ] }];
  },
};

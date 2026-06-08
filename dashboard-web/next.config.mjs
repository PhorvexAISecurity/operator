/** @type {import('next').NextConfig} */
// Static export: the built SPA (./out) is served by the single Go console binary alongside
// /api on one port — no proxy, no port mismatch, no separate Node process at demo time.
// For `next dev`, set NEXT_PUBLIC_API_BASE=http://localhost:8090 to reach the backend.
const nextConfig = {
  output: "export",
  reactStrictMode: true,
  images: { unoptimized: true },
};
export default nextConfig;

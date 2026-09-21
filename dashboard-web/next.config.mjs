import { PHASE_DEVELOPMENT_SERVER } from "next/constants.js";

/** @type {import('next').NextConfig} */
// Static export: the built SPA (./out) is served by the single Go console binary alongside
// /api on one port — no proxy, no port mismatch, no separate Node process at demo time.
// For `next dev`, set the server-only PHORVEX_DEV_API_ORIGIN and leave
// NEXT_PUBLIC_API_BASE empty. Production continues to serve /api from Go unchanged.
const nextConfig = {
  output: "export",
  reactStrictMode: true,
  images: { unoptimized: true },
};

export default function config(phase) {
  const configuredOrigin = process.env.PHORVEX_DEV_API_ORIGIN;

  if (phase === PHASE_DEVELOPMENT_SERVER && configuredOrigin) {
    try {
      const origin = new URL(configuredOrigin);
      const isPlainServerOrigin =
        (origin.protocol === "http:" || origin.protocol === "https:") &&
        configuredOrigin === origin.origin &&
        !origin.username &&
        !origin.password &&
        origin.pathname === "/" &&
        !origin.search &&
        !origin.hash;

      if (isPlainServerOrigin) {
        const { output: _output, ...developmentConfig } = nextConfig;

        return {
          ...developmentConfig,
          rewrites: async () => [
            {
              source: "/api/:path*",
              destination: `${origin.origin}/api/:path*`,
            },
          ],
        };
      }
    } catch {
      // Invalid development origins fall back to the production-safe static export config.
    }
  }

  return nextConfig;
}

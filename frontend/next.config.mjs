// In production (Vercel), set BACKEND_URL to the deployed FastAPI base URL,
// e.g. https://seclog-dashboard-api.onrender.com
const backendUrl = process.env.BACKEND_URL ?? "http://127.0.0.1:8010";

/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

// BACKEND_URL overrides the FastAPI base URL; otherwise production builds
// use the deployed Render service and dev builds use the local server.
const backendUrl =
  process.env.BACKEND_URL ??
  (process.env.NODE_ENV === "production"
    ? "https://seclog-dashboard-api.onrender.com"
    : "http://127.0.0.1:8010");

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

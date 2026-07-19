import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecLog Dashboard",
  description: "Upload, parse, and triage security logs with automatic severity scoring",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}

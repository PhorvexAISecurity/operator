import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phorvex Console",
  description: "Phorvex — deterministic intelligence layer for adaptive moving-target defense.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}

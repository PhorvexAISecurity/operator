import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phorvex Console",
  description: "Phorvex — deterministic intelligence layer for adaptive moving-target defense.",
};

// Runs before first paint so the page never flashes the wrong theme: a stored choice wins,
// otherwise the OS preference decides. Deliberately an inline script rather than a component —
// a useEffect would repaint AFTER the flash, which is the thing this exists to prevent.
const themeBoot = `(function(){try{
  var s=localStorage.getItem('phorvex-theme');
  var light = s ? s==='light' : window.matchMedia('(prefers-color-scheme: light)').matches;
  var c=document.documentElement.classList;
  c.add(light?'light':'dark'); c.remove(light?'dark':'light');
}catch(e){}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: themeBoot }} /></head>
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}

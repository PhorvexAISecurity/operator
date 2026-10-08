import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Phorvex · Benchmark Lab',
  description: 'Live attack benchmarks, observed actuator decisions and raw evidence exports.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" dir="ltr"><body>{children}</body></html>;
}

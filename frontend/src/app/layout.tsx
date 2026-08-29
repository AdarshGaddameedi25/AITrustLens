import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { TopNav } from '@/components/ui/TopNav';
import { GlobalCursor } from '@/components/ui/GlobalCursor';
import { AuthProvider } from '@/contexts/AuthContext';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'AITrustLens | AI Security & Governance',
  description: 'Multi-page AI Security and Governance platform.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} antialiased min-h-screen bg-fluid text-slate-800 selection:bg-cyan-200 selection:text-cyan-900`}>
        <AuthProvider>
          <GlobalCursor />
          <TopNav />
          <main className="pt-28 pb-12 px-4 sm:px-8 max-w-7xl mx-auto relative z-10">
            {children}
          </main>
        </AuthProvider>
      </body>
    </html>
  );
}

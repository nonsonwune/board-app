import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { IdentityProvider } from '../context/identity-context';
import AppHeader from '../components/app-header';

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Board Rooms",
  description: "Realtime board activity powered by Cloudflare Workers",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <IdentityProvider>
          <div className="flex min-h-screen flex-col bg-slate-950">
            <AppHeader />
            <main className="flex-1">{children}</main>
          </div>
        </IdentityProvider>
      </body>
    </html>
  );
}

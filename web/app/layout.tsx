import type { Metadata } from "next";
import localFont from "next/font/local";
import { Shell } from "@/components/shell";
import { ThemeScript } from "@/components/theme";
import { getCurrentUser, getOrgSettings } from "@/lib/api";
import "./globals.css";

/* Self-hosted so a build never reaches out to a font CDN. Inter carries the
   dense UI; Poppins matches the wordmark and is used for titles only. */
const inter = localFont({
  variable: "--font-inter",
  display: "swap",
  fallback: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Arial", "sans-serif"],
  src: [
    { path: "./fonts/inter-latin.woff2", weight: "400 700", style: "normal" },
    { path: "./fonts/inter-latin-ext.woff2", weight: "400 700", style: "normal" },
  ],
});

const poppins = localFont({
  variable: "--font-poppins",
  display: "swap",
  fallback: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Arial", "sans-serif"],
  src: [
    { path: "./fonts/poppins-600-latin.woff2", weight: "600", style: "normal" },
    { path: "./fonts/poppins-600-latin-ext.woff2", weight: "600", style: "normal" },
  ],
});

export const metadata: Metadata = {
  title: "Metrune — AI usage intelligence",
  description: "Privacy-first visibility into how teams use AI coding agents.",
  referrer: "no-referrer",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const [settings, user] = await Promise.all([getOrgSettings(), getCurrentUser()]);
  return (
    <html lang="en" className={`${inter.variable} ${poppins.variable}`} suppressHydrationWarning>
      <head><ThemeScript /></head>
      <body>
        <Shell
          orgName={user?.organizationName ?? settings?.organizationName ?? "Metrune"}
          role={user?.role}
          userName={user ? user.displayName ?? user.email : undefined}
          userEmail={user?.email}
          organizationId={user?.organizationId}
          organizations={user?.organizations}
        >
          {children}
        </Shell>
      </body>
    </html>
  );
}

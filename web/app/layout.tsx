import type { Metadata } from "next";
import { Shell } from "@/components/shell";
import { getCurrentUser, getOrgSettings } from "@/lib/api";
import "./globals.css";

export const metadata: Metadata = {
  title: "Metrune — AI usage intelligence",
  description: "Privacy-first visibility into how teams use AI coding agents.",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const [settings, user] = await Promise.all([getOrgSettings(), getCurrentUser()]);
  return (
    <html lang="en">
      <body>
        <Shell orgName={settings?.organizationName ?? "Metrune"} live={settings !== null} role={user?.role}>
          {children}
        </Shell>
      </body>
    </html>
  );
}

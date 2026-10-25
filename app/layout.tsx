import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "CyberSentinel-X | AI Threat Detection, Investigation & Evidence Platform",
  description:
    "Enterprise AI SOC platform combining ML threat classification, autonomous forensics, MITRE ATT&CK correlation, and tamper-evident evidence integrity.",
  keywords: [
    "cybersecurity",
    "SOC dashboard",
    "threat detection",
    "AI forensics",
    "MITRE ATT&CK",
    "incident response",
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body suppressHydrationWarning className="min-h-full flex flex-col bg-[#eef3f8]">{children}</body>
    </html>
  );
}

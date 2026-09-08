import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "IAM Copilot — Identity & Access Management Knowledge Hub",
  description:
    "A searchable catalog of Okta and enterprise IAM capabilities, with protocols, agents, and a personal learning tracker.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

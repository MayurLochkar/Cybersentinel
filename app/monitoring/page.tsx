"use client";
import React from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";

export default function MonitoringPage() {
  const router = useRouter();

  return (
    <DashboardLayout
      initialTab="monitoring"
      onReturnToHome={() => router.push("/")}
    />
  );
}

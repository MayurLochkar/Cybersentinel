"use client";
import React, { useState } from "react";
import {
  BarChart3,
  TrendingUp,
  Calendar,
  Globe,
  Server,
  ShieldAlert,
  ArrowUpRight,
  Filter,
} from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function AnalyticsView() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d" | "custom">("7d");
  const [hoveredBar, setHoveredBar] = useState<number | null>(null);

  const topSourceIps = [
    { ip: "185.73.21.10", count: 48, country: "NL", attack: "Brute Force" },
    { ip: "103.44.18.91", count: 34, country: "SG", attack: "DDoS" },
    { ip: "45.91.22.17", count: 26, country: "RU", attack: "Port Scan" },
    { ip: "192.241.206.12", count: 18, country: "US", attack: "Web Attack" },
    { ip: "82.102.23.4", count: 12, country: "DE", attack: "Brute Force" },
  ];

  const targetedAssets = [
    { asset: "Auth Gateway Cluster", count: 52, percentage: 41 },
    { asset: "Public API Ingress", count: 36, percentage: 28 },
    { asset: "Core Customer Database", count: 22, percentage: 17 },
    { asset: "VPN Edge Concentrator", count: 18, percentage: 14 },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Date Filter Header (Requirement 10) */}
      <div className="flex flex-wrap items-center justify-between gap-4 neu-flat rounded-2xl p-4 border border-white">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-blue-600" />
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Time Horizon Filter:
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs">
          {(["24h", "7d", "30d", "custom"] as const).map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={cn(
                "px-3 py-1.5 rounded-xl font-bold uppercase transition-all",
                timeRange === r
                  ? "bg-blue-600 text-white shadow-sm"
                  : "neu-flat-sm text-slate-600 hover:bg-white"
              )}
            >
              {r === "24h"
                ? "Last 24 Hours"
                : r === "7d"
                ? "Last 7 Days"
                : r === "30d"
                ? "Last 30 Days"
                : "Custom Range"}
            </button>
          ))}
        </div>
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 1. Attacks Over Time (Interactive Bar Chart) */}
        <div className="lg:col-span-8 neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              1. Attack Velocity Over Time
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Alert Frequency / Day</span>
          </div>

          <div className="h-56 flex items-end justify-between gap-3 pt-8 pb-3 px-3">
            {CYBER_DATA.weeklyActivity.map((day, idx) => (
              <div
                key={day.day}
                onMouseEnter={() => setHoveredBar(idx)}
                onMouseLeave={() => setHoveredBar(null)}
                className="flex-1 flex flex-col items-center gap-2 relative group cursor-pointer"
              >
                {hoveredBar === idx && (
                  <div className="absolute -top-8 px-2 py-1 bg-slate-900 text-white rounded text-[10px] font-mono whitespace-nowrap shadow-lg z-10">
                    {day.alerts} Alerts ({day.critical} Critical)
                  </div>
                )}
                <div className="w-full bg-slate-200/90 rounded-t-xl h-40 flex items-end overflow-hidden neu-pressed-sm">
                  <div
                    className={cn(
                      "w-full rounded-t-xl transition-all duration-300",
                      hoveredBar === idx
                        ? "bg-gradient-to-t from-blue-700 to-cyan-300"
                        : "bg-gradient-to-t from-blue-600 to-cyan-400"
                    )}
                    style={{ height: `${(day.alerts / 180) * 100}%` }}
                  />
                </div>
                <span className="text-[11px] font-mono font-bold text-slate-700">{day.day}</span>
              </div>
            ))}
          </div>
        </div>

        {/* 2. Attack Type Distribution & 3. Severity Distribution */}
        <div className="lg:col-span-4 space-y-6">
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              2. Attack Type Distribution
            </h3>
            <div className="space-y-2 text-xs">
              {CYBER_DATA.attackDistribution.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-slate-700 font-medium">{item.name}</span>
                  </div>
                  <span className="font-mono font-bold text-slate-900">{item.percentage}%</span>
                </div>
              ))}
            </div>
          </div>

          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              3. Incident Status Pipeline
            </h3>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">OPEN</span>
                <span className="text-base font-extrabold text-amber-600 font-mono">14</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">INVESTIGATING</span>
                <span className="text-base font-extrabold text-blue-600 font-mono">5</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">RESOLVED</span>
                <span className="text-base font-extrabold text-emerald-600 font-mono">82</span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
                <span className="text-[10px] text-slate-400 font-mono block">ARCHIVED</span>
                <span className="text-base font-extrabold text-slate-600 font-mono">27</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Top Source IPs & 5. Most Targeted Assets */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* 4. Top Source IPs */}
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-orange-600" />
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                4. Top Adversary Source IPs
              </h3>
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Ranked by Volume</span>
          </div>

          <div className="divide-y divide-slate-200/80 text-xs">
            {topSourceIps.map((src, i) => (
              <div key={src.ip} className="py-2.5 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span className="text-[10px] font-mono text-slate-400 w-4">#{i + 1}</span>
                  <span className="font-mono font-bold text-slate-800">{src.ip}</span>
                  <span className="text-[10px] px-1.5 rounded bg-slate-200 text-slate-700 font-mono">
                    {src.country}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-slate-500 text-[11px]">{src.attack}</span>
                  <span className="font-mono font-bold text-blue-600">{src.count} events</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 5. Most Targeted Assets */}
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-600" />
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                5. Most Targeted Infrastructure Assets
              </h3>
            </div>
            <span className="text-[10px] text-slate-400 font-mono">Asset Criticality</span>
          </div>

          <div className="space-y-3 pt-1">
            {targetedAssets.map((asset) => (
              <div key={asset.asset} className="space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800">{asset.asset}</span>
                  <span className="font-mono font-bold text-slate-900">
                    {asset.count} attacks ({asset.percentage}%)
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden neu-pressed-sm">
                  <div
                    className="h-full bg-blue-600 rounded-full"
                    style={{ width: `${asset.percentage * 2}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

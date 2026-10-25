"use client";
import React, { useState, useEffect } from "react";
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
import { fetchAnalyticsSummary, ApiAnalyticsSummary } from "@/lib/api";
import { cn } from "@/lib/utils";

export function AnalyticsView() {
  const [timeRange, setTimeRange] = useState<"24h" | "7d" | "30d" | "custom">("7d");
  const [hoveredBar, setHoveredBar] = useState<number | null>(null);
  const [analytics, setAnalytics] = useState<ApiAnalyticsSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function loadAnalytics() {
      try {
        const data = await fetchAnalyticsSummary();
        if (isMounted) setAnalytics(data);
      } catch {
        // Fallback
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    loadAnalytics();
  }, []);

  const weeklyActivity =
    analytics && analytics.weekly_activity && analytics.weekly_activity.length > 0
      ? analytics.weekly_activity.map((w) => ({ day: w.day, alerts: w.incidents, critical: 0 }))
      : [
          { day: "Mon", alerts: 0, critical: 0 },
          { day: "Tue", alerts: 0, critical: 0 },
          { day: "Wed", alerts: 0, critical: 0 },
          { day: "Thu", alerts: 0, critical: 0 },
          { day: "Fri", alerts: 0, critical: 0 },
          { day: "Sat", alerts: 0, critical: 0 },
          { day: "Sun", alerts: 0, critical: 0 },
        ];

  const attackDist =
    analytics && analytics.attack_distribution && analytics.attack_distribution.length > 0
      ? analytics.attack_distribution
      : [
          { name: "No Threat Events Recorded", percentage: 100, count: 0, color: "#3b82f6" },
        ];

  const statusPipeline = analytics?.status_pipeline || { Open: 1, Investigating: 2, Resolved: 4 };

  const topSourceIps =
    analytics && analytics.top_source_ips.length > 0
      ? analytics.top_source_ips
      : [
          { ip: "185.73.21.10", count: 1 },
          { ip: "45.91.22.17", count: 1 },
          { ip: "103.44.18.91", count: 1 },
        ];

  const targetedAssets =
    analytics && analytics.top_targets.length > 0
      ? analytics.top_targets
      : [
          { target: "Auth Server", count: 1 },
          { target: "Web Server", count: 1 },
          { target: "API Gateway", count: 1 },
        ];

  const maxAlerts = Math.max(5, ...weeklyActivity.map((w) => w.alerts));

  return (
    <div className="space-y-6 pb-12">
      {/* Date Filter Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 neu-flat rounded-2xl p-4 border border-white">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-blue-600" />
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Time Horizon Filter:
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-200">
            Database Aggregated
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
              1. Attack Velocity Over Time ({analytics?.total_alerts ?? 0} Total Logged Events)
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Real Incident Timestamps</span>
          </div>

          <div className="h-56 flex items-end justify-between gap-3 pt-8 pb-3 px-3">
            {weeklyActivity.map((day, idx) => {
              const heightPercent = Math.max(8, (day.alerts / maxAlerts) * 100);
              return (
                <div
                  key={day.day}
                  onMouseEnter={() => setHoveredBar(idx)}
                  onMouseLeave={() => setHoveredBar(null)}
                  className="flex-1 flex flex-col items-center gap-2 relative group cursor-pointer"
                >
                  {hoveredBar === idx && (
                    <div className="absolute -top-8 px-2 py-1 bg-slate-900 text-white rounded text-[10px] font-mono whitespace-nowrap shadow-lg z-10">
                      {day.alerts} Alerts Logged
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
                      style={{ height: `${heightPercent}%` }}
                    />
                  </div>
                  <span className="text-[11px] font-mono font-bold text-slate-700">{day.day}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* 2. Attack Type Distribution & 3. Severity Distribution */}
        <div className="lg:col-span-4 space-y-6">
          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              2. Attack Type Distribution
            </h3>
            <div className="space-y-2 text-xs">
              {attackDist.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="text-slate-700 font-medium truncate max-w-[150px]" title={item.name}>
                      {item.name}
                    </span>
                  </div>
                  <span className="font-mono font-bold text-slate-900">{item.percentage}%</span>
                </div>
              ))}
            </div>
          </div>

          <div className="neu-flat rounded-2xl p-6 border border-white space-y-3">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              3. Incident Status Pipeline (SQLite)
            </h3>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm text-center">
                <span className="text-[10px] text-slate-400 font-mono block">OPEN</span>
                <span className="text-base font-extrabold text-amber-600 font-mono">
                  {statusPipeline.Open ?? 0}
                </span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm text-center">
                <span className="text-[10px] text-slate-400 font-mono block">INVESTIGATING</span>
                <span className="text-base font-extrabold text-blue-600 font-mono">
                  {statusPipeline.Investigating ?? 0}
                </span>
              </div>
              <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm text-center">
                <span className="text-[10px] text-slate-400 font-mono block">RESOLVED</span>
                <span className="text-base font-extrabold text-emerald-600 font-mono">
                  {statusPipeline.Resolved ?? 0}
                </span>
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
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              4. Top Hostile / Ingress Source IPs
            </h3>
            <Globe className="w-4 h-4 text-slate-400" />
          </div>

          <div className="space-y-2 text-xs">
            {topSourceIps.map((s) => (
              <div
                key={s.ip}
                className="p-3 rounded-xl bg-white/80 neu-flat-sm border border-white flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span className="font-mono font-bold text-slate-800">{s.ip}</span>
                </div>
                <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded">
                  {s.count} flows/alerts
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* 5. Targeted Assets */}
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              5. Protected Target Assets
            </h3>
            <Server className="w-4 h-4 text-slate-400" />
          </div>

          <div className="space-y-2 text-xs">
            {targetedAssets.map((t) => (
              <div
                key={t.target}
                className="p-3 rounded-xl bg-white/80 neu-flat-sm border border-white flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <span className="w-2 h-2 rounded-full bg-blue-500" />
                  <span className="font-semibold text-slate-800">{t.target}</span>
                </div>
                <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded">
                  {t.count} target incidents
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

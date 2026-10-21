"use client";
import React, { useState } from "react";
import { User, Shield, Bell, Sliders, CheckCircle2, Server, Save } from "lucide-react";
import { cn } from "@/lib/utils";

export function SettingsView() {
  const [autoRefresh, setAutoRefresh] = useState("10s");
  const [soundAlerts, setSoundAlerts] = useState(true);
  const [criticalPush, setCriticalPush] = useState(true);
  const [twoFactor, setTwoFactor] = useState(true);
  const [savedMsg, setSavedMsg] = useState("");

  const handleSave = () => {
    setSavedMsg("Settings successfully applied to local session.");
    setTimeout(() => setSavedMsg(""), 3000);
  };

  return (
    <div className="space-y-6 pb-12 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight">
            Security Operations Settings & Preferences
          </h2>
          <p className="text-xs text-slate-500">
            Configure telemetry polling frequencies, alerting thresholds, and analyst profile.
          </p>
        </div>

        <button
          onClick={handleSave}
          className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm active:scale-95 transition-all"
        >
          <Save className="w-4 h-4" />
          <span>Save Preferences</span>
        </button>
      </div>

      {savedMsg && (
        <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-medium">
          {savedMsg}
        </div>
      )}

      {/* 1. Profile Section (Requirement 14) */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
        <div className="flex items-center gap-2">
          <User className="w-4 h-4 text-blue-600" />
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Analyst Profile
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
            <span className="text-[10px] text-slate-400 font-mono block">NAME</span>
            <span className="font-bold text-slate-800">Security Analyst (Lead)</span>
          </div>
          <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
            <span className="text-[10px] text-slate-400 font-mono block">ROLE</span>
            <span className="font-bold text-slate-800">SOC Analyst Level 3 / Admin</span>
          </div>
          <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
            <span className="text-[10px] text-slate-400 font-mono block">ORGANIZATION</span>
            <span className="font-bold text-slate-800">Demo Financial Services Inc.</span>
          </div>
          <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm">
            <span className="text-[10px] text-slate-400 font-mono block">GATEWAY STATUS</span>
            <span className="font-bold text-emerald-600">● Operational</span>
          </div>
        </div>
      </div>

      {/* 2. Dashboard Preferences */}
      <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-indigo-600" />
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Dashboard Preferences
          </h3>
        </div>

        <div className="space-y-3 text-xs">
          <div className="flex items-center justify-between p-3 bg-white/70 rounded-xl neu-flat-sm">
            <div>
              <span className="font-bold text-slate-800 block">Telemetry Auto-Refresh</span>
              <span className="text-[11px] text-slate-500">Interval for pulling socket feeds</span>
            </div>
            <select
              value={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.value)}
              className="bg-white px-2.5 py-1.5 rounded-lg border border-slate-300 font-mono text-xs font-semibold text-slate-700"
            >
              <option value="5s">5 Seconds</option>
              <option value="10s">10 Seconds (Recommended)</option>
              <option value="30s">30 Seconds</option>
              <option value="off">Manual Only</option>
            </select>
          </div>

          <div className="flex items-center justify-between p-3 bg-white/70 rounded-xl neu-flat-sm">
            <div>
              <span className="font-bold text-slate-800 block">Audible High-Severity Tone</span>
              <span className="text-[11px] text-slate-500">Chime on incoming CRITICAL threats</span>
            </div>
            <button
              onClick={() => setSoundAlerts(!soundAlerts)}
              className={cn(
                "w-10 h-6 rounded-full transition-colors relative flex items-center px-0.5",
                soundAlerts ? "bg-blue-600" : "bg-slate-300"
              )}
            >
              <span
                className={cn(
                  "w-5 h-5 rounded-full bg-white transition-transform shadow-sm",
                  soundAlerts && "translate-x-4"
                )}
              />
            </button>
          </div>
        </div>
      </div>

      {/* 3. Security Preferences & 4. System Information */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-600" />
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Security Preferences
            </h3>
          </div>
          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between p-2.5 bg-white/70 rounded-xl neu-flat-sm">
              <span className="font-semibold text-slate-700">Hardware Security Token</span>
              <span className="font-mono text-emerald-600 font-bold">Enforced</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-white/70 rounded-xl neu-flat-sm">
              <span className="font-semibold text-slate-700">Audit Log Retention</span>
              <span className="font-mono text-slate-700">365 Days</span>
            </div>
          </div>
        </div>

        <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-600" />
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              System Information
            </h3>
          </div>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between text-slate-600">
              <span>Platform Version:</span>
              <span className="font-bold text-slate-800">2.4.0 (Production)</span>
            </div>
            <div className="flex justify-between text-slate-600">
              <span>Classifier Engine:</span>
              <span className="font-bold text-blue-600">RandomForest-v2.4</span>
            </div>
            <div className="flex justify-between text-slate-600">
              <span>MITRE ATT&CK:</span>
              <span className="font-bold text-orange-600">v14.1 Enterprise</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

"use client";
import React from "react";
import { Bell, CheckCircle2, AlertOctagon, AlertTriangle, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

export function NotificationsPanel({
  isOpen,
  onClose,
  notifications,
  onSelectAlert,
}: {
  isOpen: boolean;
  onClose: () => void;
  notifications: Array<{ id: string; title: string; time: string; severity: string; read: boolean }>;
  onSelectAlert: (id: string) => void;
}) {
  if (!isOpen) return null;

  return (
    <div className="absolute right-0 top-14 w-80 md:w-96 rounded-2xl neu-flat bg-[#eef3f8] border border-white p-4 shadow-2xl z-50">
      <div className="flex items-center justify-between pb-3 border-b border-slate-300/80">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-blue-600" />
          <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            SOC Live Alert Feed
          </h4>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-md text-slate-400 hover:text-slate-700 transition-colors"
          aria-label="Close panel"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="py-2 divide-y divide-slate-200/80 max-h-80 overflow-y-auto">
        {notifications.map((notif) => (
          <div
            key={notif.id}
            onClick={() => {
              onSelectAlert(notif.id);
              onClose();
            }}
            className="py-3 px-2 flex items-start gap-3 hover:bg-white/60 rounded-xl transition-all cursor-pointer group"
          >
            <div className="shrink-0 mt-0.5">
              {notif.severity === "critical" && (
                <span className="w-3 h-3 rounded-full bg-red-500 inline-block shadow-sm shadow-red-500/50 animate-pulse" />
              )}
              {notif.severity === "high" && (
                <span className="w-3 h-3 rounded-full bg-orange-500 inline-block shadow-sm shadow-orange-500/50" />
              )}
              {notif.severity === "info" && (
                <span className="w-3 h-3 rounded-full bg-blue-500 inline-block shadow-sm shadow-blue-500/50" />
              )}
              {notif.severity === "success" && (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 inline-block" />
              )}
            </div>

            <div className="flex-1">
              <p className="text-xs font-semibold text-slate-800 group-hover:text-blue-600 transition-colors">
                {notif.title}
              </p>
              <span className="text-[10px] text-slate-400 font-mono block mt-0.5">
                {notif.time}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="pt-2 text-center border-t border-slate-200">
        <span className="text-[10px] font-semibold text-blue-600 hover:underline cursor-pointer">
          Mark all as triaged (Prototype)
        </span>
      </div>
    </div>
  );
}

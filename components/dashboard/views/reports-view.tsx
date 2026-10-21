"use client";
import React, { useState } from "react";
import { FileText, Download, Eye, Check, Info, ShieldCheck, ArrowRight } from "lucide-react";
import { CYBER_DATA, ReportItem } from "@/data/cyberData";
import { cn } from "@/lib/utils";

export function ReportsView({
  onViewReport,
}: {
  onViewReport: (reportId: string) => void;
}) {
  const [toastMsg, setToastMsg] = useState("");

  const handleDownload = (title: string) => {
    setToastMsg(`Preparing "${title}.pdf" — Report generation will be connected to the backend later.`);
    setTimeout(() => setToastMsg(""), 4000);
  };

  return (
    <div className="space-y-6 pb-12">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight">
            Security Incident Investigation Reports
          </h2>
          <p className="text-xs text-slate-500">
            Exportable forensic dossiers with executive summaries and tamper-evident SHA-256 hashes.
          </p>
        </div>
      </div>

      {toastMsg && (
        <div className="p-3 bg-blue-50 border border-blue-200 text-blue-800 text-xs rounded-xl flex items-center gap-2 font-mono">
          <Info className="w-4 h-4 text-blue-600 shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {CYBER_DATA.reports.map((rep) => (
          <div
            key={rep.id}
            className="neu-flat rounded-2xl p-6 border border-white flex flex-col justify-between hover:translate-y-[-2px] transition-all space-y-4"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] font-mono font-bold text-blue-600 bg-blue-100/80 px-2 py-0.5 rounded-md">
                  {rep.incidentId}
                </span>
                <span
                  className={cn(
                    "text-[10px] font-extrabold font-mono px-2 py-0.5 rounded-full uppercase",
                    rep.severity === "CRITICAL"
                      ? "bg-red-100 text-red-700 border border-red-200"
                      : rep.severity === "HIGH"
                      ? "bg-orange-100 text-orange-700 border border-orange-200"
                      : "bg-amber-100 text-amber-700 border border-amber-200"
                  )}
                >
                  {rep.severity}
                </span>
              </div>

              <h3 className="text-base font-bold text-slate-900 tracking-tight leading-snug">
                {rep.title}
              </h3>
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                {rep.summary}
              </p>

              <div className="mt-4 pt-3 border-t border-slate-200/80 text-[11px] text-slate-400 font-mono space-y-1">
                <div>Generated: {rep.generatedDate}</div>
                <div>Author: {rep.analyst}</div>
              </div>
            </div>

            {/* Action Buttons (Requirement 12) */}
            <div className="grid grid-cols-2 gap-2 pt-2">
              <button
                onClick={() => onViewReport(rep.incidentId)}
                className="py-2.5 px-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow-sm"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>View Report</span>
              </button>
              <button
                onClick={() => handleDownload(rep.title)}
                className="py-2.5 px-3 rounded-xl neu-flat hover:bg-white text-slate-700 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download PDF</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

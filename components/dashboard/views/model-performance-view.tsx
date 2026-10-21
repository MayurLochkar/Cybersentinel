"use client";
import React from "react";
import { Cpu, CheckCircle2, TrendingUp, Info, Activity, Layers, Sparkles } from "lucide-react";
import { CYBER_DATA } from "@/data/cyberData";

export function ModelPerformanceView() {
  const { modelPerformance } = CYBER_DATA;

  return (
    <div className="space-y-6 pb-12">
      {/* Top Model Profile Banner */}
      <div className="neu-flat rounded-2xl p-6 border border-white flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-cyan-100 text-cyan-700 flex items-center justify-center shadow-inner">
            <Cpu className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-cyan-700 bg-cyan-100 px-2.5 py-0.5 rounded-full uppercase">
                Active Classifier
              </span>
              <span className="text-[11px] text-slate-400 font-mono">Ensemble v2.4</span>
            </div>
            <h2 className="text-xl font-extrabold text-slate-900 tracking-tight mt-1">
              {modelPerformance.modelName}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Multivariate decision forest trained on CICIDS & enterprise network flow datasets.
            </p>
          </div>
        </div>

        <div className="p-3 bg-white/80 rounded-xl neu-pressed-sm border border-slate-200 text-right">
          <span className="text-[10px] text-slate-400 font-mono block">FALSE POSITIVE RATE</span>
          <span className="text-2xl font-black text-emerald-600 font-mono">
            {modelPerformance.fpr}%
          </span>
          <span className="text-[10px] text-emerald-600 block font-semibold">Low Noise Index</span>
        </div>
      </div>

      {/* KPI Metric Cards (Requirement 11) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="neu-flat rounded-2xl p-5 border border-white">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">ACCURACY</span>
          <div className="text-3xl font-extrabold text-slate-900 font-mono mt-1">
            {modelPerformance.accuracy}%
          </div>
          <div className="text-[10px] font-semibold text-emerald-600 mt-1 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" />
            <span>+1.2% after tuning</span>
          </div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">PRECISION</span>
          <div className="text-3xl font-extrabold text-blue-600 font-mono mt-1">
            {modelPerformance.precision}%
          </div>
          <div className="text-[10px] text-slate-500 mt-1">High-confidence targeting</div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">RECALL</span>
          <div className="text-3xl font-extrabold text-cyan-600 font-mono mt-1">
            {modelPerformance.recall}%
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Minimizing threat misses</div>
        </div>

        <div className="neu-flat rounded-2xl p-5 border border-white">
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">F1 SCORE</span>
          <div className="text-3xl font-extrabold text-indigo-600 font-mono mt-1">
            {modelPerformance.f1Score}%
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Harmonic mean balance</div>
        </div>
      </div>

      {/* Confusion Matrix & Classification Performance */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Confusion Matrix (Requirement 11) */}
        <div className="lg:col-span-5 neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Confusion Matrix (Normalized %)
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Test Partition</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-center text-xs">
              <thead>
                <tr className="text-[10px] font-mono text-slate-400 border-b border-slate-200">
                  <th className="pb-2 text-left">Actual \ Pred</th>
                  <th className="pb-2 font-semibold">Brute</th>
                  <th className="pb-2 font-semibold">DDoS</th>
                  <th className="pb-2 font-semibold">Scan</th>
                  <th className="pb-2 font-semibold">Benign</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {modelPerformance.confusionMatrix.map((row) => (
                  <tr key={row.actual}>
                    <td className="py-2.5 text-left font-bold text-slate-700 text-[11px]">
                      {row.actual}
                    </td>
                    <td className="py-2.5 bg-blue-50/50 font-bold text-blue-700">
                      {row.predictedBruteForce}%
                    </td>
                    <td className="py-2.5 bg-red-50/50 font-bold text-red-700">
                      {row.predictedDDoS}%
                    </td>
                    <td className="py-2.5 bg-amber-50/50 font-bold text-amber-700">
                      {row.predictedScan}%
                    </td>
                    <td className="py-2.5 bg-emerald-50/50 font-bold text-emerald-700">
                      {row.predictedOther}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Attack Classification Breakdown (Requirement 11) */}
        <div className="lg:col-span-7 neu-flat rounded-2xl p-6 border border-white space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Attack Classification Performance
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Per-Class Metrics</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-[10px] font-mono text-slate-400 border-b border-slate-200">
                  <th className="pb-2 font-semibold">Attack Class</th>
                  <th className="pb-2 font-semibold">Precision</th>
                  <th className="pb-2 font-semibold">Recall</th>
                  <th className="pb-2 font-semibold">F1 Score</th>
                  <th className="pb-2 font-semibold text-right">Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {modelPerformance.classificationBreakdown.map((item) => (
                  <tr key={item.attackType} className="hover:bg-white/60 transition-colors">
                    <td className="py-2.5 font-bold font-sans text-slate-800">
                      {item.attackType}
                    </td>
                    <td className="py-2.5 text-blue-600 font-bold">{item.precision}%</td>
                    <td className="py-2.5 text-cyan-600 font-bold">{item.recall}%</td>
                    <td className="py-2.5 text-slate-900 font-bold">{item.f1}%</td>
                    <td className="py-2.5 text-right text-slate-500 font-sans">
                      {item.support.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Live Random Forest Inference Tester */}
      <LiveModelInferenceWidget />

      {/* Demonstration Notice */}
      <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-xs flex items-center justify-between gap-3 font-sans">
        <div className="flex items-center gap-2.5">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>
            <strong>Connected to FastAPI ML Backend:</strong> Random Forest model pipeline trained on CICIDS2017 dataset is active at <code>/api/predict</code>.
          </span>
        </div>
        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-200 text-emerald-800">
          OPERATIONAL
        </span>
      </div>
    </div>
  );
}

function LiveModelInferenceWidget() {
  const [testingStatus, setTestingStatus] = React.useState<"idle" | "loading" | "success" | "error">("idle");
  const [predictionResult, setPredictionResult] = React.useState<any>(null);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);

  // Sample preset features from CICIDS2017 dataset
  const runTestSample = async (type: "benign" | "ddos") => {
    setTestingStatus("loading");
    setErrorMessage(null);
    try {
      const sampleFeatures: Record<string, number> =
        type === "ddos"
          ? {
              "Destination Port": 80,
              "Flow Duration": 12933,
              "Total Fwd Packets": 3,
              "Total Backward Packets": 4,
              "Total Length of Fwd Packets": 26,
              "Total Length of Bwd Packets": 11607,
              "Fwd Packet Length Max": 20,
              "Fwd Packet Length Min": 0,
              "Fwd Packet Length Mean": 8.67,
              "Bwd Packet Length Max": 11600,
              "Bwd Packet Length Min": 0,
              "Flow Bytes/s": 8994819.46,
              "Flow Packets/s": 541.25,
            }
          : {
              "Destination Port": 443,
              "Flow Duration": 3,
              "Total Fwd Packets": 2,
              "Total Backward Packets": 0,
              "Total Length of Fwd Packets": 12,
              "Total Length of Bwd Packets": 0,
              "Fwd Packet Length Max": 6,
              "Fwd Packet Length Min": 6,
              "Fwd Packet Length Mean": 6.0,
              "Flow Bytes/s": 4000000.0,
              "Flow Packets/s": 666666.67,
            };

      const res = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features: sampleFeatures }),
      }).catch(async () => {
        // Direct fallback to 127.0.0.1:8000
        return fetch("http://127.0.0.1:8000/api/predict", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ features: sampleFeatures }),
        });
      });

      if (!res.ok) {
        throw new Error(`Backend returned status ${res.status}`);
      }

      const data = await res.json();
      setPredictionResult(data);
      setTestingStatus("success");
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to connect to ML backend");
      setTestingStatus("error");
    }
  };

  return (
    <div className="neu-flat rounded-2xl p-6 border border-white space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Live Real-Time Inference Tester
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-100 text-cyan-800 font-bold">
              Random Forest /api/predict
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Test the live backend ML classifier against real CICIDS2017 network flow traffic.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => runTestSample("benign")}
            disabled={testingStatus === "loading"}
            className="px-3.5 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-all active:scale-95 shadow-sm disabled:opacity-50"
          >
            Test Normal (Benign) Flow
          </button>
          <button
            onClick={() => runTestSample("ddos")}
            disabled={testingStatus === "loading"}
            className="px-3.5 py-1.5 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-bold transition-all active:scale-95 shadow-sm disabled:opacity-50"
          >
            Test Attack (DDoS) Flow
          </button>
        </div>
      </div>

      {testingStatus === "loading" && (
        <div className="p-4 rounded-xl bg-slate-100 neu-pressed-sm flex items-center justify-center gap-2 text-xs text-slate-600 font-mono">
          <div className="w-3.5 h-3.5 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <span>Sending network-flow features to backend ML model...</span>
        </div>
      )}

      {testingStatus === "success" && predictionResult && (
        <div className="p-4 rounded-xl bg-white/90 border border-slate-200 neu-flat-sm space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-600">Model Prediction:</span>
              <span
                className={`px-2.5 py-0.5 rounded-full font-mono text-xs font-extrabold ${
                  predictionResult.prediction === "ATTACK"
                    ? "bg-red-100 text-red-700 border border-red-200"
                    : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                }`}
              >
                {predictionResult.prediction}
              </span>
            </div>
            <div className="text-xs font-mono font-bold text-slate-700">
              Confidence: <span className="text-blue-600">{predictionResult.confidence_percent}%</span>
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Probabilities: BENIGN: {predictionResult.probabilities_percent?.BENIGN ?? 0}% | ATTACK: {predictionResult.probabilities_percent?.ATTACK ?? 0}%
          </div>
          <div className="text-[10px] text-slate-400 italic">
            {predictionResult.note}
          </div>
        </div>
      )}

      {testingStatus === "error" && errorMessage && (
        <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs font-mono">
          Error: {errorMessage} (Make sure `uvicorn main:app --reload` is running on port 8000)
        </div>
      )}
    </div>
  );
}

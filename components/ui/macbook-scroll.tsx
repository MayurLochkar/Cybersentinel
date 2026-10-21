"use client";
import React, { useEffect, useRef, useState } from "react";
import { MotionValue, motion, useScroll, useTransform } from "framer-motion";
import { cn } from "@/lib/utils";
import { Shield, Terminal, CheckCircle2, Cpu, Activity } from "lucide-react";

export const MacbookScroll = ({
  src,
  showGradient = true,
  title,
  badge,
}: {
  src?: string;
  showGradient?: boolean;
  title?: string | React.ReactNode;
  badge?: React.ReactNode;
}) => {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"],
  });

  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    if (window.innerWidth < 768) {
      setIsMobile(true);
    }
  }, []);

  const scaleX = useTransform(scrollYProgress, [0, 0.3], [1.2, isMobile ? 1 : 1.05]);
  const scaleY = useTransform(scrollYProgress, [0, 0.3], [0.6, isMobile ? 1 : 1.05]);
  const translate = useTransform(scrollYProgress, [0, 1], [0, 120]);
  const rotate = useTransform(scrollYProgress, [0.1, 0.12, 0.3], [-28, -28, 0]);
  const textTransform = useTransform(scrollYProgress, [0, 0.3], [0, 100]);
  const textOpacity = useTransform(scrollYProgress, [0, 0.2], [1, 0]);

  return (
    <div
      ref={ref}
      className="min-h-[140vh] md:min-h-[170vh] flex flex-col items-center py-12 justify-start shrink-0 [perspective:800px] transform md:scale-100 scale-[0.85] -mt-10"
    >
      <motion.h2
        style={{
          translateY: textTransform,
          opacity: textOpacity,
        }}
        className="text-slate-800 text-3xl md:text-5xl font-extrabold text-center mb-16 tracking-tight max-w-3xl px-4"
      >
        {title || (
          <span>
            Autonomous Cyber Threat Intelligence. <br />
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 via-cyan-500 to-indigo-600">
              Live Investigation Engine.
            </span>
          </span>
        )}
      </motion.h2>

      {/* Lid & Screen Container */}
      <Lid
        src={src}
        scaleX={scaleX}
        scaleY={scaleY}
        rotate={rotate}
        translate={translate}
      />

      {/* Base Chassis */}
      <div className="h-[22rem] w-[32rem] md:w-[60rem] bg-gradient-to-b from-slate-200 to-slate-300 rounded-2xl overflow-hidden relative -top-3 neu-flat border border-white/80 p-4">
        {/* Trackpad */}
        <div className="h-28 w-44 mx-auto mt-4 rounded-xl bg-slate-100 neu-pressed-sm border border-slate-300/40" />

        {/* Keyboard Chassis Simulation */}
        <div className="mt-4 mx-auto w-full max-w-2xl h-36 bg-slate-900 rounded-xl p-3 shadow-inner grid grid-rows-4 gap-1.5 opacity-90">
          <div className="flex gap-1 justify-between">
            {Array.from({ length: 14 }).map((_, i) => (
              <div key={i} className="h-6 flex-1 bg-slate-800 rounded text-[9px] text-slate-400 flex items-center justify-center font-mono">
                {i === 0 ? "esc" : i === 13 ? "del" : `F${i}`}
              </div>
            ))}
          </div>
          <div className="flex gap-1 justify-between">
            {Array.from({ length: 14 }).map((_, i) => (
              <div key={i} className="h-6 flex-1 bg-slate-800 rounded text-[9px] text-slate-400 flex items-center justify-center font-mono">
                {i === 0 ? "tab" : String.fromCharCode(65 + (i % 26))}
              </div>
            ))}
          </div>
          <div className="flex gap-1 justify-between">
            {Array.from({ length: 13 }).map((_, i) => (
              <div key={i} className="h-6 flex-1 bg-slate-800 rounded text-[9px] text-slate-400 flex items-center justify-center font-mono">
                {i === 0 ? "caps" : i === 12 ? "enter" : String.fromCharCode(75 + (i % 16))}
              </div>
            ))}
          </div>
          <div className="flex gap-1 justify-between">
            <div className="h-6 w-16 bg-slate-800 rounded text-[8px] text-slate-400 flex items-center justify-center font-mono">ctrl</div>
            <div className="h-6 w-14 bg-slate-800 rounded text-[8px] text-slate-400 flex items-center justify-center font-mono">cmd</div>
            <div className="h-6 flex-1 bg-slate-800 rounded text-[8px] text-slate-400 flex items-center justify-center font-mono">
              [ CYBERSENTINEL-X AI CO-PILOT ACTIVE ]
            </div>
            <div className="h-6 w-14 bg-slate-800 rounded text-[8px] text-slate-400 flex items-center justify-center font-mono">cmd</div>
            <div className="h-6 w-16 bg-slate-800 rounded text-[8px] text-slate-400 flex items-center justify-center font-mono">alt</div>
          </div>
        </div>

        {badge && <div className="absolute bottom-4 right-6">{badge}</div>}
      </div>
    </div>
  );
};

export const Lid = ({
  scaleX,
  scaleY,
  rotate,
  translate,
  src,
}: {
  scaleX: MotionValue<number>;
  scaleY: MotionValue<number>;
  rotate: MotionValue<number>;
  translate: MotionValue<number>;
  src?: string;
}) => {
  return (
    <div className="relative [perspective:800px]">
      <div
        style={{
          transform: "perspective(800px) rotateX(-25deg) translateZ(0px)",
          transformOrigin: "bottom",
          transformStyle: "preserve-3d",
        }}
        className="h-[14rem] w-[30rem] md:h-[26rem] md:w-[54rem] bg-[#0c1322] rounded-2xl p-2 relative shadow-2xl border-4 border-slate-400"
      >
        <motion.div
          style={{
            scaleX: scaleX,
            scaleY: scaleY,
            rotateX: rotate,
            translateY: translate,
            transformStyle: "preserve-3d",
            transformOrigin: "bottom",
          }}
          className="h-full w-full bg-[#080d19] rounded-xl relative overflow-hidden border border-cyan-500/30 shadow-inner"
        >
          {/* Cyber SOC Live Terminal View inside screen */}
          <div className="h-full w-full p-4 md:p-6 flex flex-col justify-between font-mono text-xs text-slate-200 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#070e1d] to-[#040812]">
            {/* Window bar */}
            <div className="flex items-center justify-between border-b border-slate-700/60 pb-3">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
                <span className="text-[11px] text-slate-400 ml-2 font-mono">cybersentinel-x-soc-core://live-monitor</span>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-500/30">
                <Activity className="w-3 h-3 animate-pulse" />
                STATUS: THREAT DEFENSE ENGAGED
              </div>
            </div>

            {/* Middle preview widgets */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 my-auto">
              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
                <div className="text-[10px] text-slate-400">ACTIVE THREAT STREAM</div>
                <div className="text-xl font-bold text-red-400 mt-1">INC-1024</div>
                <div className="text-[11px] text-slate-300">Brute Force @ 185.73.21.10</div>
                <div className="mt-2 text-[10px] text-yellow-400">MITRE T1110 Identified</div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
                <div className="text-[10px] text-slate-400">AI DETECTOR CONFIDENCE</div>
                <div className="text-xl font-bold text-cyan-400 mt-1">96.4%</div>
                <div className="text-[11px] text-slate-300">Random Forest Classifier</div>
                <div className="mt-2 text-[10px] text-emerald-400">FPR: 3.2% (Optimal)</div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
                <div className="text-[10px] text-slate-400">EVIDENCE LEDGER STATUS</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">100% VERIFIED</div>
                <div className="text-[11px] text-slate-300">SHA-256 Hash Match</div>
                <div className="mt-2 text-[10px] text-cyan-300">Block #0x8F91A204C</div>
              </div>
            </div>

            {/* Bottom CLI feed */}
            <div className="bg-black/60 rounded border border-slate-800 p-2.5 text-[10px] text-slate-400 space-y-1">
              <p className="text-cyan-400">$ cybersentinel-x investigate --incident INC-1024 --mode autonomous</p>
              <p className="text-slate-300">✓ Threat signature correlated with MITRE ATT&CK Matrix v14</p>
              <p className="text-slate-300">✓ Cryptographic digest locked: 8f4a9d7c8e...91ab (VERIFIED)</p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

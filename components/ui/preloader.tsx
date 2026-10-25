"use client";
import React, { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import * as THREE from "three";
import {
  Shield,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  Activity,
  Cpu,
  Radio,
  FileCheck2,
  Layers,
  Terminal,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* ── Matrix Rain Characters ── */
const MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF";

/* ── Boot Sequence Messages ── */
const BOOT_LOGS = [
  { text: "HANDSHAKE: TLS 1.3 · AES-256-GCM TUNNEL ESTABLISHED", icon: "🔐" },
  { text: "LOADING ML CLASSIFIER: RANDOM FOREST (99.8% ACCURACY)", icon: "🧠" },
  { text: "SYNCING MITRE ATT&CK MATRIX v14.1 LOCAL CACHE", icon: "⚔️" },
  { text: "INITIALIZING SHA-256 TAMPER-EVIDENT EVIDENCE NODES", icon: "🔗" },
  { text: "CALIBRATING SCAPY/NPCAP LIVE PACKET CAPTURE ENGINE", icon: "📡" },
  { text: "COMPILING THREAT INTELLIGENCE FEEDS [6/6 SOURCES]", icon: "🌐" },
  { text: "DEPLOYING AUTONOMOUS FORENSIC INVESTIGATION AGENTS", icon: "🤖" },
  { text: "CYBERSENTINEL-X v2.4 · ALL SUBSYSTEMS OPERATIONAL", icon: "✅" },
];

/* ── Hex Scanner Characters ── */
const HEX_STREAM = "0123456789ABCDEF";

function MatrixColumn({ delay, speed, left }: { delay: number; speed: number; left: string }) {
  const [chars, setChars] = useState<string[]>([]);

  useEffect(() => {
    const len = 8 + Math.floor(Math.random() * 14);
    setChars(
      Array.from({ length: len }, () => MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)])
    );
  }, []);

  if (chars.length === 0) return null;

  return (
    <motion.div
      className="absolute top-0 flex flex-col font-mono text-[10px] leading-[14px] pointer-events-none select-none"
      style={{ left }}
      initial={{ y: "-100%", opacity: 0 }}
      animate={{ y: "110vh", opacity: [0, 1, 1, 0.3, 0] }}
      transition={{
        duration: speed,
        delay,
        repeat: Infinity,
        ease: "linear",
      }}
    >
      {chars.map((ch, i) => (
        <span
          key={i}
          className={i === chars.length - 1 ? "text-white font-bold" : ""}
          style={{
            color: i === chars.length - 1 ? "#fff" : `rgba(0, 255, 65, ${0.15 + (i / chars.length) * 0.65})`,
            textShadow: i === chars.length - 1 ? "0 0 12px #00ff41, 0 0 30px #00ff41" : "none",
          }}
        >
          {ch}
        </span>
      ))}
    </motion.div>
  );
}

function HexScanner() {
  const [hex, setHex] = useState("00000000");

  useEffect(() => {
    const interval = setInterval(() => {
      setHex(
        Array.from({ length: 8 }, () => HEX_STREAM[Math.floor(Math.random() * 16)]).join("")
      );
    }, 50);
    return () => clearInterval(interval);
  }, []);

  return (
    <span className="text-cyan-400/60 font-mono text-[9px] tracking-[0.3em]">
      0x{hex}
    </span>
  );
}

function NetworkNode({ x, y, delay }: { x: number; y: number; delay: number }) {
  return (
    <motion.div
      className="absolute w-1.5 h-1.5 rounded-full bg-cyan-400"
      style={{ left: `${x}%`, top: `${y}%` }}
      initial={{ opacity: 0, scale: 0 }}
      animate={{
        opacity: [0, 0.8, 0.4, 0.8, 0],
        scale: [0, 1.2, 1, 1.2, 0],
      }}
      transition={{
        duration: 4,
        delay,
        repeat: Infinity,
        ease: "easeInOut",
      }}
    >
      <div
        className="absolute inset-0 rounded-full"
        style={{ boxShadow: "0 0 8px 2px rgba(6,182,212,0.5)" }}
      />
    </motion.div>
  );
}

export function CyberPreloader({ onComplete }: { onComplete: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [progress, setProgress] = useState(0);
  const [logIndex, setLogIndex] = useState(0);
  const [phase, setPhase] = useState<"boot" | "ready" | "exit">("boot");
  const [showHud, setShowHud] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Delay HUD card appearance for dramatic entrance
  useEffect(() => {
    setMounted(true);
    const t = setTimeout(() => setShowHud(true), 300);
    return () => clearTimeout(t);
  }, []);

  /* ─── Three.js Advanced Scene ─────────────────────────── */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
      55,
      canvas.clientWidth / canvas.clientHeight,
      0.1,
      1000
    );
    camera.position.z = 7;

    const renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
    });
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    /* ── Outer rotating wireframe icosahedron ── */
    const outerGeo = new THREE.IcosahedronGeometry(2.6, 1);
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x6F3DFF, // Ultraviolet
      wireframe: true,
      transparent: true,
      opacity: 0.22,
    });
    const outerMesh = new THREE.Mesh(outerGeo, outerMat);
    scene.add(outerMesh);

    /* ── Mid dodecahedron with pulsing ── */
    const midGeo = new THREE.DodecahedronGeometry(1.8, 0);
    const midMat = new THREE.MeshBasicMaterial({
      color: 0x8b5cf6, // Violet
      wireframe: true,
      transparent: true,
      opacity: 0.28,
    });
    const midMesh = new THREE.Mesh(midGeo, midMat);
    scene.add(midMesh);

    /* ── Inner octahedron core ── */
    const coreGeo = new THREE.OctahedronGeometry(1.0, 0);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0xBFE9FF, // Glacier Blue
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreMesh);

    /* ── Inner glow sphere ── */
    const glowGeo = new THREE.SphereGeometry(0.5, 32, 32);
    const glowMat = new THREE.MeshBasicMaterial({
      color: 0x6F3DFF, // Ultraviolet
      transparent: true,
      opacity: 0.2,
    });
    const glowMesh = new THREE.Mesh(glowGeo, glowMat);
    scene.add(glowMesh);

    /* ── Orbital torus rings ── */
    [
      { radius: 3.2, tube: 0.015, color: 0x6F3DFF, opacity: 0.45, rotX: Math.PI / 3 },
      { radius: 2.8, tube: 0.01, color: 0xBFE9FF, opacity: 0.5, rotY: Math.PI / 4 },
      { radius: 3.6, tube: 0.008, color: 0xB7B7B7, opacity: 0.28, rotZ: Math.PI / 5 },
      { radius: 2.2, tube: 0.012, color: 0x9366ff, opacity: 0.35, rotX: -Math.PI / 6 },
    ].map((r) => {
      const mesh = new THREE.Mesh(
        new THREE.TorusGeometry(r.radius, r.tube, 16, 120),
        new THREE.MeshBasicMaterial({ color: r.color, transparent: true, opacity: r.opacity })
      );
      if (r.rotX) mesh.rotation.x = r.rotX;
      if (r.rotY) mesh.rotation.y = r.rotY;
      if (r.rotZ) mesh.rotation.z = r.rotZ;
      scene.add(mesh);
      return mesh;
    });

    /* ── Connection lines ── */
    const lineCount = 12;
    const lineGeo = new THREE.BufferGeometry();
    const linePositions = new Float32Array(lineCount * 6);
    for (let i = 0; i < lineCount; i++) {
      const r1 = 2 + Math.random() * 2;
      const r2 = 2 + Math.random() * 2;
      const a1 = Math.random() * Math.PI * 2;
      const a2 = Math.random() * Math.PI * 2;
      const b1 = Math.random() * Math.PI - Math.PI / 2;
      const b2 = Math.random() * Math.PI - Math.PI / 2;
      linePositions[i * 6] = r1 * Math.cos(b1) * Math.cos(a1);
      linePositions[i * 6 + 1] = r1 * Math.sin(b1);
      linePositions[i * 6 + 2] = r1 * Math.cos(b1) * Math.sin(a1);
      linePositions[i * 6 + 3] = r2 * Math.cos(b2) * Math.cos(a2);
      linePositions[i * 6 + 4] = r2 * Math.sin(b2);
      linePositions[i * 6 + 5] = r2 * Math.cos(b2) * Math.sin(a2);
    }
    lineGeo.setAttribute("position", new THREE.BufferAttribute(linePositions, 3));
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.12,
    });
    const lines = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(lines);

    /* ── Floating data particles ── */
    const pCount = 800;
    const positions = new Float32Array(pCount * 3);
    for (let i = 0; i < pCount * 3; i++) {
      positions[i] = (Math.random() - 0.5) * 12;
    }
    const ptGeo = new THREE.BufferGeometry();
    ptGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const ptMat = new THREE.PointsMaterial({
      size: 0.025,
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.55,
    });
    const points = new THREE.Points(ptGeo, ptMat);
    scene.add(points);

    /* ── Animation loop ── */
    let frameId: number;
    const startTime = Date.now();

    const animate = () => {
      const t = (Date.now() - startTime) / 1000;

      outerMesh.rotation.x = t * 0.12;
      outerMesh.rotation.y = t * 0.2;

      midMesh.rotation.x = -t * 0.18;
      midMesh.rotation.z = t * 0.15;
      midMat.opacity = 0.2 + Math.sin(t * 2) * 0.1;

      coreMesh.rotation.y = t * 0.5;
      coreMesh.rotation.x = t * 0.35;
      coreMat.opacity = 0.5 + Math.sin(t * 3) * 0.3;

      lines.rotation.y = -t * 0.04;
      lines.rotation.x = t * 0.02;

      points.rotation.y = t * 0.05;
      points.rotation.x = t * 0.025;

      renderer.render(scene, camera);
      frameId = requestAnimationFrame(animate);
    };
    animate();

    const onResize = () => {
      if (!canvas) return;
      camera.aspect = canvas.clientWidth / canvas.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("resize", onResize);
      renderer.dispose();
    };
  }, []);

  /* ─── Progress & log ticker ─────────────────────────── */
  useEffect(() => {
    const progressTimer = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressTimer);
          return 100;
        }
        return Math.min(100, prev + Math.floor(Math.random() * 4) + 1);
      });
    }, 55);

    const logTimer = setInterval(() => {
      setLogIndex((p) => Math.min(p + 1, BOOT_LOGS.length - 1));
    }, 380);

    return () => {
      clearInterval(progressTimer);
      clearInterval(logTimer);
    };
  }, []);

  /* ─── Completion trigger ────────────────────────────── */
  useEffect(() => {
    if (progress >= 100) {
      const t1 = setTimeout(() => setPhase("ready"), 400);
      const t2 = setTimeout(() => {
        setPhase("exit");
        setTimeout(onComplete, 700);
      }, 2000);
      return () => {
        clearTimeout(t1);
        clearTimeout(t2);
      };
    }
  }, [progress, onComplete]);

  const handleSkip = useCallback(() => {
    setPhase("exit");
    setTimeout(onComplete, 300);
  }, [onComplete]);

  // ESC key handler
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleSkip();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleSkip]);

  // Matrix columns data
  const matrixColumns = useMemo(
    () =>
      Array.from({ length: 30 }, (_, i) => ({
        delay: Math.random() * 5,
        speed: 4 + Math.random() * 6,
        left: `${(i / 30) * 100}%`,
      })),
    []
  );

  // Network nodes data
  const networkNodes = useMemo(
    () =>
      Array.from({ length: 16 }, (_, i) => ({
        x: Math.random() * 90 + 5,
        y: Math.random() * 90 + 5,
        delay: Math.random() * 3,
      })),
    []
  );

  // 4 Core Subsystems Data for the interactive HUD grid
  const subsystems = [
    {
      name: "AI CLASSIFIER",
      detail: "CICIDS2017 RF (99.8%)",
      icon: <Cpu className="w-4 h-4 text-purple-400" />,
      threshold: 25,
    },
    {
      name: "NPCAP SNIFFER",
      detail: "Physical NIC Ingestion",
      icon: <Radio className="w-4 h-4 text-emerald-400" />,
      threshold: 50,
    },
    {
      name: "EVIDENCE LEDGER",
      detail: "SHA-256 Chain of Custody",
      icon: <FileCheck2 className="w-4 h-4 text-cyan-400" />,
      threshold: 75,
    },
    {
      name: "MITRE ATT&CK",
      detail: "Tactics & Matrix v14.1",
      icon: <Layers className="w-4 h-4 text-amber-400" />,
      threshold: 95,
    },
  ];

  return (
    <AnimatePresence>
      {phase !== "exit" && (
        <motion.div
          key="preloader-overlay"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 1.05 }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="fixed inset-0 z-[9999] flex items-center justify-center bg-[#070b14] overflow-hidden select-none"
        >
          {/* Layer 1: Ambient background cyber mesh grid */}
          <div
            className="absolute inset-0 pointer-events-none opacity-20"
            style={{
              backgroundImage:
                "linear-gradient(rgba(111, 61, 255, 0.25) 1px, transparent 1px), linear-gradient(90deg, rgba(111, 61, 255, 0.25) 1px, transparent 1px)",
              backgroundSize: "44px 44px",
            }}
          />

          {/* Layer 2: Matrix code rain streams */}
          <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-30">
            {mounted && matrixColumns.map((col, i) => (
              <MatrixColumn key={i} {...col} />
            ))}
          </div>

          {/* Layer 3: Scanning horizontal laser beam */}
          <motion.div
            className="absolute left-0 right-0 h-[1.5px] pointer-events-none z-20"
            style={{
              background: "linear-gradient(90deg, transparent, #BFE9FF 30%, #6F3DFF 70%, transparent)",
              boxShadow: "0 0 25px 6px rgba(191,233,255,0.4), 0 0 40px 10px rgba(111,61,255,0.25)",
            }}
            animate={{ top: ["0%", "100%"] }}
            transition={{ duration: 3.5, repeat: Infinity, ease: "linear" }}
          />

          {/* Layer 4: Ambient glow orbs */}
          <div className="absolute top-1/4 left-1/5 w-[500px] h-[500px] rounded-full bg-[#6F3DFF]/[0.15] blur-[150px] pointer-events-none" />
          <div className="absolute bottom-1/4 right-1/5 w-[400px] h-[400px] rounded-full bg-[#BFE9FF]/[0.10] blur-[120px] pointer-events-none" />

          {/* Layer 5: Network connection nodes */}
          <div className="absolute inset-0 pointer-events-none">
            {mounted && networkNodes.map((node, i) => (
              <NetworkNode key={i} {...node} />
            ))}
          </div>

          {/* Layer 6: Three.js Canvas */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <canvas
              ref={canvasRef}
              className="w-[600px] h-[600px] md:w-[780px] md:h-[780px] opacity-80"
            />
          </div>

          {/* Corner HUD Elements */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.7 }}
            transition={{ delay: 0.4 }}
            className="absolute top-6 left-6 z-20 font-mono text-[9px] text-[#BFE9FF]/70 space-y-1"
          >
            <div>SYS.KERNEL :: v2.4.0-STABLE</div>
            <div>STATUS: AUTONOMOUS DEFENSE ACTIVE</div>
            <HexScanner />
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.7 }}
            transition={{ delay: 0.5 }}
            className="absolute top-6 right-6 z-20 font-mono text-[9px] text-[#BFE9FF]/70 text-right space-y-1"
          >
            <div>NODE: SENTINEL-PRIMARY</div>
            <div>TLS 1.3 · ZERO-TRUST ENCLAVE</div>
            <div className="flex items-center gap-1.5 justify-end">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-emerald-300">LINK: NOMINAL</span>
            </div>
          </motion.div>

          {/* ══════════════════════════════════════════════════════
              CENTRAL ENHANCED HOLOGRAPHIC CYBER HUD CARD
          ══════════════════════════════════════════════════════ */}
          <AnimatePresence>
            {showHud && (
              <motion.div
                initial={{ opacity: 0, y: 25, scale: 0.94 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.92, y: -15 }}
                transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
                className="relative z-30 w-full max-w-[460px] mx-4"
              >
                {/* Exterior Neon Glow Ring */}
                <div className="absolute -inset-1 rounded-3xl bg-gradient-to-r from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] opacity-35 blur-xl pointer-events-none" />

                {/* Main Card Container */}
                <div
                  className="rounded-3xl p-6 sm:p-8 flex flex-col items-center text-center relative overflow-hidden backdrop-blur-2xl border"
                  style={{
                    background:
                      "linear-gradient(155deg, rgba(111,61,255,0.18) 0%, rgba(10,16,35,0.92) 40%, rgba(6,11,26,0.98) 100%)",
                    boxShadow:
                      "0 20px 60px -10px rgba(0,0,0,0.8), 0 0 50px rgba(111,61,255,0.25), inset 0 1px 1px rgba(255,255,255,0.15)",
                    borderColor: "rgba(111,61,255,0.45)",
                  }}
                >
                  {/* Rotating Gradient Border Beam */}
                  <motion.div
                    className="absolute inset-0 rounded-3xl pointer-events-none"
                    style={{
                      background:
                        "linear-gradient(90deg, transparent 10%, rgba(191,233,255,0.5) 45%, rgba(111,61,255,0.7) 65%, transparent 90%)",
                      backgroundSize: "200% 100%",
                    }}
                    animate={{ backgroundPosition: ["0% 50%", "200% 50%"] }}
                    transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                  />

                  {/* High-Tech Tactical Corner Brackets */}
                  <div className="absolute top-0 left-0 w-6 h-6 border-t-2 border-l-2 border-[#BFE9FF] rounded-tl-2xl pointer-events-none" />
                  <div className="absolute top-0 right-0 w-6 h-6 border-t-2 border-r-2 border-[#6F3DFF] rounded-tr-2xl pointer-events-none" />
                  <div className="absolute bottom-0 left-0 w-6 h-6 border-b-2 border-l-2 border-[#6F3DFF] rounded-bl-2xl pointer-events-none" />
                  <div className="absolute bottom-0 right-0 w-6 h-6 border-b-2 border-r-2 border-[#BFE9FF] rounded-br-2xl pointer-events-none" />

                  {/* ── 1. Animated Holographic Shield Core ── */}
                  <div className="relative w-20 h-20 flex items-center justify-center mb-3">
                    {/* Concentric radar pulse rings */}
                    <motion.div
                      className="absolute inset-0 rounded-full border border-[#BFE9FF]/30"
                      animate={{ scale: [1, 1.45, 1], opacity: [0.8, 0, 0.8] }}
                      transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
                    />
                    <motion.div
                      className="absolute -inset-2 rounded-full border border-[#6F3DFF]/30"
                      animate={{ scale: [1, 1.25, 1], opacity: [0.6, 0.1, 0.6] }}
                      transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 0.4 }}
                    />

                    {/* Outer rotating dashed ring */}
                    <motion.div
                      className="absolute inset-0 rounded-full border-2 border-dashed border-[#6F3DFF]/60"
                      animate={{ rotate: 360 }}
                      transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
                    />

                    {/* Inner counter-rotating ring with neon tick */}
                    <motion.div
                      className="absolute inset-2 rounded-full border border-t-2 border-t-[#BFE9FF] border-r-[#6F3DFF] border-b-transparent border-l-transparent"
                      animate={{ rotate: -360 }}
                      transition={{ duration: 5, repeat: Infinity, ease: "linear" }}
                    />

                    {/* Glowing Core Shield */}
                    <motion.div
                      className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] flex items-center justify-center text-white shadow-xl shadow-[#6F3DFF]/50 border border-white/40 relative z-10"
                      animate={{ scale: [1, 1.05, 1] }}
                      transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                    >
                      <Shield className="w-6 h-6 text-white" />
                    </motion.div>
                  </div>

                  {/* ── 2. Brand Identity & Waveform ── */}
                  <div className="relative z-10 mb-1">
                    <div className="flex items-center justify-center gap-2">
                      {/* Left spectrum bars */}
                      <div className="flex items-center gap-0.5 h-4">
                        {[0.4, 0.8, 1, 0.6].map((h, i) => (
                          <motion.span
                            key={i}
                            className="w-0.5 rounded-full bg-[#6F3DFF]"
                            animate={{ height: ["3px", `${h * 14}px`, "3px"] }}
                            transition={{ duration: 0.7 + i * 0.1, repeat: Infinity, ease: "easeInOut", delay: i * 0.08 }}
                          />
                        ))}
                      </div>

                      <h1 className="text-2xl sm:text-3xl font-black tracking-tight font-mono text-white flex items-center">
                        <span>CYBER</span>
                        <span
                          className="text-[#BFE9FF] mx-0.5"
                          style={{
                            textShadow: "0 0 20px rgba(191,233,255,0.9), 0 0 35px rgba(111,61,255,0.6)",
                          }}
                        >
                          SENTINEL
                        </span>
                        <span className="text-[#6F3DFF]">-X</span>
                      </h1>

                      {/* Right spectrum bars */}
                      <div className="flex items-center gap-0.5 h-4">
                        {[0.6, 1, 0.8, 0.4].map((h, i) => (
                          <motion.span
                            key={i}
                            className="w-0.5 rounded-full bg-[#BFE9FF]"
                            animate={{ height: ["3px", `${h * 14}px`, "3px"] }}
                            transition={{ duration: 0.7 + i * 0.1, repeat: Infinity, ease: "easeInOut", delay: i * 0.08 }}
                          />
                        ))}
                      </div>
                    </div>

                    <p className="text-[10px] text-slate-400 font-mono tracking-[0.22em] mt-1 uppercase">
                      AI Threat Detection & Evidence Platform
                    </p>
                  </div>

                  {/* Live Security Enclave Badge */}
                  <div className="flex items-center gap-2 px-3 py-1 rounded-full border border-purple-500/30 bg-[#6F3DFF]/20 my-3 relative z-10">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                    </span>
                    <span className="text-[9px] font-mono font-bold text-[#BFE9FF] tracking-wider uppercase">
                      QUANTUM ENGINE · {phase === "ready" ? "DECRYPTED" : "INITIALIZING"}
                    </span>
                  </div>

                  {/* ── 3. Interactive 4-Pillar Subsystems Grid ── */}
                  <div className="grid grid-cols-2 gap-2 w-full my-3 relative z-10">
                    {subsystems.map((sub) => {
                      const isOnline = progress >= sub.threshold;
                      return (
                        <div
                          key={sub.name}
                          className={cn(
                            "p-2.5 rounded-xl border text-left transition-all duration-300 relative overflow-hidden backdrop-blur-md",
                            isOnline
                              ? "bg-[#6F3DFF]/20 border-[#6F3DFF]/60 shadow-md shadow-[#6F3DFF]/25"
                              : "bg-slate-900/60 border-slate-700/40 text-slate-500"
                          )}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs">{sub.icon}</span>
                            <span
                              className={cn(
                                "text-[8px] font-mono font-bold px-1.5 py-0.2 rounded-full",
                                isOnline
                                  ? "bg-emerald-500/25 text-emerald-300 border border-emerald-500/40"
                                  : "bg-slate-800 text-slate-500"
                              )}
                            >
                              {isOnline ? "ONLINE" : "STANDBY"}
                            </span>
                          </div>
                          <div className="text-[10px] font-bold text-white font-mono leading-tight">{sub.name}</div>
                          <div className="text-[8px] text-slate-400 font-mono mt-0.5">{sub.detail}</div>
                        </div>
                      );
                    })}
                  </div>

                  {/* ── 4. Glowing Progress Capsule & Ticker ── */}
                  <div className="w-full space-y-2 mt-2 relative z-10">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-400 text-[11px] flex items-center gap-1.5">
                        <motion.span
                          className="w-1.5 h-1.5 rounded-full bg-[#BFE9FF]"
                          animate={{ opacity: [1, 0.3, 1] }}
                          transition={{ duration: 1, repeat: Infinity }}
                        />
                        {phase === "ready" ? "ALL SUBSYSTEMS NOMINAL" : "SYNCING THREAT TELEMETRY"}
                      </span>
                      <span
                        className="font-black text-[#BFE9FF] tabular-nums text-sm font-mono"
                        style={{ textShadow: "0 0 16px rgba(191,233,255,0.95)" }}
                      >
                        {progress}%
                      </span>
                    </div>

                    {/* Progress Track */}
                    <div
                      className="h-2.5 w-full rounded-full overflow-hidden border border-[#6F3DFF]/50 p-[1.5px] relative"
                      style={{ background: "rgba(10,15,30,0.8)" }}
                    >
                      <motion.div
                        className="h-full rounded-full relative"
                        style={{
                          width: `${progress}%`,
                          background: "linear-gradient(90deg, #6F3DFF 0%, #855bff 50%, #BFE9FF 100%)",
                          boxShadow: "0 0 20px rgba(111,61,255,0.9), 0 0 35px rgba(191,233,255,0.6)",
                        }}
                        transition={{ ease: "easeOut", duration: 0.12 }}
                      >
                        {/* Shimmer light beam */}
                        <motion.div
                          className="absolute inset-0 rounded-full"
                          style={{
                            background: "linear-gradient(90deg, transparent 20%, rgba(255,255,255,0.8) 50%, transparent 80%)",
                            backgroundSize: "200% 100%",
                          }}
                          animate={{ backgroundPosition: ["100% 0", "-100% 0"] }}
                          transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                        />
                      </motion.div>
                    </div>
                  </div>

                  {/* ── 5. High-Tech Terminal Window ── */}
                  <div
                    className="w-full mt-4 rounded-xl text-left font-mono text-[10px] border border-slate-700/60 overflow-hidden relative z-10"
                    style={{ background: "rgba(3,6,15,0.85)" }}
                  >
                    {/* Terminal Header */}
                    <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-800 bg-slate-950/70">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-rose-500/80" />
                        <span className="w-2 h-2 rounded-full bg-amber-500/80" />
                        <span className="w-2 h-2 rounded-full bg-emerald-500/80" />
                        <span className="text-[9px] text-slate-400 font-mono ml-2">kernel_boot.log</span>
                      </div>
                      <span className="text-[9px] font-mono text-cyan-400/60">LIVE</span>
                    </div>

                    {/* Log Entries */}
                    <div className="p-2.5 space-y-1 max-h-[85px] overflow-hidden text-[9px]">
                      {BOOT_LOGS.slice(0, logIndex + 1).map((log, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: -6 }}
                          animate={{ opacity: i === logIndex ? 1 : 0.45, x: 0 }}
                          transition={{ duration: 0.2 }}
                          className="flex items-center gap-1.5"
                        >
                          <span className="shrink-0">{log.icon}</span>
                          <span className={i === logIndex ? "text-cyan-200 font-semibold" : "text-slate-400"}>
                            {log.text}
                          </span>
                        </motion.div>
                      ))}
                      <span className="inline-block w-1.5 h-3 bg-cyan-400 ml-5 animate-pulse" />
                    </div>
                  </div>

                  {/* ── 6. Ready State Launch Button or Skip ── */}
                  <div className="w-full mt-4 relative z-10">
                    <AnimatePresence>
                      {phase === "ready" ? (
                        <motion.button
                          key="launch-btn"
                          initial={{ opacity: 0, scale: 0.9, y: 10 }}
                          animate={{ opacity: 1, scale: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.9 }}
                          onClick={() => {
                            setPhase("exit");
                            setTimeout(onComplete, 300);
                          }}
                          className="w-full py-3 rounded-2xl bg-gradient-to-r from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] text-white font-mono font-bold text-xs flex items-center justify-center gap-2 shadow-xl shadow-[#6F3DFF]/50 hover:scale-[1.02] active:scale-[0.98] transition-all border border-white/30"
                        >
                          <Sparkles className="w-4 h-4 text-white animate-spin" />
                          <span>ENTER SOC PLATFORM</span>
                          <ArrowRight className="w-4 h-4" />
                        </motion.button>
                      ) : (
                        <motion.button
                          key="skip-btn"
                          onClick={handleSkip}
                          className="text-[10px] font-mono text-slate-500 hover:text-cyan-300 transition-colors uppercase tracking-[0.2em] px-4 py-1.5 rounded-full border border-slate-700/50 hover:border-cyan-500/40 bg-slate-900/40"
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                        >
                          [ ESC · SKIP SEQUENCE ⏭ ]
                        </motion.button>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Bottom SHA-256 integrity check status */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.4 }}
            transition={{ delay: 0.8 }}
            className="absolute bottom-6 right-6 z-20 font-mono text-[8px] text-cyan-500/50"
          >
            <HexScanner /> · SHA-256 INTEGRITY VERIFIED
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

"use client";
import React, { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import * as THREE from "three";

const BOOT_LOGS = [
  "> INITIALIZING WEBGL THREAT INTELLIGENCE ENGINE v2.4...",
  "> LOADING ML CLASSIFIER (RANDOM FOREST · 96.4% F1)...",
  "> CONNECTING MITRE ATT&CK MATRIX v14.1 CACHE...",
  "> CALIBRATING SHA-256 TAMPER-EVIDENT LEDGER NODES...",
  "> VALIDATING CRYPTOGRAPHIC EVIDENCE INTEGRITY...",
  "> CYBERSENTINEL-X CORE OPERATIONAL. DECRYPTING PORTAL...",
];

export function CyberPreloader({ onComplete }: { onComplete: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [progress, setProgress] = useState(0);
  const [logIndex, setLogIndex] = useState(0);
  const [phase, setPhase] = useState<"boot" | "ready" | "exit">("boot");

  /* ─── Three.js Scene ─────────────────────────────────── */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Scene
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
      50,
      canvas.clientWidth / canvas.clientHeight,
      0.1,
      1000
    );
    camera.position.z = 6;

    const renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
    });
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    /* ── Outer holographic icosahedron ── */
    const outerGeo = new THREE.IcosahedronGeometry(2.2, 1);
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x0ea5e9,
      wireframe: true,
      transparent: true,
      opacity: 0.25,
    });
    const outerMesh = new THREE.Mesh(outerGeo, outerMat);
    scene.add(outerMesh);

    /* ── Mid-layer dodecahedron ── */
    const midGeo = new THREE.DodecahedronGeometry(1.5, 0);
    const midMat = new THREE.MeshBasicMaterial({
      color: 0x6366f1,
      wireframe: true,
      transparent: true,
      opacity: 0.4,
    });
    const midMesh = new THREE.Mesh(midGeo, midMat);
    scene.add(midMesh);

    /* ── Inner octahedron core ── */
    const coreGeo = new THREE.OctahedronGeometry(0.9, 0);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x22d3ee,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreMesh);

    /* ── Torus rings ── */
    const ring1 = new THREE.Mesh(
      new THREE.TorusGeometry(2.8, 0.012, 16, 120),
      new THREE.MeshBasicMaterial({
        color: 0x06b6d4,
        transparent: true,
        opacity: 0.5,
      })
    );
    ring1.rotation.x = Math.PI / 3;
    scene.add(ring1);

    const ring2 = new THREE.Mesh(
      new THREE.TorusGeometry(2.4, 0.008, 16, 100),
      new THREE.MeshBasicMaterial({
        color: 0x818cf8,
        transparent: true,
        opacity: 0.35,
      })
    );
    ring2.rotation.y = Math.PI / 4;
    scene.add(ring2);

    const ring3 = new THREE.Mesh(
      new THREE.TorusGeometry(3.2, 0.006, 16, 140),
      new THREE.MeshBasicMaterial({
        color: 0x0ea5e9,
        transparent: true,
        opacity: 0.2,
      })
    );
    ring3.rotation.z = Math.PI / 5;
    scene.add(ring3);

    /* ── Floating data particles ── */
    const count = 600;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count * 3; i++) {
      positions[i] = (Math.random() - 0.5) * 9;
    }
    const ptGeo = new THREE.BufferGeometry();
    ptGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const ptMat = new THREE.PointsMaterial({
      size: 0.028,
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.7,
    });
    const points = new THREE.Points(ptGeo, ptMat);
    scene.add(points);

    /* ── Animation loop ── */
    let frameId: number;
    const startTime = Date.now();

    const animate = () => {
      const t = (Date.now() - startTime) / 1000;

      outerMesh.rotation.x = t * 0.15;
      outerMesh.rotation.y = t * 0.25;

      midMesh.rotation.x = -t * 0.22;
      midMesh.rotation.z = t * 0.18;

      coreMesh.rotation.y = t * 0.6;
      coreMesh.rotation.x = t * 0.4;

      ring1.rotation.z = t * 0.12;
      ring2.rotation.x = t * 0.17;
      ring3.rotation.y = t * 0.08;

      points.rotation.y = t * 0.06;
      points.rotation.x = t * 0.03;

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
        return Math.min(100, prev + Math.floor(Math.random() * 5) + 2);
      });
    }, 45);

    const logTimer = setInterval(() => {
      setLogIndex((p) => Math.min(p + 1, BOOT_LOGS.length - 1));
    }, 480);

    return () => {
      clearInterval(progressTimer);
      clearInterval(logTimer);
    };
  }, []);

  /* ─── Completion trigger ────────────────────────────── */
  useEffect(() => {
    if (progress >= 100) {
      const t1 = setTimeout(() => setPhase("ready"), 300);
      const t2 = setTimeout(() => {
        setPhase("exit");
        setTimeout(onComplete, 700);
      }, 1600);
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

  return (
    <AnimatePresence>
      {phase !== "exit" && (
        <motion.div
          key="preloader"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 1.08, filter: "blur(20px)" }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="fixed inset-0 z-[9999] flex flex-col items-center justify-center overflow-hidden select-none"
          style={{ background: "#0a0f1e" }}
        >
          {/* Deep space gradient */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_#0d1b40_0%,_#050a14_70%)]" />

          {/* Subtle cyber grid */}
          <div
            className="absolute inset-0 opacity-[0.07]"
            style={{
              backgroundImage:
                "linear-gradient(#06b6d4 1px, transparent 1px), linear-gradient(90deg, #06b6d4 1px, transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />

          {/* Ambient glow orbs */}
          <div className="absolute top-1/4 left-1/4 w-80 h-80 rounded-full bg-cyan-500/10 blur-[100px] animate-pulse pointer-events-none" />
          <div className="absolute bottom-1/4 right-1/4 w-64 h-64 rounded-full bg-indigo-600/10 blur-[80px] pointer-events-none" />

          {/* Three.js Canvas - FULL background */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <canvas
              ref={canvasRef}
              className="w-[520px] h-[520px] md:w-[680px] md:h-[680px] opacity-90"
            />
          </div>

          {/* ── Central HUD Card ── */}
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ delay: 0.15, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            className="relative z-10 w-full max-w-sm mx-4"
          >
            {/* Glassmorphism card */}
            <div
              className="rounded-2xl border border-cyan-500/20 p-7 flex flex-col items-center text-center backdrop-blur-xl"
              style={{
                background:
                  "linear-gradient(135deg, rgba(6,182,212,0.07) 0%, rgba(10,15,30,0.85) 100%)",
                boxShadow:
                  "0 0 60px rgba(6,182,212,0.12), inset 0 1px 0 rgba(255,255,255,0.05)",
              }}
            >
              {/* Live telemetry badge */}
              <div className="flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-950/50 mb-5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-[10px] font-mono font-bold text-cyan-400 tracking-[0.2em]">
                  WEBGL ENCLAVE · ENCRYPTED
                </span>
              </div>

              {/* Brand */}
              <h1 className="text-3xl font-black tracking-tight font-mono text-white">
                CYBER
                <span
                  className="text-transparent"
                  style={{
                    WebkitTextStroke: "1px #06b6d4",
                    textShadow: "0 0 20px rgba(6,182,212,0.8)",
                  }}
                >
                  SENTINEL
                </span>
                <span className="text-cyan-400">-X</span>
              </h1>
              <p className="text-[11px] text-slate-400 font-mono mt-1 tracking-wider">
                AI-DRIVEN THREAT DETECTION & FORENSICS
              </p>

              {/* Progress Bar */}
              <div className="w-full mt-7 space-y-2">
                <div className="flex justify-between text-[11px] font-mono">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                    {phase === "ready" ? "CORE READY" : "INITIALIZING"}
                  </span>
                  <span
                    className="font-black text-cyan-400 tabular-nums"
                    style={{ textShadow: "0 0 10px rgba(6,182,212,0.8)" }}
                  >
                    {progress}%
                  </span>
                </div>

                {/* Track */}
                <div
                  className="h-2 w-full rounded-full overflow-hidden border border-cyan-900/60"
                  style={{ background: "rgba(6,182,212,0.08)" }}
                >
                  <motion.div
                    className="h-full rounded-full"
                    style={{
                      width: `${progress}%`,
                      background:
                        "linear-gradient(90deg, #0ea5e9, #818cf8, #06b6d4)",
                      boxShadow: "0 0 16px rgba(6,182,212,0.9)",
                    }}
                    transition={{ ease: "easeOut", duration: 0.15 }}
                  />
                </div>
              </div>

              {/* Terminal log */}
              <div
                className="w-full mt-5 p-3.5 rounded-xl text-left font-mono text-[10px] border border-slate-700/60"
                style={{ background: "rgba(0,0,0,0.6)" }}
              >
                <AnimatePresence mode="wait">
                  <motion.div
                    key={logIndex}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="flex items-center gap-2 text-slate-200"
                  >
                    <span className="text-cyan-400 shrink-0">›</span>
                    <span className="truncate">{BOOT_LOGS[logIndex]}</span>
                    <span className="shrink-0 w-1.5 h-3.5 bg-cyan-400 animate-pulse ml-auto" />
                  </motion.div>
                </AnimatePresence>
              </div>

              {/* Ready state banner */}
              <AnimatePresence>
                {phase === "ready" && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="mt-4 w-full py-2.5 rounded-xl text-center font-mono text-xs font-bold text-emerald-300 border border-emerald-500/30"
                    style={{ background: "rgba(16,185,129,0.08)", textShadow: "0 0 12px rgba(16,185,129,0.8)" }}
                  >
                    ✓ SOC PORTAL DECRYPTED — LAUNCHING
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Skip */}
              <button
                onClick={handleSkip}
                className="mt-5 text-[10px] font-mono text-slate-500 hover:text-cyan-400 transition-colors uppercase tracking-[0.15em]"
              >
                [ Press ESC to skip ]
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

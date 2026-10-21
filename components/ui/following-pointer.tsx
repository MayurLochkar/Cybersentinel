"use client";
import React, { useEffect, useRef, useState } from "react";
import { motion, useMotionValue, useSpring } from "framer-motion";
import { cn } from "@/lib/utils";

export const FollowerPointerCard = ({
  children,
  className,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string | React.ReactNode;
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [isInteractive, setIsInteractive] = useState(false);
  const [isTouchDevice, setIsTouchDevice] = useState(false);
  const [isClicking, setIsClicking] = useState(false);

  const rawX = useMotionValue(-200);
  const rawY = useMotionValue(-200);

  // Spring trailing for the outer ring (more lag = more trail)
  const springX = useSpring(rawX, { stiffness: 180, damping: 22 });
  const springY = useSpring(rawY, { stiffness: 180, damping: 22 });

  // Faster spring for the center dot
  const dotX = useSpring(rawX, { stiffness: 600, damping: 30 });
  const dotY = useSpring(rawY, { stiffness: 600, damping: 30 });

  useEffect(() => {
    if (typeof window !== "undefined") {
      if ("ontouchstart" in window || navigator.maxTouchPoints > 0) {
        setIsTouchDevice(true);
        return;
      }
    }

    const updateMouse = (e: MouseEvent) => {
      rawX.set(e.clientX);
      rawY.set(e.clientY);
      if (!isVisible) setIsVisible(true);

      const target = e.target as HTMLElement | null;
      if (!target) return;
      const interactive =
        target.tagName === "BUTTON" ||
        target.tagName === "A" ||
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        !!target.closest("button") ||
        !!target.closest("a") ||
        target.getAttribute("role") === "button" ||
        target.classList.contains("cursor-pointer");
      setIsInteractive(interactive);
    };

    const onMouseLeave = () => setIsVisible(false);
    const onMouseDown = () => setIsClicking(true);
    const onMouseUp = () => setIsClicking(false);

    window.addEventListener("mousemove", updateMouse, { passive: true });
    document.body.addEventListener("mouseleave", onMouseLeave);
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("mouseup", onMouseUp);

    return () => {
      window.removeEventListener("mousemove", updateMouse);
      document.body.removeEventListener("mouseleave", onMouseLeave);
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [isVisible, rawX, rawY]);

  return (
    <div className={cn("relative min-h-screen", className)}>
      {/* Hide OS cursor only on non-touch */}
      {!isTouchDevice && (
        <style>{`body { cursor: none !important; } a, button, [role="button"], input, textarea, select { cursor: none !important; }`}</style>
      )}

      {/* ── Center Dot (fast) ── */}
      {!isTouchDevice && isVisible && (
        <motion.div
          className="fixed top-0 left-0 z-[9999] pointer-events-none"
          style={{ x: dotX, y: dotY }}
        >
          <motion.div
            className="rounded-full bg-cyan-400"
            style={{
              width: isInteractive ? 6 : 4,
              height: isInteractive ? 6 : 4,
              marginTop: isInteractive ? -3 : -2,
              marginLeft: isInteractive ? -3 : -2,
              boxShadow: "0 0 10px rgba(6,182,212,0.9)",
            }}
            animate={{
              scale: isClicking ? 0.5 : isInteractive ? 1.4 : 1,
              backgroundColor: isInteractive ? "#3b82f6" : "#22d3ee",
            }}
            transition={{ duration: 0.15 }}
          />
        </motion.div>
      )}

      {/* ── Trailing Ring (slow spring) ── */}
      {!isTouchDevice && isVisible && (
        <motion.div
          className="fixed top-0 left-0 z-[9998] pointer-events-none"
          style={{ x: springX, y: springY }}
        >
          <motion.div
            className="rounded-full border"
            animate={{
              width: isClicking ? 16 : isInteractive ? 36 : 26,
              height: isClicking ? 16 : isInteractive ? 36 : 26,
              marginTop: isClicking ? -8 : isInteractive ? -18 : -13,
              marginLeft: isClicking ? -8 : isInteractive ? -18 : -13,
              borderColor: isInteractive
                ? "rgba(59,130,246,0.7)"
                : "rgba(6,182,212,0.5)",
              backgroundColor: isInteractive
                ? "rgba(59,130,246,0.08)"
                : "rgba(0,0,0,0)",
              boxShadow: isInteractive
                ? "0 0 18px rgba(59,130,246,0.4)"
                : "0 0 10px rgba(6,182,212,0.25)",
            }}
            transition={{ duration: 0.2 }}
          />

          {/* Analyst label badge */}
          <motion.div
            className="absolute top-6 left-6 pointer-events-none"
            animate={{ opacity: isInteractive ? 0 : 0.9 }}
            transition={{ duration: 0.2 }}
          >
            <div className="px-2.5 py-0.5 bg-slate-900/90 text-cyan-300 font-mono text-[9px] font-bold rounded-full shadow-lg border border-cyan-500/40 whitespace-nowrap flex items-center gap-1.5 backdrop-blur-md">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>{title || "SOC ANALYST (L3)"}</span>
            </div>
          </motion.div>

          {/* Interactive hint */}
          <motion.div
            className="absolute top-6 left-6 pointer-events-none"
            animate={{ opacity: isInteractive ? 0.9 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="px-2.5 py-0.5 bg-blue-900/90 text-blue-200 font-mono text-[9px] font-bold rounded-full border border-blue-400/40 whitespace-nowrap flex items-center gap-1 backdrop-blur-md">
              <span>⬤</span>
              <span>CLICK TO INTERACT</span>
            </div>
          </motion.div>
        </motion.div>
      )}

      {children}
    </div>
  );
};

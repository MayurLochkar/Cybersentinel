"use client";
import React, { useEffect, useState } from "react";
import { motion, useMotionValue, useSpring } from "framer-motion";

export function CyberCursor() {
  const [mounted, setMounted] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const [isClicking, setIsClicking] = useState(false);
  const [coords, setCoords] = useState({ x: 0, y: 0 });
  const [isVisible, setIsVisible] = useState(false);

  const rawX = useMotionValue(-100);
  const rawY = useMotionValue(-100);

  // Smooth springs for high-tech tactical trailing reticle
  const springConfig = { damping: 28, stiffness: 350, mass: 0.5 };
  const smoothX = useSpring(rawX, springConfig);
  const smoothY = useSpring(rawY, springConfig);

  useEffect(() => {
    setMounted(true);

    // Disable on touch devices
    if (window.matchMedia("(pointer: coarse)").matches) {
      return;
    }

    const handleMouseMove = (e: MouseEvent) => {
      rawX.set(e.clientX);
      rawY.set(e.clientY);
      setCoords({ x: e.clientX, y: e.clientY });
      if (!isVisible) setIsVisible(true);

      // Check if hovering over an interactive element
      const target = e.target as HTMLElement | null;
      if (target) {
        const interactive = target.closest(
          "button, a, input, select, textarea, [role='button'], .cursor-pointer, .interactive-card"
        );
        setIsHovered(!!interactive);
      }
    };

    const handleMouseDown = () => setIsClicking(true);
    const handleMouseUp = () => setIsClicking(false);
    const handleMouseLeave = () => setIsVisible(false);
    const handleMouseEnter = () => setIsVisible(true);

    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("mousedown", handleMouseDown);
    window.addEventListener("mouseup", handleMouseUp);
    document.addEventListener("mouseleave", handleMouseLeave);
    document.addEventListener("mouseenter", handleMouseEnter);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mousedown", handleMouseDown);
      window.removeEventListener("mouseup", handleMouseUp);
      document.removeEventListener("mouseleave", handleMouseLeave);
      document.removeEventListener("mouseenter", handleMouseEnter);
    };
  }, [rawX, rawY, isVisible]);

  if (!mounted || !isVisible) return null;

  return (
    <div className="fixed inset-0 pointer-events-none z-[999999] overflow-hidden select-none">
      {/* 1. Fast Sharp Center Crosshair Dot */}
      <motion.div
        className="fixed top-0 left-0 w-2 h-2 rounded-full pointer-events-none z-50 -translate-x-1/2 -translate-y-1/2"
        style={{
          x: rawX,
          y: rawY,
          backgroundColor: isHovered ? "#BFE9FF" : "#6F3DFF",
          boxShadow: isHovered
            ? "0 0 10px 2px #BFE9FF, 0 0 20px #6F3DFF"
            : "0 0 8px 1px #6F3DFF",
        }}
      />

      {/* 2. Tactical Rotating Target Bracket Rings */}
      <motion.div
        className="fixed top-0 left-0 pointer-events-none -translate-x-1/2 -translate-y-1/2 flex items-center justify-center"
        style={{
          x: smoothX,
          y: smoothY,
          width: isHovered ? 44 : 26,
          height: isHovered ? 44 : 26,
        }}
        transition={{ type: "spring", damping: 25, stiffness: 300 }}
      >
        {/* Outer Ring */}
        <motion.div
          className="absolute inset-0 rounded-full border border-dashed"
          style={{
            borderColor: isHovered ? "rgba(191, 233, 255, 0.75)" : "rgba(111, 61, 255, 0.45)",
          }}
          animate={{ rotate: 360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
        />

        {/* 4 Corner Crosshair Marks */}
        <div
          className="absolute -top-1 w-1.5 h-0.5"
          style={{ backgroundColor: isHovered ? "#BFE9FF" : "#6F3DFF" }}
        />
        <div
          className="absolute -bottom-1 w-1.5 h-0.5"
          style={{ backgroundColor: isHovered ? "#BFE9FF" : "#6F3DFF" }}
        />
        <div
          className="absolute -left-1 w-0.5 h-1.5"
          style={{ backgroundColor: isHovered ? "#BFE9FF" : "#6F3DFF" }}
        />
        <div
          className="absolute -right-1 w-0.5 h-1.5"
          style={{ backgroundColor: isHovered ? "#BFE9FF" : "#6F3DFF" }}
        />

        {/* Active Click Ping Ring */}
        {isClicking && (
          <motion.div
            className="absolute inset-0 rounded-full border-2 border-[#BFE9FF]"
            initial={{ scale: 0.8, opacity: 1 }}
            animate={{ scale: 2.2, opacity: 0 }}
            transition={{ duration: 0.35, ease: "easeOut" }}
          />
        )}
      </motion.div>

      {/* 3. Tactical HUD Coordinates Tag (Monospace Cyber Ticker) */}
      {isHovered && (
        <motion.div
          className="fixed top-0 left-0 pointer-events-none px-2 py-0.5 rounded bg-slate-950/85 text-[8px] font-mono font-bold text-[#BFE9FF] border border-[#6F3DFF]/40 tracking-wider shadow-lg backdrop-blur-sm"
          style={{
            x: smoothX,
            y: smoothY,
            translateX: 24,
            translateY: -20,
          }}
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0 }}
        >
          SOC://LOCKED [{coords.x},{coords.y}]
        </motion.div>
      )}
    </div>
  );
}

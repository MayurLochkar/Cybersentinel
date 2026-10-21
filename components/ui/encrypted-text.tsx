"use client";
import React, { useEffect, useState, useCallback, useRef } from "react";
import { cn } from "@/lib/utils";

const CYBER_CHARS =
  "01アイウエオカキクケコ0123456789!@#$%^&*_+-=[]{}~ΞΨΩ█▓▒░▄▀■□ABCXYZ";

interface EncryptedTextProps {
  text: string;
  className?: string;
  interval?: number;
  highlightClass?: string;
  autoReplay?: boolean;
  startDelay?: number;
}

export function EncryptedText({
  text,
  className = "",
  interval = 22,
  highlightClass = "text-cyan-500 font-mono drop-shadow-[0_0_12px_rgba(6,182,212,0.9)]",
  autoReplay = false,
  startDelay = 0,
}: EncryptedTextProps) {
  const [chars, setChars] = useState<
    { char: string; state: "scrambled" | "decrypted" | "locked" }[]
  >(() =>
    text.split("").map((c) => ({ char: c, state: "scrambled" }))
  );
  const [isRunning, setIsRunning] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const delayRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const runDecrypt = useCallback(() => {
    if (isRunning) return;
    setIsRunning(true);

    // Reset to full scramble
    setChars(
      text.split("").map((c) => ({
        char:
          c === " "
            ? " "
            : CYBER_CHARS[Math.floor(Math.random() * CYBER_CHARS.length)],
        state: c === " " ? "decrypted" : "scrambled",
      }))
    );

    let revealIdx = 0;
    let scrambleIter = 0;

    timerRef.current = setInterval(() => {
      scrambleIter++;

      setChars(
        text.split("").map((char, i) => {
          if (char === " ") return { char: " ", state: "decrypted" };
          if (i < revealIdx) return { char, state: "decrypted" };
          // Randomly update scrambled chars for dynamic feel
          const rnd = CYBER_CHARS[Math.floor(Math.random() * CYBER_CHARS.length)];
          return { char: rnd, state: "scrambled" };
        })
      );

      // Every 3 iterations, lock one more character
      if (scrambleIter % 3 === 0) {
        revealIdx++;
      }

      if (revealIdx >= text.length) {
        if (timerRef.current) clearInterval(timerRef.current);
        setChars(text.split("").map((c) => ({ char: c, state: "locked" })));
        setIsRunning(false);
      }
    }, interval);
  }, [text, interval, isRunning]);

  // Initial trigger with optional delay
  useEffect(() => {
    delayRef.current = setTimeout(() => {
      runDecrypt();
    }, startDelay);
    return () => {
      if (delayRef.current) clearTimeout(delayRef.current);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-replay
  useEffect(() => {
    if (!autoReplay) return;
    const replayInterval = setInterval(() => {
      runDecrypt();
    }, 10000);
    return () => clearInterval(replayInterval);
  }, [autoReplay, runDecrypt]);

  return (
    <span
      onMouseEnter={runDecrypt}
      className={cn("inline-block cursor-crosshair select-none", className)}
      title="Hover to decrypt"
    >
      {chars.map((item, i) => (
        <span
          key={i}
          className={cn(
            "inline-block transition-all",
            item.state === "scrambled"
              ? [highlightClass, "scale-110 opacity-80"].join(" ")
              : item.state === "decrypted"
              ? "opacity-100 scale-100"
              : "opacity-100 scale-100"
          )}
          style={{
            transitionDuration: item.state === "locked" ? "150ms" : "50ms",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {item.char}
        </span>
      ))}
      {isRunning && (
        <span className="inline-block w-[2px] h-[0.85em] ml-0.5 bg-cyan-400 animate-pulse align-middle shadow-[0_0_8px_#06b6d4]" />
      )}
    </span>
  );
}

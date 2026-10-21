"use client";
import React, { useState } from "react";
import Image from "next/image";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { ArrowUpRight, ShieldAlert, Eye } from "lucide-react";

export type CardType = {
  title: string;
  src: string;
  category?: string;
  severity?: string;
};

export const Card = React.memo(
  ({
    card,
    index,
    hovered,
    setHovered,
    onSelect,
    className,
  }: {
    card: CardType;
    index: number;
    hovered: number | null;
    setHovered: React.Dispatch<React.SetStateAction<number | null>>;
    onSelect?: (card: CardType) => void;
    className?: string;
  }) => {
    const isHovered = hovered === index;
    const isBlurred = hovered !== null && hovered !== index;

    return (
      <motion.div
        onMouseEnter={() => setHovered(index)}
        onMouseLeave={() => setHovered(null)}
        onClick={() => onSelect && onSelect(card)}
        whileHover={{ scale: 1.03, y: -4 }}
        transition={{ type: "spring", stiffness: 300, damping: 22 }}
        className={cn(
          "rounded-3xl relative overflow-hidden h-72 md:h-96 cursor-pointer select-none group",
          "border border-white/80 shadow-lg",
          isBlurred ? "opacity-50 scale-[0.97] blur-[1px]" : "opacity-100",
          isHovered
            ? "ring-2 ring-cyan-400/60 shadow-[0_16px_48px_rgba(14,165,233,0.25)]"
            : "neu-flat",
          className
        )}
        style={{ transition: "opacity 0.35s ease, filter 0.35s ease, scale 0.35s ease" }}
      >
        {/* Background image */}
        <Image
          src={card.src}
          alt={card.title}
          fill
          sizes="(max-width: 768px) 100vw, 33vw"
          className={cn(
            "object-cover absolute inset-0 transition-transform duration-700 ease-out",
            isHovered ? "scale-110" : "scale-100"
          )}
        />

        {/* Gradient overlay */}
        <div
          className={cn(
            "absolute inset-0 transition-all duration-500",
            isHovered
              ? "bg-gradient-to-t from-slate-950/98 via-slate-900/60 to-cyan-900/20"
              : "bg-gradient-to-t from-slate-950/90 via-slate-950/40 to-transparent"
          )}
        />

        {/* Animated scan line on hover */}
        <AnimatePresence>
          {isHovered && (
            <motion.div
              className="absolute left-0 right-0 h-px bg-cyan-400/70 pointer-events-none"
              style={{ boxShadow: "0 0 8px 1px rgba(6,182,212,0.6)" }}
              initial={{ top: "0%", opacity: 0 }}
              animate={{ top: ["0%", "100%"], opacity: [0, 1, 1, 0] }}
              transition={{ duration: 1.5, ease: "linear", repeat: Infinity }}
            />
          )}
        </AnimatePresence>

        {/* Card content */}
        <div
          className={cn(
            "absolute inset-0 flex flex-col justify-end p-5 transition-all duration-300",
            isHovered ? "pb-6" : "pb-5"
          )}
        >
          {/* Badges */}
          {card.category && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: isHovered ? 1 : 0.8, y: 0 }}
              className="flex items-center gap-2 mb-2"
            >
              <span className="text-[9px] font-mono font-bold tracking-widest uppercase px-2.5 py-0.5 rounded-full bg-cyan-500/30 text-cyan-200 border border-cyan-400/40 backdrop-blur-md">
                {card.category}
              </span>
              {card.severity && (
                <span
                  className={cn(
                    "text-[9px] font-mono font-black tracking-widest uppercase px-2 py-0.5 rounded-full backdrop-blur-md",
                    card.severity === "CRITICAL"
                      ? "bg-red-500/40 text-red-200 border border-red-500/50"
                      : card.severity === "HIGH"
                      ? "bg-orange-500/40 text-orange-200 border border-orange-500/50"
                      : "bg-amber-500/40 text-amber-200 border border-amber-500/50"
                  )}
                >
                  {card.severity}
                </span>
              )}
            </motion.div>
          )}

          <div className="flex items-end justify-between gap-2">
            <div className="text-base md:text-lg font-extrabold text-white leading-snug drop-shadow-md">
              {card.title}
            </div>
            <motion.div
              animate={{
                scale: isHovered ? 1.1 : 1,
                backgroundColor: isHovered ? "rgb(6,182,212)" : "rgba(255,255,255,0.2)",
              }}
              className="w-8 h-8 shrink-0 rounded-full backdrop-blur-md flex items-center justify-center text-white shadow-md transition-colors"
            >
              <ArrowUpRight className="w-4 h-4" />
            </motion.div>
          </div>

          {/* Hover detail panel */}
          <AnimatePresence>
            {isHovered && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.25, ease: "easeOut" }}
                className="mt-3 overflow-hidden"
              >
                <div className="flex items-center gap-2 text-[10px] font-mono text-cyan-300/80">
                  <Eye className="w-3 h-3" />
                  <span>Click to investigate in SOC Console →</span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    );
  }
);

Card.displayName = "Card";

/* ─── Marquee wrapper ──────────────────────────────────────── */
function MarqueeRow({
  cards,
  hovered,
  setHovered,
  onSelect,
  reverse = false,
}: {
  cards: CardType[];
  hovered: number | null;
  setHovered: React.Dispatch<React.SetStateAction<number | null>>;
  onSelect?: (card: CardType) => void;
  reverse?: boolean;
}) {
  // Duplicate for seamless loop
  const doubled = [...cards, ...cards];

  return (
    <div className="relative overflow-hidden w-full" style={{ maskImage: "linear-gradient(to right, transparent 0%, black 8%, black 92%, transparent 100%)" }}>
      <motion.div
        className="flex gap-5 w-max"
        animate={{ x: reverse ? ["0%", "-50%"] : ["-50%", "0%"] }}
        transition={{
          duration: 38,
          ease: "linear",
          repeat: Infinity,
        }}
        style={{ willChange: "transform" }}
        // Pause on hover of any child
        whileHover={{ animationPlayState: "paused" }}
      >
        {doubled.map((card, idx) => (
          <Card
            key={`${card.title}-${idx}`}
            card={card}
            index={idx % cards.length}
            hovered={hovered}
            setHovered={setHovered}
            onSelect={onSelect}
            className="w-80 md:w-96 shrink-0"
          />
        ))}
      </motion.div>
    </div>
  );
}

/* ─── FocusCards ──────────────────────────────────────────── */
export function FocusCards({
  cards,
  onSelect,
  useMarquee = false,
}: {
  cards: CardType[];
  onSelect?: (card: CardType) => void;
  useMarquee?: boolean;
}) {
  const [hovered, setHovered] = useState<number | null>(null);

  if (useMarquee) {
    const mid = Math.ceil(cards.length / 2);
    const row1 = cards.slice(0, mid);
    const row2 = cards.slice(mid);

    return (
      <div className="w-full space-y-5 py-4">
        {/* Row 1 — left to right */}
        <MarqueeRow
          cards={row1.length >= 2 ? row1 : cards}
          hovered={hovered}
          setHovered={setHovered}
          onSelect={onSelect}
        />
        {/* Row 2 — right to left */}
        <MarqueeRow
          cards={row2.length >= 2 ? row2 : [...cards].reverse()}
          hovered={hovered}
          setHovered={setHovered}
          onSelect={onSelect}
          reverse
        />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto w-full px-4">
      {cards.map((card, index) => (
        <Card
          key={card.title}
          card={card}
          index={index}
          hovered={hovered}
          setHovered={setHovered}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

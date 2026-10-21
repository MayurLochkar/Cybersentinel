"use client";
import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, X, Shield, Cpu, Lock, Database, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import { AnimatePresence, motion } from "framer-motion";
import Image from "next/image";

interface CarouselProps {
  items: React.ReactNode[];
  initialScroll?: number;
}

type CardType = {
  src: string;
  title: string;
  category: string;
  content: React.ReactNode;
};

export const CarouselContext = createContext<{
  onCardClose: (index: number) => void;
  currentIndex: number;
}>({
  onCardClose: () => {},
  currentIndex: 0,
});

export const Carousel = ({ items, initialScroll = 0 }: CarouselProps) => {
  const carouselRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(true);
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (carouselRef.current) {
      carouselRef.current.scrollLeft = initialScroll;
      checkScrollability();
    }
  }, [initialScroll]);

  const checkScrollability = () => {
    if (carouselRef.current) {
      const { scrollLeft, scrollWidth, clientWidth } = carouselRef.current;
      setCanScrollLeft(scrollLeft > 0);
      setCanScrollRight(scrollLeft < scrollWidth - clientWidth - 1);
    }
  };

  const scrollLeft = () => {
    if (carouselRef.current) {
      carouselRef.current.scrollBy({ left: -320, behavior: "smooth" });
    }
  };

  const scrollRight = () => {
    if (carouselRef.current) {
      carouselRef.current.scrollBy({ left: 320, behavior: "smooth" });
    }
  };

  const handleCardClose = (index: number) => {
    if (carouselRef.current) {
      const cardWidth = isMobile() ? 230 : 384;
      const gap = isMobile() ? 16 : 32;
      const scrollPosition = (cardWidth + gap) * (index + 1);
      carouselRef.current.scrollTo({
        left: scrollPosition,
        behavior: "smooth",
      });
      setCurrentIndex(index);
    }
  };

  const isMobile = () => {
    return typeof window !== "undefined" && window.innerWidth < 768;
  };

  return (
    <CarouselContext.Provider value={{ onCardClose: handleCardClose, currentIndex }}>
      <div className="relative w-full">
        <div
          className="flex w-full overflow-x-scroll overscroll-x-auto py-10 md:py-14 scroll-smooth [scrollbar-width:none]"
          ref={carouselRef}
          onScroll={checkScrollability}
        >
          <div className={cn("absolute right-0 z-[1000] h-auto w-[5%] overflow-hidden bg-gradient-to-l")} />
          <div className={cn("flex flex-row justify-start gap-6 pl-4 max-w-7xl mx-auto")}>
            {items.map((item, index) => (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{
                  opacity: 1,
                  y: 0,
                  transition: {
                    duration: 0.5,
                    delay: 0.1 * index,
                    ease: "easeOut",
                  },
                }}
                key={"card" + index}
                className="last:pr-[5%] md:last:pr-[15%] rounded-3xl"
              >
                {item}
              </motion.div>
            ))}
          </div>
        </div>
        <div className="flex justify-end gap-3 mr-10">
          <button
            className="relative z-40 h-10 w-10 rounded-full neu-flat flex items-center justify-center disabled:opacity-40 hover:bg-white transition-all active:scale-95"
            onClick={scrollLeft}
            disabled={!canScrollLeft}
            aria-label="Previous slide"
          >
            <ArrowLeft className="h-5 w-5 text-slate-700" />
          </button>
          <button
            className="relative z-40 h-10 w-10 rounded-full neu-flat flex items-center justify-center disabled:opacity-40 hover:bg-white transition-all active:scale-95"
            onClick={scrollRight}
            disabled={!canScrollRight}
            aria-label="Next slide"
          >
            <ArrowRight className="h-5 w-5 text-slate-700" />
          </button>
        </div>
      </div>
    </CarouselContext.Provider>
  );
};

export const AppleCard = ({
  card,
  index,
  layout = false,
}: {
  card: CardType;
  index: number;
  layout?: boolean;
}) => {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const { onCardClose } = useContext(CarouselContext);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        handleClose();
      }
    }

    if (open) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "auto";
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    onCardClose(index);
  };

  return (
    <>
      <AnimatePresence>
        {open && (
          <div className="fixed inset-0 h-screen z-50 overflow-auto flex items-center justify-center">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="bg-black/60 backdrop-blur-md h-full w-full fixed inset-0"
              onClick={handleClose}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              ref={containerRef}
              className="max-w-3xl w-full mx-4 my-10 bg-[#eef3f8] h-fit max-h-[85vh] z-[60] p-6 md:p-10 rounded-3xl neu-flat font-sans relative overflow-y-auto border border-white/80"
            >
              <button
                className="sticky top-0 float-right ml-auto bg-white/80 neu-flat-sm text-slate-800 rounded-full p-2 h-9 w-9 flex items-center justify-center"
                onClick={handleClose}
                aria-label="Close details"
              >
                <X className="h-5 w-5" />
              </button>
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-600">
                {card.category}
              </span>
              <h3 className="text-2xl md:text-3xl font-extrabold text-slate-800 mt-2 mb-6">
                {card.title}
              </h3>
              <div className="py-2">{card.content}</div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
      <motion.button
        onClick={handleOpen}
        className="rounded-3xl neu-flat neu-flat-hover bg-[#eef3f8] h-80 w-64 md:h-[26rem] md:w-80 overflow-hidden flex flex-col items-start justify-between relative z-10 p-6 border border-white/80 text-left group"
      >
        <div className="z-10">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 bg-cyan-100/60 px-2.5 py-1 rounded-full">
            {card.category}
          </span>
          <p className="text-slate-800 text-lg md:text-xl font-bold max-w-xs text-left [text-wrap:balance] mt-3 group-hover:text-cyan-600 transition-colors">
            {card.title}
          </p>
        </div>
        <div className="relative w-full h-44 mt-auto rounded-2xl overflow-hidden neu-pressed-sm">
          <Image
            src={card.src}
            alt={card.title}
            fill
            sizes="320px"
            className="object-cover group-hover:scale-105 transition-transform duration-500"
          />
        </div>
      </motion.button>
    </>
  );
};

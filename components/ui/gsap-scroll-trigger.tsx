"use client";

import React, { useEffect } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

// Ensure GSAP ScrollTrigger is registered safely on client
if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

/**
 * Global GSAP ScrollTrigger Provider
 * Detects elements with `data-gsap` attributes across the page and attaches
 * high-performance hardware-accelerated ScrollTrigger animations.
 */
export function GsapScrollTriggerProvider({ children }: { children?: React.ReactNode }) {
  useEffect(() => {
    // Only run on client
    if (typeof window === "undefined") return;

    const ctx = gsap.context(() => {
      // 1. Reveal-Up Elements: Smooth fade-up with cubic easing
      const revealElements = document.querySelectorAll('[data-gsap="reveal-up"]');
      revealElements.forEach((el) => {
        gsap.fromTo(
          el,
          { opacity: 0, y: 36 },
          {
            opacity: 1,
            y: 0,
            duration: 0.85,
            ease: "power3.out",
            scrollTrigger: {
              trigger: el,
              start: "top 88%",
              toggleActions: "play none none reverse",
            },
          }
        );
      });

      // 2. Staggered Grid/Cards: Children animate in cascade
      const staggerContainers = document.querySelectorAll('[data-gsap="stagger-cards"]');
      staggerContainers.forEach((container) => {
        const children = container.children;
        if (children.length > 0) {
          gsap.fromTo(
            children,
            { opacity: 0, y: 30, scale: 0.96 },
            {
              opacity: 1,
              y: 0,
              scale: 1,
              duration: 0.75,
              stagger: 0.12,
              ease: "power2.out",
              scrollTrigger: {
                trigger: container,
                start: "top 85%",
                toggleActions: "play none none reverse",
              },
            }
          );
        }
      });

      // 3. Scale-In Sections
      const scaleElements = document.querySelectorAll('[data-gsap="scale-in"]');
      scaleElements.forEach((el) => {
        gsap.fromTo(
          el,
          { opacity: 0, scale: 0.92 },
          {
            opacity: 1,
            scale: 1,
            duration: 0.9,
            ease: "back.out(1.4)",
            scrollTrigger: {
              trigger: el,
              start: "top 85%",
              toggleActions: "play none none reverse",
            },
          }
        );
      });

      // 4. Parallax Floating Elements (Scrubbed with scroll velocity)
      const parallaxElements = document.querySelectorAll('[data-gsap="parallax"]');
      parallaxElements.forEach((el) => {
        gsap.to(el, {
          y: -40,
          ease: "none",
          scrollTrigger: {
            trigger: el,
            start: "top bottom",
            end: "bottom top",
            scrub: 1.2,
          },
        });
      });

      // 5. Scroll Progress Bar
      const progressBar = document.getElementById("gsap-scroll-progress");
      if (progressBar) {
        gsap.to(progressBar, {
          scaleX: 1,
          ease: "none",
          scrollTrigger: {
            trigger: document.body,
            start: "top top",
            end: "bottom bottom",
            scrub: 0.3,
          },
        });
      }

      // Refresh ScrollTrigger to calculate exact dimensions
      ScrollTrigger.refresh();
    });

    return () => {
      ctx.revert();
    };
  }, []);

  return (
    <>
      {/* Top Cybernetic Scroll Progress Bar */}
      <div className="fixed top-0 left-0 right-0 h-1 z-[9999] pointer-events-none origin-left overflow-hidden bg-transparent">
        <div
          id="gsap-scroll-progress"
          className="h-full w-full bg-gradient-to-r from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] shadow-[0_0_12px_#6F3DFF]"
          style={{ transform: "scaleX(0)", transformOrigin: "0% 50%" }}
        />
      </div>
      {children}
    </>
  );
}

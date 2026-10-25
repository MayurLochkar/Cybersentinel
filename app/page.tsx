"use client";
import React, { useState } from "react";
import dynamic from "next/dynamic";
import { Hero } from "@/components/hero";
import { FocusCards } from "@/components/ui/focus-cards";
import { FeaturesSection } from "@/components/features-section";
const CyberPreloader = dynamic(
  () => import("@/components/ui/preloader").then((mod) => mod.CyberPreloader),
  { ssr: false }
);
import { FloatingDock } from "@/components/ui/floating-dock";
import { Carousel, AppleCard } from "@/components/ui/apple-cards-carousel";
import { FollowerPointerCard } from "@/components/ui/following-pointer";
import { AuthModal } from "@/components/auth/auth-modal";
import { Footer } from "@/components/footer";
import { DashboardLayout } from "@/components/dashboard/dashboard-layout";
import {
  ShieldAlert,
  Terminal,
  Activity,
  Cpu,
  Lock,
  Database,
  Layers,
  ArrowRight,
  ShieldCheck,
  FileCheck2,
  BrainCircuit,
  BarChart3,
  User,
  LayoutDashboard,
  Bell,
  Sparkles,
  Flame,
  Radio,
  ExternalLink,
} from "lucide-react";
import confetti from "canvas-confetti";
import { cn } from "@/lib/utils";

export default function Home() {
  const [inDashboard, setInDashboard] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authInitialTab, setAuthInitialTab] = useState<"signin" | "signup" | "recovery">("signin");
  const [preloaderActive, setPreloaderActive] = useState(true);

  // Focus Cards Data (Threat scenarios matching Aceternity component + Marquee)
  const focusCardsData = [
    {
      title: "Credential Stuffing Vector",
      category: "Brute Force",
      severity: "HIGH",
      src: "https://images.unsplash.com/photo-1563986768609-322da13575f3?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Distributed Flood Reflection",
      category: "DDoS Impact",
      severity: "CRITICAL",
      src: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Zero-Day Exploit Trap",
      category: "Web Reconnaissance",
      severity: "HIGH",
      src: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Rogue API Gateway Infiltration",
      category: "Cloud Lateral Movement",
      severity: "CRITICAL",
      src: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Ransomware Cryptographic Lock",
      category: "Host Endpoint",
      severity: "HIGH",
      src: "https://images.unsplash.com/photo-1504639725590-34d0984388bd?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Stealth SYN Probe Sweep",
      category: "Port Scan",
      severity: "MEDIUM",
      src: "https://images.unsplash.com/photo-1510511459019-5dda7724fd87?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Adversary-In-The-Middle Pivot",
      category: "Network Interception",
      severity: "CRITICAL",
      src: "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop",
    },
    {
      title: "Lateral Movement via WMI",
      category: "Persistence",
      severity: "HIGH",
      src: "https://images.unsplash.com/photo-1592609931041-40265b692757?q=80&w=1200&auto=format&fit=crop",
    },
  ];

  // Apple Cards Carousel items showcasing CyberSentinel-X Core Capabilities
  const appleCardsData = [
    {
      category: "Detection Engine",
      title: "Multivariate Random Forest ML Classifier",
      src: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=800&auto=format&fit=crop",
      content: (
        <div className="space-y-4 text-slate-700 text-xs leading-relaxed">
          <p>
            Trained on millions of simulated and real-world network packet flows (CICIDS, NSL-KDD), our ensemble Random Forest model achieves a <strong>96.4% Accuracy</strong> and <strong>95.3% F1-Score</strong> with a negligible 3.2% false positive rate.
          </p>
          <div className="p-4 bg-white/80 rounded-xl neu-pressed-sm space-y-2">
            <span className="font-bold text-slate-900 block uppercase font-mono text-[11px]">Features Analysed:</span>
            <ul className="list-disc list-inside space-y-1 font-mono text-[11px] text-slate-600">
              <li>Inter-arrival packet delta variance</li>
              <li>TCP Flag distribution & SYN/ACK sequence ratios</li>
              <li>Payload entropy & byte distribution frequency</li>
            </ul>
          </div>
        </div>
      ),
    },
    {
      category: "Autonomous Forensics",
      title: "AI Co-Pilot & MITRE ATT&CK Correlation",
      src: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=800&auto=format&fit=crop",
      content: (
        <div className="space-y-4 text-slate-700 text-xs leading-relaxed">
          <p>
            When an anomaly exceeds safety thresholds, CyberSentinel-X triggers autonomous forensic agents. The system synthesizes incident telemetry, cross-references adversary techniques in the MITRE ATT&CK Matrix, and outputs plain-language explanations for SOC tier-1 and tier-2 analysts.
          </p>
          <div className="p-4 bg-white/80 rounded-xl neu-pressed-sm">
            <span className="font-bold text-slate-900 block font-mono text-[11px]">Standardized Output:</span>
            <p className="mt-1 text-slate-600">
              Direct linkage to Technique T1110 (Brute Force), T1498 (Network DoS), and T1046 (Network Service Discovery).
            </p>
          </div>
        </div>
      ),
    },
    {
      category: "Tamper-Evident Ledger",
      title: "Cryptographic Evidence Integrity Verification",
      src: "https://images.unsplash.com/photo-1563986768609-322da13575f3?q=80&w=800&auto=format&fit=crop",
      content: (
        <div className="space-y-4 text-slate-700 text-xs leading-relaxed">
          <p>
            Digital evidence admissibility in legal and regulatory proceedings requires unimpeachable chain of custody. CyberSentinel-X calculates an immediate SHA-256 hash digest upon log extraction and immutably pins it into a verifiable ledger.
          </p>
          <div className="p-4 bg-white/80 rounded-xl neu-pressed-sm font-mono text-[11px]">
            <div className="text-emerald-700 font-bold">100% Cryptographic Match Guarantee</div>
            <div className="text-slate-500 mt-1">Status: VERIFIED at each investigative access point.</div>
          </div>
        </div>
      ),
    },
    {
      category: "Risk Quantification",
      title: "Dynamic Multi-Vector Risk Scoring",
      src: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=800&auto=format&fit=crop",
      content: (
        <div className="space-y-4 text-slate-700 text-xs leading-relaxed">
          <p>
            Rather than relying on raw CVSS scores alone, CyberSentinel-X computes a contextual risk score (0-100) taking into account model confidence, attack frequency, targeted asset criticality, threat intelligence reputation, and forensic evidence certainty.
          </p>
        </div>
      ),
    },
  ];

  // Floating dock navigation items (Requirement 7)
  const floatingDockItems = [
    {
      title: "SOC Dashboard",
      icon: <LayoutDashboard className="w-full h-full text-blue-600" />,
      onClick: () => setInDashboard(true),
    },
    {
      title: "Alerts Matrix",
      icon: <Bell className="w-full h-full text-orange-600" />,
      onClick: () => setInDashboard(true),
    },
    {
      title: "AI Investigation",
      icon: <BrainCircuit className="w-full h-full text-indigo-600" />,
      onClick: () => setInDashboard(true),
    },
    {
      title: "Evidence Ledger",
      icon: <FileCheck2 className="w-full h-full text-emerald-600" />,
      onClick: () => setInDashboard(true),
    },
    {
      title: "Model Metrics",
      icon: <Cpu className="w-full h-full text-cyan-600" />,
      onClick: () => setInDashboard(true),
    },
    {
      title: "Analyst Sign In",
      icon: <User className="w-full h-full text-slate-700" />,
      onClick: () => {
        setAuthInitialTab("signin");
        setAuthModalOpen(true);
      },
    },
  ];

  const handleOpenAuth = (tab: "signin" | "signup" | "recovery") => {
    setAuthInitialTab(tab);
    setAuthModalOpen(true);
  };

  const handleLoginSuccess = () => {
    confetti({
      particleCount: 80,
      spread: 70,
      origin: { y: 0.6 },
    });
    setInDashboard(true);
  };

  // If user navigated into the SOC Dashboard application
  if (inDashboard) {
    return <DashboardLayout onReturnToHome={() => setInDashboard(false)} />;
  }

  // Showcase Landing Portal
  return (
    <>
      {/* Three.js WebGL Holographic Preloader */}
      {preloaderActive && (
        <CyberPreloader onComplete={() => setPreloaderActive(false)} />
      )}

      {/* Non-Blocking Fixed Cursor with Target Crosshair */}
      <FollowerPointerCard title="Security Analyst (You)">
        <div className="min-h-screen bg-[#eef3f8] selection:bg-[#BFE9FF] selection:text-[#6F3DFF] relative">
          {/* Hero Section with Floating Curved Capsule Navbar */}
          <section id="hero" className="relative">
            <Hero
              onLaunchDashboard={() => setInDashboard(true)}
              onOpenAuth={handleOpenAuth}
            />
          </section>

          {/* Quick Launch Banner Bar */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 -mt-6 mb-16">
            <div className="neu-flat rounded-3xl p-6 md:p-8 border border-[#B7B7B7]/40 flex flex-col md:flex-row items-center justify-between gap-6 bg-gradient-to-r from-[#6F3DFF]/8 via-white to-[#BFE9FF]/15 shadow-xl">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-[#6F3DFF] via-[#855bff] to-[#BFE9FF] text-white flex items-center justify-center shadow-md shadow-[#6F3DFF]/25 shrink-0 border border-white/50">
                  <Sparkles className="w-6 h-6 text-white" />
                </div>
                <div>
                  <div className="text-xs font-bold text-[#6F3DFF] font-mono">LIVE PROTOTYPE CONSOLE</div>
                  <div className="text-sm md:text-base font-extrabold text-slate-900 mt-0.5">
                    Ready to test all 11 SOC investigation modules with realistic threat telemetry?
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <button
                  onClick={() => setInDashboard(true)}
                  className="px-6 py-3 rounded-full bg-gradient-to-r from-[#6F3DFF] to-[#4e19d9] hover:from-[#7c4dff] hover:to-[#5c24e6] text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-[#6F3DFF]/30 active:scale-95 transition-all border border-[#BFE9FF]/30"
                >
                  <span>Enter SOC Console</span>
                  <ArrowRight className="w-4 h-4 text-[#BFE9FF]" />
                </button>
              </div>
            </div>
          </div>

          {/* Middle Features Showcase Section */}
          <FeaturesSection onLaunchConsole={() => setInDashboard(true)} />

          {/* Threat Scenarios with Infinite Marquee Effect (User's specific request) */}
          <section id="scenarios" className="py-20 overflow-hidden relative">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-10 text-center">
              <span className="px-3.5 py-1.5 rounded-full neu-flat-sm text-[11px] font-bold text-[#6F3DFF] uppercase tracking-wider font-mono border border-[#B7B7B7]/40">
                Aceternity Focus Cards &bull; Infinite Marquee Stream
              </span>
              <h2 className="text-3xl md:text-5xl font-black text-slate-900 tracking-tight mt-3">
                Active Threat Scenarios Under Watch
              </h2>
              <p className="text-xs md:text-sm text-slate-500 mt-2 max-w-xl mx-auto">
                Hover across cards to pause the stream, isolate threat vectors, and inspect real-time classification.
              </p>
            </div>

            {/* FocusCards rendered with useMarquee={true} for infinite smooth scrolling */}
            <FocusCards
              cards={focusCardsData}
              useMarquee={true}
              onSelect={(card) => {
                setInDashboard(true);
              }}
            />
          </section>

          {/* Apple Cards Carousel Section */}
          <section id="modules" className="py-20 bg-slate-100/60 border-y border-slate-200/80">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex flex-col md:flex-row md:items-end justify-between mb-6">
                <div>
                  <span className="px-3.5 py-1.5 rounded-full neu-flat-sm text-[11px] font-bold text-[#6F3DFF] uppercase tracking-wider font-mono border border-[#B7B7B7]/40">
                    Enterprise Capabilities
                  </span>
                  <h2 className="text-3xl md:text-5xl font-black text-slate-900 tracking-tight mt-3">
                    Autonomous SOC Architecture
                  </h2>
                </div>
                <p className="text-xs text-slate-500 max-w-sm mt-2 md:mt-0">
                  Swipe through core components powering detection, forensic analysis, MITRE mapping, and cryptographic assurance.
                </p>
              </div>

              <Carousel
                items={appleCardsData.map((card, index) => (
                  <AppleCard key={card.title} card={card} index={index} />
                ))}
              />
            </div>
          </section>

          {/* Floating Dock Fixed Navigation */}
          <FloatingDock
            items={floatingDockItems}
            desktopClassName="fixed bottom-8 left-1/2 -translate-x-1/2 z-50 shadow-2xl"
            mobileClassName="fixed bottom-6 right-6 z-50"
          />

          {/* Neumorphic Auth Modal */}
          <AuthModal
            isOpen={authModalOpen}
            onClose={() => setAuthModalOpen(false)}
            initialTab={authInitialTab}
            onLoginSuccess={handleLoginSuccess}
          />

          {/* DevStudio Style Footer */}
          <Footer
            onOpenAuth={handleOpenAuth}
            onNavigate={(page) => setInDashboard(true)}
          />
        </div>
      </FollowerPointerCard>
    </>
  );
}

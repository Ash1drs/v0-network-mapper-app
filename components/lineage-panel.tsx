"use client";

import { useEffect, useState } from "react";
import {
  Globe,
  Server,
  Network,
  Building2,
  Crown,
  ArrowDown,
  Loader2,
  ShieldCheck,
  CircleHelp,
  Radar,
} from "lucide-react";
import type { Lineage, LineageHop, RdapResult } from "@/lib/origin-trace";
import { applyRdapToLineage } from "@/lib/origin-trace";

const LEVEL_ICON: Record<LineageHop["level"], typeof Globe> = {
  domain: Globe,
  ip: Server,
  asn: Network,
  org: Building2,
  parent: Crown,
};

const LEVEL_LABEL: Record<LineageHop["level"], string> = {
  domain: "Domain",
  ip: "IP Address",
  asn: "Autonomous System",
  org: "Network Operator",
  parent: "Ultimate Parent",
};

const SOURCE_STYLE: Record<LineageHop["source"], { label: string; className: string }> = {
  uploaded: { label: "Uploaded", className: "bg-primary/15 text-primary" },
  derived: { label: "Derived", className: "bg-chart-4/15 text-chart-4" },
  rdap: { label: "RDAP Live", className: "bg-chart-2/15 text-chart-2" },
};

const CONFIDENCE_STYLE: Record<LineageHop["confidence"], { icon: typeof ShieldCheck; className: string }> = {
  high: { icon: ShieldCheck, className: "text-chart-2" },
  medium: { icon: CircleHelp, className: "text-chart-4" },
  low: { icon: CircleHelp, className: "text-muted-foreground" },
};

interface LineagePanelProps {
  lineage: Lineage | null;
  onClose: () => void;
}

export function LineagePanel({ lineage: initialLineage, onClose }: LineagePanelProps) {
  const [lineage, setLineage] = useState<Lineage | null>(initialLineage);
  const [enriching, setEnriching] = useState(false);
  const [enriched, setEnriched] = useState(false);

  // Reset when a new node is traced
  useEffect(() => {
    setLineage(initialLineage);
    setEnriched(false);
    setEnriching(false);
  }, [initialLineage]);

  // Layer live RDAP data on top of the derived lineage for IP-rooted traces
  useEffect(() => {
    if (!initialLineage || initialLineage.root.kind !== "ip" || enriched) return;

    let cancelled = false;
    const run = async () => {
      setEnriching(true);
      try {
        const res = await fetch("/api/rdap", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ips: [initialLineage.root.value] }),
        });
        if (res.ok) {
          const data: { results: RdapResult[] } = await res.json();
          const rdap = data.results?.[0];
          if (rdap && !cancelled) {
            setLineage((prev) => (prev ? applyRdapToLineage(prev, rdap) : prev));
          }
        }
      } catch {
        // Keep the derived lineage if RDAP fails
      } finally {
        if (!cancelled) {
          setEnriching(false);
          setEnriched(true);
        }
      }
    };
    run();
    return () => {
      cancelled = true;
    };
  }, [initialLineage, enriched]);

  if (!lineage) return null;

  const OriginConfidence = CONFIDENCE_STYLE[lineage.originConfidence].icon;

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-0.5">
          <span className="text-xs uppercase tracking-wider text-muted-foreground">
            Origin Trace
          </span>
          <span className="font-mono text-sm text-foreground break-all">
            {lineage.root.value}
          </span>
        </div>
        <button
          onClick={onClose}
          className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground"
          aria-label="Close origin trace"
        >
          <span className="text-lg leading-none">&times;</span>
        </button>
      </div>

      {/* Origin summary card */}
      <div className="rounded-lg border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-center gap-2">
          <Crown className="h-4 w-4 text-primary" />
          <span className="text-xs uppercase tracking-wider text-primary">
            Ultimate Parent
          </span>
        </div>
        <p className="mt-1 text-lg font-semibold text-foreground text-balance">
          {lineage.origin}
        </p>
        <div className="mt-1 flex items-center gap-1.5">
          <OriginConfidence className={`h-3.5 w-3.5 ${CONFIDENCE_STYLE[lineage.originConfidence].className}`} />
          <span className="text-xs text-muted-foreground capitalize">
            {lineage.originConfidence} confidence
          </span>
          {enriching && (
            <span className="ml-auto flex items-center gap-1 text-xs text-chart-2">
              <Loader2 className="h-3 w-3 animate-spin" />
              RDAP lookup...
            </span>
          )}
        </div>
      </div>

      {/* Lineage chain */}
      <div className="flex flex-col">
        <div className="mb-2 flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground">
          <Radar className="h-3.5 w-3.5" />
          Lineage Chain
        </div>
        {lineage.hops.map((hop, i) => {
          const Icon = LEVEL_ICON[hop.level];
          const source = SOURCE_STYLE[hop.source];
          const isLast = i === lineage.hops.length - 1;
          return (
            <div key={`${hop.level}-${i}`} className="flex flex-col">
              <div
                className={`flex items-start gap-3 rounded-md border p-2.5 ${
                  hop.level === "parent"
                    ? "border-primary/40 bg-primary/5"
                    : "border-border bg-card"
                }`}
              >
                <div
                  className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${
                    hop.level === "parent" ? "bg-primary/20" : "bg-secondary"
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 ${
                      hop.level === "parent" ? "text-primary" : "text-muted-foreground"
                    }`}
                  />
                </div>
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      {LEVEL_LABEL[hop.level]}
                    </span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${source.className}`}
                    >
                      {source.label}
                    </span>
                  </div>
                  <span className="font-mono text-sm text-foreground break-all">
                    {hop.label}
                  </span>
                  {hop.sublabel && (
                    <span className="text-xs text-muted-foreground break-all">
                      {hop.sublabel}
                    </span>
                  )}
                  {hop.detail && (
                    <span className="text-xs text-muted-foreground/70">
                      {hop.detail}
                    </span>
                  )}
                </div>
              </div>
              {!isLast && (
                <div className="flex justify-start pl-[26px]">
                  <ArrowDown className="my-0.5 h-4 w-4 text-border" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      <p className="text-xs text-muted-foreground/70 leading-relaxed">
        Chain reads bottom-up: the observed artifact resolves through its
        network operator to the ultimate controlling organization. Derived hops
        use offline rollup rules; RDAP hops are authoritative registry data.
      </p>
    </div>
  );
}

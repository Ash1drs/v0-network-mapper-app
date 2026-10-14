"use client";

import { Filter, Sparkles, GitBranch, Waypoints, History, ShieldOff } from "lucide-react";
import type { GraphFilterState } from "@/app/page";
import {
  ENTITY_KIND_LABEL,
  MATCH_COLOR,
  ZONE_COLOR,
  ZONE_LABEL,
  ZONE_ORDER,
  feedColor,
  type EntityKind,
  type Zone,
} from "@/lib/network-types";
import {
  SIGNAL_COLOR,
  SIGNAL_DESC,
  SIGNAL_LABEL,
  SIGNAL_ORDER,
  type Signal,
} from "@/lib/signals";

export const SIGNAL_ICON: Record<Signal, typeof Sparkles> = {
  match: Sparkles,
  overlap: Waypoints,
  pivot: GitBranch,
  sequence: History,
};

interface GraphFiltersProps {
  feedOrder: string[];
  byKind: Record<EntityKind, number>;
  filters: GraphFilterState;
  onChange: (filters: GraphFilterState) => void;
  signalCountsMap: Record<Signal, number>;
  caHiddenCount: number;
  zoneCountsMap: Record<Zone, number>;
}

export function GraphFilters({
  feedOrder,
  byKind,
  filters,
  onChange,
  signalCountsMap,
  caHiddenCount,
  zoneCountsMap,
}: GraphFiltersProps) {
  const kinds = Object.keys(byKind) as EntityKind[];

  const toggleZone = (zone: Zone) => {
    const next = new Set(filters.zones);
    if (next.has(zone)) next.delete(zone);
    else next.add(zone);
    onChange({ ...filters, zones: next });
  };

  const toggleSignal = (sig: Signal) => {
    const next = new Set(filters.signals);
    if (next.has(sig)) next.delete(sig);
    else next.add(sig);
    onChange({ ...filters, signals: next });
  };

  const toggleKind = (kind: EntityKind) => {
    const next = new Set(filters.kinds);
    if (next.has(kind)) next.delete(kind);
    else next.add(kind);
    onChange({ ...filters, kinds: next });
  };

  const toggleFeed = (feed: string) => {
    const next = new Set(filters.feeds);
    if (next.has(feed)) next.delete(feed);
    else next.add(feed);
    onChange({ ...filters, feeds: next });
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold text-foreground">Filters</h2>
      </div>

      {/* Relationship signals — show only entities carrying the chosen signal(s) */}
      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-muted-foreground">
          Relationship signal {filters.signals.size > 1 ? "(any selected)" : ""}
        </span>
        <div className="flex flex-col gap-1">
          {SIGNAL_ORDER.map((sig) => {
            const active = filters.signals.has(sig);
            const color = SIGNAL_COLOR[sig];
            const Icon = SIGNAL_ICON[sig];
            return (
              <button
                key={sig}
                type="button"
                aria-pressed={active}
                onClick={() => toggleSignal(sig)}
                className="flex items-center gap-2.5 rounded-md border px-2.5 py-1.5 text-left transition-colors min-h-[44px]"
                style={{
                  borderColor: active ? color : "var(--border)",
                  backgroundColor: active ? color + "14" : "transparent",
                }}
              >
                <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} aria-hidden="true" />
                <span className="flex flex-1 flex-col overflow-hidden">
                  <span className="text-xs font-medium text-foreground">{SIGNAL_LABEL[sig]}</span>
                  <span className="truncate text-[11px] text-muted-foreground">{SIGNAL_DESC[sig]}</span>
                </span>
                <span
                  className="rounded-full px-1.5 py-0.5 text-xs font-mono font-bold"
                  style={{ backgroundColor: color + "22", color }}
                >
                  {signalCountsMap[sig]}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Certificate-authority noise */}
      <button
        type="button"
        role="switch"
        aria-checked={filters.showCA}
        onClick={() => onChange({ ...filters, showCA: !filters.showCA })}
        className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2 text-left transition-colors hover:bg-secondary/40 min-h-[44px]"
      >
        <span className="flex items-center gap-2">
          <ShieldOff className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="flex flex-col">
            <span className="text-xs font-medium text-foreground">
              {filters.showCA ? "Showing CA hosts" : "CA hosts hidden"}
            </span>
            <span className="text-[11px] text-muted-foreground">
              OCSP / CRL / issuer noise, unless matched
            </span>
          </span>
        </span>
        <span className="rounded-full bg-secondary px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
          {caHiddenCount}
        </span>
      </button>

      {/* Environment zones */}
      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-muted-foreground">Environment (color = zone)</span>
        <div className="flex flex-col gap-1">
          {ZONE_ORDER.map((zone) => {
            const active = filters.zones.has(zone);
            const color = ZONE_COLOR[zone];
            return (
              <button
                key={zone}
                type="button"
                onClick={() => toggleZone(zone)}
                className={`flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-left transition-colors min-h-[36px] ${
                  active ? "border-border bg-secondary/50" : "border-border/50 opacity-50"
                }`}
              >
                <span className="h-3 w-3 rounded-full shrink-0" style={{ backgroundColor: color }} />
                <span className="flex-1 truncate text-xs font-medium text-foreground">
                  {ZONE_LABEL[zone]}
                </span>
                <span className="text-xs font-mono text-muted-foreground">{zoneCountsMap[zone]}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Entity kinds */}
      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-muted-foreground">Entity types</span>
        <div className="flex flex-wrap gap-1.5">
          {kinds.map((kind) => {
            const active = filters.kinds.has(kind);
            return (
              <button
                key={kind}
                type="button"
                onClick={() => toggleKind(kind)}
                className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors min-h-[36px] ${
                  active
                    ? "border-primary bg-primary/20 text-primary"
                    : "border-border bg-secondary/50 text-muted-foreground hover:text-foreground"
                }`}
              >
                {ENTITY_KIND_LABEL[kind]}
                <span className="ml-1 opacity-70">{byKind[kind]}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Feeds + color legend */}
      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-muted-foreground">
          Feeds (color = source)
        </span>
        <div className="flex flex-col gap-1">
          {feedOrder.map((feed, i) => {
            const active = filters.feeds.has(feed);
            const color = feedColor(i);
            return (
              <button
                key={feed}
                type="button"
                onClick={() => toggleFeed(feed)}
                className={`flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-left transition-colors min-h-[36px] ${
                  active ? "border-border bg-secondary/50" : "border-border/50 opacity-50"
                }`}
              >
                <span
                  className="h-3 w-3 rounded-full shrink-0"
                  style={{ backgroundColor: color }}
                />
                <span className="flex-1 truncate text-xs font-mono text-foreground">
                  {feed}
                </span>
              </button>
            );
          })}
          {/* Match legend row */}
          <div className="mt-1 flex items-center gap-2 px-2.5 py-1.5">
            <span
              className="h-3 w-3 rounded-full shrink-0 ring-2 ring-offset-1 ring-offset-background"
              style={{ backgroundColor: MATCH_COLOR, boxShadow: `0 0 0 1px ${MATCH_COLOR}` }}
            />
            <span className="text-xs text-muted-foreground">
              In multiple feeds (match)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

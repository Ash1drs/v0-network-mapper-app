"use client";

import { Filter, Sparkles, GitBranch } from "lucide-react";
import type { GraphFilterState } from "@/app/page";
import {
  ENTITY_KIND_LABEL,
  MATCH_COLOR,
  BRIDGE_COLOR,
  ZONE_COLOR,
  ZONE_LABEL,
  ZONE_ORDER,
  feedColor,
  type EntityKind,
  type Zone,
} from "@/lib/network-types";

interface GraphFiltersProps {
  feedOrder: string[];
  byKind: Record<EntityKind, number>;
  filters: GraphFilterState;
  onChange: (filters: GraphFilterState) => void;
  matchedCount: number;
  zoneCountsMap: Record<Zone, number>;
  pivotCount: number;
}

export function GraphFilters({
  feedOrder,
  byKind,
  filters,
  onChange,
  matchedCount,
  zoneCountsMap,
  pivotCount,
}: GraphFiltersProps) {
  const kinds = Object.keys(byKind) as EntityKind[];

  const toggleZone = (zone: Zone) => {
    const next = new Set(filters.zones);
    if (next.has(zone)) next.delete(zone);
    else next.add(zone);
    onChange({ ...filters, zones: next });
  };

  const setPivotsOnly = (value: boolean) => {
    onChange({ ...filters, pivotsOnly: value });
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

  const setMatchedOnly = (value: boolean) => {
    onChange({ ...filters, matchedOnly: value });
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold text-foreground">Filters</h2>
      </div>

      {/* Matched-only toggle */}
      <button
        type="button"
        onClick={() => setMatchedOnly(!filters.matchedOnly)}
        className="flex items-center justify-between rounded-md border px-3 py-2 transition-colors min-h-[44px]"
        style={{
          borderColor: filters.matchedOnly ? MATCH_COLOR : "var(--border)",
          backgroundColor: filters.matchedOnly ? MATCH_COLOR + "14" : "transparent",
        }}
      >
        <span className="flex items-center gap-2">
          <Sparkles
            className="h-3.5 w-3.5"
            style={{ color: filters.matchedOnly ? MATCH_COLOR : undefined }}
          />
          <span
            className="text-xs font-medium"
            style={{ color: filters.matchedOnly ? MATCH_COLOR : "var(--foreground)" }}
          >
            Cross-feed matches only
          </span>
        </span>
        <span
          className="rounded-full px-1.5 py-0.5 text-xs font-mono font-bold"
          style={{ backgroundColor: MATCH_COLOR + "22", color: MATCH_COLOR }}
        >
          {matchedCount}
        </span>
      </button>

      {/* Pivots-only toggle — nodes that bridge two environments */}
      <button
        type="button"
        onClick={() => setPivotsOnly(!filters.pivotsOnly)}
        className="flex items-center justify-between rounded-md border px-3 py-2 transition-colors min-h-[44px]"
        style={{
          borderColor: filters.pivotsOnly ? BRIDGE_COLOR : "var(--border)",
          backgroundColor: filters.pivotsOnly ? BRIDGE_COLOR + "14" : "transparent",
        }}
      >
        <span className="flex items-center gap-2">
          <GitBranch className="h-3.5 w-3.5" style={{ color: filters.pivotsOnly ? BRIDGE_COLOR : undefined }} />
          <span className="text-xs font-medium text-foreground">Pivot points only</span>
        </span>
        <span
          className="rounded-full px-1.5 py-0.5 text-xs font-mono font-bold"
          style={{ backgroundColor: BRIDGE_COLOR + "22", color: BRIDGE_COLOR }}
        >
          {pivotCount}
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

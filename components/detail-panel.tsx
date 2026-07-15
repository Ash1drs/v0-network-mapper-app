"use client";

import {
  Globe,
  Server,
  Link2,
  Hash,
  Clock,
  X,
  ChevronRight,
  Layers,
  Fingerprint,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  entityColor,
  zoneColor,
  categoryOf,
  categoryColor,
  confidenceColor,
  CATEGORY_LABEL,
  confidenceBand,
  confidenceBandLabel,
  EDGE_KIND_LABEL,
  ENTITY_KIND_LABEL,
  MATCH_COLOR,
  BRIDGE_COLOR,
  ZONE_COLOR,
  ZONE_LABEL,
  ZONE_ORDER,
  type Entity,
  type EntityKind,
  type ThreatGraph,
  type Zone,
} from "@/lib/network-types";
import type { ColorMode } from "@/app/page";
import { GitBranch, ShieldAlert } from "lucide-react";

function riskColor(score: number): string {
  if (score >= 70) return "#f87171";
  if (score >= 40) return "#fbbf24";
  if (score >= 20) return "#38bdf8";
  return "#4ade80";
}

function KindIcon({ kind, className }: { kind: EntityKind; className?: string }) {
  switch (kind) {
    case "domain":
      return <Globe className={className} />;
    case "ip":
      return <Server className={className} />;
    case "url":
      return <Link2 className={className} />;
    case "hash":
      return <Fingerprint className={className} />;
    case "asn":
      return <Layers className={className} />;
  }
}

interface DetailPanelProps {
  graph: ThreatGraph;
  feedOrder: string[];
  colorMode: ColorMode;
  selected: Entity | null;
  onSelect: (entity: Entity | null) => void;
  onSetZone: (id: string, zone: Zone) => void;
}

export function DetailPanel({
  graph,
  feedOrder,
  colorMode,
  selected,
  onSelect,
  onSetZone,
}: DetailPanelProps) {
  // ---- Selected entity detail view ----
  if (selected) {
    const byId = new Map(graph.entities.map((e) => [e.id, e]));
    const connections = graph.relationships
      .filter((r) => r.source === selected.id || r.target === selected.id)
      .map((r) => {
        const isSource = r.source === selected.id;
        const otherId = isSource ? r.target : r.source;
        return {
          rel: r,
          other: byId.get(otherId),
          direction: isSource ? "out" : "in",
        };
      })
      .filter((c) => c.other);

    const color =
      colorMode === "zone"
        ? zoneColor(selected.zone)
        : colorMode === "category"
          ? categoryColor(categoryOf(selected))
          : entityColor(selected, feedOrder);

    return (
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">Entity Details</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => onSelect(null)}
            className="h-8 w-8 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
            <span className="sr-only">Close</span>
          </Button>
        </div>

        <div className="rounded-lg border border-border bg-secondary/30 p-3">
          <div className="flex items-center gap-2 mb-2">
            <span
              className="inline-flex h-6 w-6 items-center justify-center rounded-md shrink-0"
              style={{ backgroundColor: color + "22" }}
            >
              <KindIcon kind={selected.kind} className="h-3.5 w-3.5" />
            </span>
            <span className="text-sm font-bold text-foreground break-all">
              {selected.value}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 mb-3">
            <span className="rounded-full border border-border px-2 py-0.5 text-xs font-mono text-muted-foreground">
              {selected.subtype ?? ENTITY_KIND_LABEL[selected.kind]}
            </span>
            <span
              className="rounded-full px-2 py-0.5 text-xs font-mono"
              style={{
                backgroundColor: categoryColor(categoryOf(selected)) + "20",
                color: categoryColor(categoryOf(selected)),
              }}
            >
              {CATEGORY_LABEL[categoryOf(selected)]}
            </span>
            {selected.isAnchor && (
              <span
                className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-mono font-bold"
                style={{ backgroundColor: "#fbbf2422", color: "#fbbf24" }}
              >
                <ShieldAlert className="h-3 w-3" />
                anchor
              </span>
            )}
            {selected.riskScore > 0 && (
              <span
                className="rounded-full px-2 py-0.5 text-xs font-mono font-bold"
                style={{
                  backgroundColor: riskColor(selected.riskScore) + "20",
                  color: riskColor(selected.riskScore),
                }}
              >
                risk {selected.riskScore}
              </span>
            )}
            {selected.matched && (
              <span
                className="rounded-full px-2 py-0.5 text-xs font-mono font-bold"
                style={{ backgroundColor: MATCH_COLOR + "22", color: MATCH_COLOR }}
              >
                matched
              </span>
            )}
            {selected.isBridge && (
              <span
                className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-mono font-bold"
                style={{ backgroundColor: BRIDGE_COLOR + "22", color: BRIDGE_COLOR }}
              >
                <GitBranch className="h-3 w-3" />
                pivot
              </span>
            )}
          </div>

          {/* Environment zone — auto-classified, manually overridable */}
          <div className="mb-3">
            <span className="text-xs text-muted-foreground">Environment</span>
            <div className="mt-1 flex flex-wrap gap-1">
              {ZONE_ORDER.map((z) => {
                const active = (selected.zone ?? "unknown") === z;
                return (
                  <button
                    key={z}
                    type="button"
                    onClick={() => onSetZone(selected.id, z)}
                    className="rounded-md border px-2 py-1 text-xs font-medium transition-colors min-h-[32px]"
                    style={{
                      borderColor: active ? ZONE_COLOR[z] : "var(--border)",
                      backgroundColor: active ? ZONE_COLOR[z] + "22" : "transparent",
                      color: active ? ZONE_COLOR[z] : "var(--muted-foreground)",
                    }}
                  >
                    {ZONE_LABEL[z]}
                  </button>
                );
              })}
            </div>
            {selected.isBridge && (
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground text-pretty">
                This node connects more than one environment — a pivot point where
                the compromise crossed between them.
              </p>
            )}
          </div>

          {/* Feeds this entity appeared in */}
          <div className="mb-3">
            <span className="text-xs text-muted-foreground">
              Seen in {selected.feeds.length} feed
              {selected.feeds.length !== 1 ? "s" : ""}:
            </span>
            <div className="mt-1 flex flex-wrap gap-1">
              {selected.feeds.map((f) => (
                <span
                  key={f}
                  className="rounded-md border px-1.5 py-0.5 font-mono text-xs"
                  style={{
                    borderColor: color + "55",
                    color,
                    backgroundColor: color + "12",
                  }}
                >
                  {f}
                </span>
              ))}
            </div>
          </div>

          {(selected.asn || selected.firstSeen || selected.lastSeen) && (
            <div className="flex flex-col gap-1 mb-3 text-xs">
              {selected.asn && (
                <div className="flex items-center gap-2">
                  <Server className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">ASN:</span>
                  <span className="font-mono text-foreground">
                    {selected.asn}
                    {selected.asName ? ` (${selected.asName})` : ""}
                  </span>
                </div>
              )}
              {selected.firstSeen && (
                <div className="flex items-center gap-2">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">First:</span>
                  <span className="font-mono text-foreground">{selected.firstSeen}</span>
                </div>
              )}
              {selected.lastSeen && (
                <div className="flex items-center gap-2">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">Last:</span>
                  <span className="font-mono text-foreground">{selected.lastSeen}</span>
                </div>
              )}
            </div>
          )}

          {/* Relationships */}
          <div className="text-xs text-muted-foreground mb-2">
            {connections.length} relationship{connections.length !== 1 ? "s" : ""}:
          </div>
          <div className="max-h-[40vh] overflow-y-auto rounded-md border border-border bg-card">
            {connections.length === 0 && (
              <div className="px-3 py-2 text-xs text-muted-foreground">
                No linked entities.
              </div>
            )}
            {connections.map(({ rel, other, direction }) => {
              if (!other) return null;
              const oc =
                colorMode === "zone"
                  ? zoneColor(other.zone)
                  : colorMode === "category"
                    ? categoryColor(categoryOf(other))
                    : entityColor(other, feedOrder);
              const conf = rel.confidence ?? 0;
              return (
                <div key={rel.id} className="border-b border-border/50 last:border-0">
                  <button
                    type="button"
                    onClick={() => onSelect(other)}
                    className="flex w-full items-center gap-2 px-2 py-2 text-left hover:bg-secondary/30 min-h-[44px]"
                  >
                    <KindIcon
                      kind={other.kind}
                      className="h-3 w-3 shrink-0 text-muted-foreground"
                    />
                    <div className="flex flex-1 flex-col overflow-hidden">
                      <span className="truncate text-xs font-mono text-foreground">
                        {other.value}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {direction === "out" ? "" : "\u2190 "}
                        {EDGE_KIND_LABEL[rel.kind]}
                        {direction === "out" ? " \u2192" : ""}
                      </span>
                    </div>
                    {rel.crossZone && (
                      <GitBranch
                        className="h-3 w-3 shrink-0"
                        style={{ color: BRIDGE_COLOR }}
                      />
                    )}
                    {conf > 0 && (
                      <span
                        className="shrink-0 rounded px-1 py-0.5 text-[10px] font-mono font-bold"
                        style={{ backgroundColor: confidenceColor(conf) + "20", color: confidenceColor(conf) }}
                        title={`${confidenceBandLabel(confidenceBand(conf))} (${conf})`}
                      >
                        {conf}
                      </span>
                    )}
                    <span
                      className="h-2 w-2 rounded-full shrink-0"
                      style={{ backgroundColor: oc }}
                    />
                  </button>
                  {rel.explanation?.why && (
                    <p className="px-2 pb-2 text-[11px] leading-relaxed text-muted-foreground text-pretty">
                      {rel.explanation.why}
                      {rel.explanation.sources?.length ? (
                        <span className="text-muted-foreground/70">
                          {" "}
                          &middot; {rel.explanation.sources.join(", ")}
                        </span>
                      ) : null}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  // ---- Empty state ----
  if (graph.entities.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">Entities</h2>
        <p className="text-xs text-muted-foreground leading-relaxed">
          Upload STIX, MISP / VirusTotal Graph, OpenIOC / OTX, or CSV data to map
          how domains, IPs, URLs, and file hashes relate. Indicators that appear
          in more than one feed are highlighted as matches.
        </p>
      </div>
    );
  }

  // ---- Browse list (sorted: matched first, then risk, then degree) ----
  const degree = new Map<string, number>();
  for (const r of graph.relationships) {
    degree.set(r.source, (degree.get(r.source) || 0) + 1);
    degree.set(r.target, (degree.get(r.target) || 0) + 1);
  }
  const sorted = [...graph.entities].sort((a, b) => {
    if (!!b.matched !== !!a.matched) return b.matched ? 1 : -1;
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    return (degree.get(b.id) || 0) - (degree.get(a.id) || 0);
  });
  const top = sorted.slice(0, 80);

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-foreground">
        Entities
        <span className="ml-2 text-xs font-normal text-muted-foreground">
          ({graph.entities.length})
        </span>
      </h2>
      <div className="flex flex-col gap-1.5 max-h-[50vh] overflow-y-auto">
        {top.map((entity) => {
          const color =
            colorMode === "zone"
              ? zoneColor(entity.zone)
              : colorMode === "category"
                ? categoryColor(categoryOf(entity))
                : entityColor(entity, feedOrder);
          const deg = degree.get(entity.id) || 0;
          return (
            <button
              key={entity.id}
              type="button"
              onClick={() => onSelect(entity)}
              className="flex items-center gap-2 rounded-md border border-border bg-secondary/30 px-3 py-2 text-left hover:bg-secondary/50 transition-colors min-h-[44px]"
            >
              <span
                className="inline-flex h-5 w-5 items-center justify-center rounded shrink-0"
                style={{ backgroundColor: color + "22" }}
              >
                <KindIcon kind={entity.kind} className="h-3 w-3" />
              </span>
              <div className="flex flex-1 flex-col overflow-hidden">
                <span className="truncate text-xs font-mono text-foreground">
                  {entity.value}
                </span>
                <span className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{ENTITY_KIND_LABEL[entity.kind]}</span>
                  <span className="flex items-center gap-0.5">
                    <Hash className="h-2.5 w-2.5" />
                    {deg}
                  </span>
                </span>
              </div>
              {entity.matched && (
                <span
                  className="rounded-full px-1.5 py-0.5 text-[10px] font-mono font-bold shrink-0"
                  style={{ backgroundColor: MATCH_COLOR + "22", color: MATCH_COLOR }}
                >
                  match
                </span>
              )}
              {entity.riskScore > 0 && (
                <span
                  className="shrink-0 rounded px-1 py-0.5 text-xs font-mono"
                  style={{
                    backgroundColor: riskColor(entity.riskScore) + "20",
                    color: riskColor(entity.riskScore),
                  }}
                >
                  {entity.riskScore}
                </span>
              )}
              <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
            </button>
          );
        })}
        {sorted.length > top.length && (
          <div className="px-3 py-2 text-xs text-muted-foreground text-center">
            +{sorted.length - top.length} more &mdash; use filters to narrow down
          </div>
        )}
      </div>
    </div>
  );
}

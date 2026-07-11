"use client";

import { useState, useMemo, useRef } from "react";
import { NetworkGraph, type NetworkGraphHandle } from "@/components/network-graph";
import { UploadPanel } from "@/components/ip-input-panel";
import { DetailPanel } from "@/components/detail-panel";
import { GraphFilters } from "@/components/filter-controls";
import type { Entity, EntityKind, ThreatGraph } from "@/lib/network-types";
import { exportPng, canvasToPng, generatePdfReport, type ReportStats } from "@/lib/report";
import { Activity, ChevronDown, ChevronUp, ImageDown, FileDown } from "lucide-react";

interface AnalysisStats {
  entities: number;
  relationships: number;
  byKind: Record<EntityKind, number>;
  matchedEntities: number;
  matchedEdges: number;
  feeds: number;
}

export interface GraphFilterState {
  kinds: Set<EntityKind>;
  feeds: Set<string>;
  matchedOnly: boolean;
}

const EMPTY_GRAPH: ThreatGraph = { entities: [], relationships: [] };

export default function Page() {
  const [rawGraph, setRawGraph] = useState<ThreatGraph>(EMPTY_GRAPH);
  const [feedOrder, setFeedOrder] = useState<string[]>([]);
  const [stats, setStats] = useState<AnalysisStats | null>(null);
  const [selected, setSelected] = useState<Entity | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);
  const [filters, setFilters] = useState<GraphFilterState>({
    kinds: new Set(),
    feeds: new Set(),
    matchedOnly: false,
  });
  const graphRef = useRef<NetworkGraphHandle>(null);

  const handleAnalyze = async (graphs: ThreatGraph[]) => {
    if (graphs.length === 0) {
      setRawGraph(EMPTY_GRAPH);
      setFeedOrder([]);
      setStats(null);
      setSelected(null);
      setError(null);
      return;
    }
    setIsLoading(true);
    setError(null);
    setSelected(null);
    try {
      const res = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ graphs }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Analysis failed");
        return;
      }
      setRawGraph(data.graph);
      setFeedOrder(data.feedOrder);
      setStats(data.stats);
      // Reset filters to show everything present.
      setFilters({
        kinds: new Set(Object.keys(data.stats.byKind) as EntityKind[]),
        feeds: new Set(data.feedOrder as string[]),
        matchedOnly: false,
      });
    } catch {
      setError("Failed to analyze data");
    } finally {
      setIsLoading(false);
    }
  };

  // Apply live filters to the merged graph.
  const filteredGraph = useMemo<ThreatGraph>(() => {
    if (rawGraph.entities.length === 0) return EMPTY_GRAPH;
    const keep = new Set<string>();
    const entities = rawGraph.entities.filter((e) => {
      if (filters.kinds.size && !filters.kinds.has(e.kind)) return false;
      if (filters.feeds.size && !e.feeds.some((f) => filters.feeds.has(f))) return false;
      if (filters.matchedOnly && !e.matched) return false;
      keep.add(e.id);
      return true;
    });
    const relationships = rawGraph.relationships.filter(
      (r) => keep.has(r.source) && keep.has(r.target),
    );
    return { entities, relationships };
  }, [rawGraph, filters]);

  // Resolve the canvas background so exported images match the on-screen card.
  const graphBackground = (canvas: HTMLCanvasElement) => {
    const parentBg = canvas.parentElement
      ? getComputedStyle(canvas.parentElement).backgroundColor
      : "";
    return parentBg && parentBg !== "rgba(0, 0, 0, 0)" ? parentBg : "#0f1420";
  };

  // Stats for the report reflect exactly what's visible (post-filter).
  const reportStats = (g: ThreatGraph): ReportStats => {
    const byKind = { domain: 0, ip: 0, url: 0, hash: 0, asn: 0 } as Record<EntityKind, number>;
    for (const e of g.entities) byKind[e.kind]++;
    return {
      entities: g.entities.length,
      relationships: g.relationships.length,
      byKind,
      matchedEntities: g.entities.filter((e) => e.matched).length,
      matchedEdges: g.relationships.filter((r) => r.matched).length,
      feeds: new Set(g.entities.flatMap((e) => e.feeds)).size,
    };
  };

  const handleExportPng = () => {
    const canvas = graphRef.current?.getCanvas();
    if (!canvas) return;
    exportPng(canvas, graphBackground(canvas));
  };

  const handleExportPdf = () => {
    const canvas = graphRef.current?.getCanvas();
    const image = canvas ? canvasToPng(canvas, graphBackground(canvas)) : null;
    generatePdfReport({
      graph: filteredGraph,
      feedOrder,
      stats: reportStats(filteredGraph),
      graphImage: image,
    });
  };

  const canExport = filteredGraph.entities.length > 0;

  return (
    <main className="flex min-h-dvh flex-col bg-background lg:h-dvh lg:overflow-hidden">
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2.5">
          <Activity className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-bold tracking-tight text-foreground font-mono">NetMap</h1>
        </div>
        <span className="text-xs font-mono text-muted-foreground hidden sm:inline">
          Threat Intel Relationship Mapper
        </span>
      </header>

      <div className="flex flex-1 flex-col lg:flex-row lg:min-h-0 lg:overflow-hidden">
        <aside className="flex flex-col border-b border-border lg:border-b-0 lg:border-r lg:w-80 xl:w-96 lg:min-h-0">
          <button
            type="button"
            onClick={() => setPanelOpen(!panelOpen)}
            className="flex items-center justify-between px-4 py-3 lg:hidden min-h-[44px]"
          >
            <span className="text-sm font-semibold text-foreground">Controls</span>
            {panelOpen ? (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            )}
          </button>

          <div
            className={`flex flex-col gap-6 overflow-y-auto px-4 pb-4 lg:py-4 lg:flex-1 lg:min-h-0 ${
              panelOpen ? "block" : "hidden lg:block"
            }`}
          >
            <UploadPanel onAnalyze={handleAnalyze} isLoading={isLoading} stats={stats} />

            {error && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}

            {stats && (
              <GraphFilters
                feedOrder={feedOrder}
                byKind={stats.byKind}
                filters={filters}
                onChange={setFilters}
                matchedCount={stats.matchedEntities}
              />
            )}

            <DetailPanel graph={rawGraph} feedOrder={feedOrder} selected={selected} onSelect={setSelected} />
          </div>
        </aside>

        <section className="flex flex-1 flex-col p-3 lg:p-4 min-h-[350px] lg:min-h-0 lg:h-full">
          <div className="mb-3 flex items-center justify-between gap-2">
            <span className="text-xs font-mono text-muted-foreground">
              {canExport
                ? `${filteredGraph.entities.length} entities · ${filteredGraph.relationships.length} relationships`
                : "No graph loaded"}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleExportPng}
                disabled={!canExport}
                className="inline-flex min-h-[36px] items-center gap-1.5 rounded-md border border-border bg-card px-3 text-xs font-medium text-foreground transition-colors hover:bg-secondary disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ImageDown className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">PNG</span>
              </button>
              <button
                type="button"
                onClick={handleExportPdf}
                disabled={!canExport}
                className="inline-flex min-h-[36px] items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <FileDown className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Report PDF</span>
              </button>
            </div>
          </div>
          <NetworkGraph
            ref={graphRef}
            graph={filteredGraph}
            feedOrder={feedOrder}
            selectedId={selected?.id ?? null}
            onSelectEntity={setSelected}
          />
        </section>
      </div>
    </main>
  );
}

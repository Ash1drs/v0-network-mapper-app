"use client";

import { useState, useMemo } from "react";
import { NetworkGraph } from "@/components/network-graph";
import { UploadPanel } from "@/components/ip-input-panel";
import { DetailPanel } from "@/components/detail-panel";
import { GraphFilters } from "@/components/filter-controls";
import type { Entity, EntityKind, ThreatGraph } from "@/lib/network-types";
import { Activity, ChevronDown, ChevronUp } from "lucide-react";

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

  return (
    <main className="flex min-h-dvh flex-col bg-background">
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2.5">
          <Activity className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-bold tracking-tight text-foreground font-mono">NetMap</h1>
        </div>
        <span className="text-xs font-mono text-muted-foreground hidden sm:inline">
          Threat Intel Relationship Mapper
        </span>
      </header>

      <div className="flex flex-1 flex-col lg:flex-row">
        <aside className="flex flex-col border-b border-border lg:border-b-0 lg:border-r lg:w-80 xl:w-96">
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
            className={`flex flex-col gap-6 overflow-y-auto px-4 pb-4 lg:py-4 ${
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

        <section className="flex flex-1 flex-col p-3 lg:p-4 min-h-[350px] lg:min-h-0">
          <NetworkGraph
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

import { enrichGraph, mergeGraphs } from "@/lib/ingest";
import {
  categoryOf,
  type Category,
  type EntityKind,
  type ThreatGraph,
} from "@/lib/network-types";

export interface AnalysisResult {
  graph: ThreatGraph;
  feedOrder: string[];
  stats: {
    entities: number;
    relationships: number;
    byKind: Record<EntityKind, number>;
    byCategory: Record<Category, number>;
    matchedEntities: number;
    matchedEdges: number;
    anchors: number;
    correlationEdges: number;
    feeds: number;
  };
}

export class AnalysisError extends Error {}

/**
 * Pure, dependency-free analysis so it can run in the browser. Large uploads
 * (tens of thousands of indicators) exceed the serverless request body limit,
 * so the client no longer round-trips the raw feeds to an API route.
 */
export function analyzeGraphs(graphs: ThreatGraph[]): AnalysisResult {
  if (graphs.length === 0) {
    throw new AnalysisError(
      "No graphs to analyze. Upload STIX, MISP/VirusTotal, OpenIOC (AlienVault), passive DNS, or CSV data.",
    );
  }

  const graph = enrichGraph(mergeGraphs(graphs));

  if (graph.entities.length === 0) {
    throw new AnalysisError(
      "No indicators found. Each feed needs at least one domain, IP, URL, or file hash.",
    );
  }

  const feedOrderSet = new Set<string>();
  for (const e of graph.entities) for (const f of e.feeds) feedOrderSet.add(f);
  const feedOrder = [...feedOrderSet];

  const byKind = {} as Record<EntityKind, number>;
  const byCategory = {} as Record<Category, number>;
  let matchedEntities = 0;
  let anchors = 0;
  for (const e of graph.entities) {
    byKind[e.kind] = (byKind[e.kind] || 0) + 1;
    const c = categoryOf(e);
    byCategory[c] = (byCategory[c] || 0) + 1;
    if (e.matched) matchedEntities++;
    if (e.isAnchor) anchors++;
  }

  let matchedEdges = 0;
  let correlationEdges = 0;
  for (const r of graph.relationships) {
    if (r.matched) matchedEdges++;
    if (r.kind.startsWith("shares-")) correlationEdges++;
  }

  return {
    graph,
    feedOrder,
    stats: {
      entities: graph.entities.length,
      relationships: graph.relationships.length,
      byKind,
      byCategory,
      matchedEntities,
      matchedEdges,
      anchors,
      correlationEdges,
      feeds: feedOrder.length,
    },
  };
}

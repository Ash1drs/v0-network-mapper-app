import { NextRequest, NextResponse } from "next/server";
import { mergeGraphs } from "@/lib/ingest";
import type { EntityKind, ThreatGraph } from "@/lib/network-types";

interface LookupBody {
  graphs?: ThreatGraph[];
}

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as LookupBody;
    const graphs = Array.isArray(body.graphs) ? body.graphs : [];

    if (graphs.length === 0) {
      return NextResponse.json(
        {
          error:
            "No graphs to analyze. Upload STIX, MISP/VirusTotal, OpenIOC (AlienVault), passive DNS, or CSV data.",
        },
        { status: 400 },
      );
    }

    const graph = mergeGraphs(graphs);

    if (graph.entities.length === 0) {
      return NextResponse.json(
        {
          error:
            "No indicators found. Each feed needs at least one domain, IP, URL, or file hash.",
        },
        { status: 400 },
      );
    }

    // Feed order = order feeds first appear, used for stable per-feed coloring.
    const feedOrder: string[] = [];
    for (const e of graph.entities)
      for (const f of e.feeds) if (!feedOrder.includes(f)) feedOrder.push(f);

    const byKind = {} as Record<EntityKind, number>;
    for (const e of graph.entities) byKind[e.kind] = (byKind[e.kind] || 0) + 1;

    const matchedEntities = graph.entities.filter((e) => e.matched).length;
    const matchedEdges = graph.relationships.filter((r) => r.matched).length;

    return NextResponse.json({
      graph,
      feedOrder,
      stats: {
        entities: graph.entities.length,
        relationships: graph.relationships.length,
        byKind,
        matchedEntities,
        matchedEdges,
        feeds: feedOrder.length,
      },
    });
  } catch (error) {
    console.error("[v0] lookup parse error:", error);
    return NextResponse.json(
      { error: "Failed to analyze uploaded data." },
      { status: 500 },
    );
  }
}

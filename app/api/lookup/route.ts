import { NextRequest, NextResponse } from "next/server";
import { AnalysisError, analyzeGraphs } from "@/lib/analyze";
import type { ThreatGraph } from "@/lib/network-types";

interface LookupBody {
  graphs?: ThreatGraph[];
}

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as LookupBody;
    const graphs = Array.isArray(body.graphs) ? body.graphs : [];
    return NextResponse.json(analyzeGraphs(graphs));
  } catch (error) {
    if (error instanceof AnalysisError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    console.error("lookup parse error:", error);
    return NextResponse.json(
      { error: "Failed to analyze uploaded data." },
      { status: 500 },
    );
  }
}

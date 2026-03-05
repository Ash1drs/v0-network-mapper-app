import { NextRequest, NextResponse } from "next/server";
import type { DnsRecord, AsnGroup } from "@/lib/network-types";

const GROUP_COLORS = [
  "#22d3ee", "#34d399", "#f59e0b", "#f472b6",
  "#a78bfa", "#fb923c", "#38bdf8", "#4ade80",
  "#e879f9", "#facc15", "#2dd4bf", "#f87171",
  "#818cf8", "#a3e635", "#fbbf24", "#c084fc",
];

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    let records: DnsRecord[] = [];

    // Accept either { records: [...] } or a raw array
    if (Array.isArray(body)) {
      records = body;
    } else if (body.records && Array.isArray(body.records)) {
      records = body.records;
    } else {
      return NextResponse.json(
        { error: "Could not find DNS records in uploaded data. Expected a JSON array of objects with query/answer fields." },
        { status: 400 }
      );
    }

    // Validate we actually have the right shape
    const valid = records.filter(
      (r) => r.query && r.answer && r.answer_asn !== undefined
    );

    if (valid.length === 0) {
      return NextResponse.json(
        { error: "No valid DNS records found. Each record needs at least query, answer, and answer_asn fields." },
        { status: 400 }
      );
    }

    // Group by ASN
    const asnMap = new Map<string, { asName: string; ips: Set<string>; domains: Set<string>; records: DnsRecord[]; riskScores: number[]; totalCount: number }>();

    for (const r of valid) {
      const key = r.answer_asn || "unknown";
      if (!asnMap.has(key)) {
        asnMap.set(key, {
          asName: r.answer_as_name || "Unknown",
          ips: new Set(),
          domains: new Set(),
          records: [],
          riskScores: [],
          totalCount: 0,
        });
      }
      const group = asnMap.get(key)!;
      group.ips.add(r.answer);
      group.domains.add(r.query);
      group.records.push(r);
      group.riskScores.push(r.answer_risk_score);
      group.totalCount += r.count;
    }

    let colorIndex = 0;
    const groups: AsnGroup[] = Array.from(asnMap.entries())
      .sort((a, b) => b[1].ips.size - a[1].ips.size)
      .map(([asn, data]) => ({
        asn,
        asName: data.asName,
        ips: Array.from(data.ips),
        domains: Array.from(data.domains),
        records: data.records,
        maxRiskScore: Math.max(...data.riskScores),
        avgRiskScore: Math.round(data.riskScores.reduce((a, b) => a + b, 0) / data.riskScores.length),
        totalCount: data.totalCount,
        color: GROUP_COLORS[colorIndex++ % GROUP_COLORS.length],
      }));

    return NextResponse.json({
      groups,
      totalRecords: valid.length,
      uniqueIps: new Set(valid.map((r) => r.answer)).size,
      uniqueDomains: new Set(valid.map((r) => r.query)).size,
      uniqueAsns: asnMap.size,
    });
  } catch (error) {
    console.error("Parse error:", error);
    return NextResponse.json(
      { error: "Failed to parse uploaded data. Make sure it's valid JSON." },
      { status: 500 }
    );
  }
}

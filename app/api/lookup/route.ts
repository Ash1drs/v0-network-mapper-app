import { NextRequest, NextResponse } from "next/server";
import type { DnsRecord, AsnGroup } from "@/lib/network-types";

const GROUP_COLORS = [
  "#22d3ee", "#34d399", "#f59e0b", "#f472b6",
  "#a78bfa", "#fb923c", "#38bdf8", "#4ade80",
  "#e879f9", "#facc15", "#2dd4bf", "#f87171",
  "#818cf8", "#a3e635", "#fbbf24", "#c084fc",
];

interface IpApiResponse {
  query: string;
  status: string;
  org?: string;
  isp?: string;
  as?: string;
}

async function enrichIpsWithAsn(ips: string[]): Promise<Map<string, { asn: string; asName: string }>> {
  const results = new Map<string, { asn: string; asName: string }>();
  
  if (ips.length === 0) return results;
  
  // Batch in chunks of 100 (ip-api limit)
  const chunks: string[][] = [];
  for (let i = 0; i < ips.length; i += 100) {
    chunks.push(ips.slice(i, i + 100));
  }
  
  for (const chunk of chunks) {
    try {
      const response = await fetch("http://ip-api.com/batch?fields=query,status,org,isp,as", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(chunk.map(ip => ({ query: ip }))),
      });
      
      if (response.ok) {
        const data: IpApiResponse[] = await response.json();
        for (const item of data) {
          if (item.status === "success") {
            // Extract ASN number from "AS12345 Org Name" format
            const asMatch = item.as?.match(/^AS(\d+)/);
            const asn = asMatch ? `AS${asMatch[1]}` : "UNKNOWN";
            const asName = item.org || item.isp || item.as || "Unknown Organization";
            results.set(item.query, { asn, asName });
          }
        }
      }
      
      // Rate limit: small delay between chunks
      if (chunks.length > 1) {
        await new Promise(r => setTimeout(r, 500));
      }
    } catch (e) {
      console.error("IP enrichment failed:", e);
    }
  }
  
  return results;
}

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
        { error: "Could not find records in uploaded data. Expected a JSON array." },
        { status: 400 }
      );
    }

    // Filter to records that have at least an IP or domain
    const valid = records.filter(r => r.answer || r.query);

    if (valid.length === 0) {
      return NextResponse.json(
        { error: "No valid records found. Each record needs at least an IP address or domain." },
        { status: 400 }
      );
    }

    // Find IPs that need ASN enrichment
    const ipsNeedingEnrichment = [...new Set(
      valid
        .filter(r => r.answer && (!r.answer_asn || r.answer_asn === "UNKNOWN"))
        .map(r => r.answer)
    )];

    // Enrich IPs with ASN data if needed (limit to 500 for performance)
    let enrichmentMap = new Map<string, { asn: string; asName: string }>();
    if (ipsNeedingEnrichment.length > 0 && ipsNeedingEnrichment.length <= 500) {
      enrichmentMap = await enrichIpsWithAsn(ipsNeedingEnrichment);
    }

    // Apply enrichment to records
    const enrichedRecords = valid.map(r => {
      if (r.answer && (!r.answer_asn || r.answer_asn === "UNKNOWN")) {
        const enrichment = enrichmentMap.get(r.answer);
        if (enrichment) {
          return {
            ...r,
            answer_asn: enrichment.asn,
            answer_as_name: enrichment.asName,
          };
        }
      }
      return r;
    });

    // Group by ASN
    const asnMap = new Map<string, { asName: string; ips: Set<string>; domains: Set<string>; records: DnsRecord[]; riskScores: number[]; totalCount: number }>();

    for (const r of enrichedRecords) {
      const key = r.answer_asn || "UNKNOWN";
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
      if (r.answer) group.ips.add(r.answer);
      if (r.query) group.domains.add(r.query);
      group.records.push(r);
      group.riskScores.push(r.answer_risk_score || r.query_risk_score || 0);
      group.totalCount += r.count || 1;
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
        maxRiskScore: data.riskScores.length > 0 ? Math.max(...data.riskScores) : 0,
        avgRiskScore: data.riskScores.length > 0 ? Math.round(data.riskScores.reduce((a, b) => a + b, 0) / data.riskScores.length) : 0,
        totalCount: data.totalCount,
        color: GROUP_COLORS[colorIndex++ % GROUP_COLORS.length],
      }));

    return NextResponse.json({
      groups,
      totalRecords: enrichedRecords.length,
      uniqueIps: new Set(enrichedRecords.map(r => r.answer).filter(Boolean)).size,
      uniqueDomains: new Set(enrichedRecords.map(r => r.query).filter(Boolean)).size,
      uniqueAsns: asnMap.size,
      enrichedCount: enrichmentMap.size,
    });
  } catch (error) {
    console.error("Parse error:", error);
    return NextResponse.json(
      { error: "Failed to parse uploaded data. Make sure it's valid JSON." },
      { status: 500 }
    );
  }
}

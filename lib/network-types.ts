// Raw record from INFRARUN / passive DNS export
export interface DnsRecord {
  query: string;
  query_risk_score: number;
  query_risk_score_decider: string;
  query_asn: string;
  query_as_name: string;
  answer: string;
  answer_risk_score: number;
  answer_risk_score_decider: string;
  answer_asn: string;
  answer_as_name: string;
  count: number;
  first_seen: string;
  last_seen: string;
  type: string;
}

// Human-friendly label for a cluster key. Real ASNs render as "AS15169";
// domain-family or other keys (e.g. "symantke.com", "unknown") render as-is.
export function clusterLabel(asn: string): string {
  if (!asn || asn === "unknown") return "Ungrouped";
  if (/^AS\d+$/i.test(asn)) return asn.toUpperCase();
  if (/^\d+$/.test(asn)) return `AS${asn}`;
  return asn;
}

// Grouped by ASN / organization
export interface AsnGroup {
  asn: string;
  asName: string;
  ips: string[];
  domains: string[];
  records: DnsRecord[];
  maxRiskScore: number;
  avgRiskScore: number;
  totalCount: number;
  color: string;
}

// Graph visualization types
export interface GraphNode {
  id: string;
  label: string;
  type: "asn" | "ip" | "domain";
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  riskScore: number;
  data?: DnsRecord;
  asnGroup?: AsnGroup;
}

export interface GraphEdge {
  source: string;
  target: string;
  color: string;
}

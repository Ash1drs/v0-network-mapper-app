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

// ===========================================================================
// Threat-intel relationship graph model
// A typed entity + relationship graph that all feeds (STIX, MISP/VT, OpenIOC,
// passive DNS, CSV) normalize into. Identical indicators across feeds merge
// into one shared entity; typed edges are preserved.
//
// GOLDEN RULE: NetMap is an evidence-driven correlation engine, NOT an
// attribution engine. Every node, edge, score, and conclusion must be
// explainable, reproducible, and traceable back to observable evidence.
// ===========================================================================

// The structural kind drives node SHAPE + parsing. Kept to the original five
// so all shape/label logic stays stable. Precise indicator typing lives in
// `Entity.subtype`, and visual/semantic grouping in `Entity.category`.
export type EntityKind = "domain" | "ip" | "url" | "hash" | "asn";

export type EdgeKind =
  // observed structural relationships
  | "resolves-to"
  | "sub-domain-of"
  | "sibling-of"
  | "communicates-with"
  | "belongs-to"
  | "downloaded-from"
  | "hosts"
  | "beacons-to"
  | "executes"
  | "spawns"
  | "issued-by"
  | "signed-by"
  // correlation edges — EARNED by shared evidence across the graph/feeds
  | "shares-ip"
  | "shares-domain"
  | "shares-cert"
  | "shares-hash"
  | "shares-asn"
  | "shares-infrastructure"
  | "shares-device"
  | "shares-user"
  | "repeated-in"
  | "related-to";

// Edges created by the cross-dataset correlation pass (vs. observed in a feed).
export const CORRELATION_EDGES: ReadonlySet<EdgeKind> = new Set<EdgeKind>([
  "shares-ip",
  "shares-domain",
  "shares-cert",
  "shares-hash",
  "shares-asn",
  "shares-infrastructure",
  "shares-device",
  "shares-user",
  "repeated-in",
]);

// ---- Confidence model (earned by correlation, not origin) -----------------
// Every edge carries a 0-100 confidence and a short reason. Bands follow the
// spec: crypto-verified overlap is highest; single-source speculation lowest.
export type ConfidenceBand =
  | "verified"
  | "strong"
  | "probable"
  | "possible"
  | "speculative"
  | "unknown";

export interface EdgeExplanation {
  why: string; // one-line plain-language justification
  evidence: string[]; // concrete observable facts supporting the edge
  sources: string[]; // feed ids that assert / corroborate this edge
  firstSeen?: string;
  lastSeen?: string;
}

export const CONFIDENCE_BANDS: {
  band: ConfidenceBand;
  min: number;
  label: string;
  color: string;
}[] = [
  { band: "verified", min: 90, label: "Verified", color: "#4ade80" },
  { band: "strong", min: 75, label: "Strong", color: "#22d3ee" },
  { band: "probable", min: 55, label: "Probable", color: "#38bdf8" },
  { band: "possible", min: 35, label: "Possible", color: "#facc15" },
  { band: "speculative", min: 15, label: "Speculative", color: "#fb923c" },
  { band: "unknown", min: 0, label: "Unknown", color: "#64748b" },
];

export function confidenceBand(score: number): ConfidenceBand {
  for (const b of CONFIDENCE_BANDS) if (score >= b.min) return b.band;
  return "unknown";
}

export function confidenceColor(score: number): string {
  const band = confidenceBand(score);
  return CONFIDENCE_BANDS.find((b) => b.band === band)?.color ?? "#64748b";
}

export function confidenceBandLabel(band: ConfidenceBand): string {
  return CONFIDENCE_BANDS.find((b) => b.band === band)?.label ?? "Unknown";
}

// An environment zone: which side of the compromise a node belongs to.
// This is the layer that reveals the personal -> corporate pivot structure.
export type Zone = "personal" | "corporate" | "adversary" | "unknown";

export interface Entity {
  id: string; // canonical key: `${kind}:${value}` (value lowercased)
  kind: EntityKind;
  value: string;
  feeds: string[]; // source feed ids (filenames) that contributed this entity
  riskScore: number; // 0-100
  asn?: string;
  asName?: string;
  firstSeen?: string;
  lastSeen?: string;
  matched?: boolean; // present in more than one feed (computed on merge)
  zone?: Zone; // environment classification (auto + manual override)
  isBridge?: boolean; // connects two different known zones = a pivot point
  category?: Category; // visual/semantic bucket (color)
  subtype?: string; // precise indicator type (ja3, imei, registry-key, ...)
  secret?: boolean; // shape of a secret detected; value is NEVER stored
  isAnchor?: boolean; // matches a case seed-anchor indicator
}

export interface Relationship {
  id: string; // `${source}|${kind}|${target}`
  source: string; // entity id
  target: string; // entity id
  kind: EdgeKind;
  feeds: string[];
  matched?: boolean; // same edge asserted by more than one feed
  crossZone?: boolean; // endpoints sit in two different known zones
  confidence?: number; // 0-100, earned by correlation strength
  explanation?: EdgeExplanation; // why this edge exists + provenance
}

export interface ThreatGraph {
  entities: Entity[];
  relationships: Relationship[];
}

// ---------------------------------------------------------------------------
// Indicator taxonomy — full list, TIERED. `category` drives color; `subtype`
// records the precise type. Secrets are detected by shape and flagged only.
// ---------------------------------------------------------------------------
export type Category =
  | "infrastructure"
  | "domain"
  | "organization"
  | "certificate"
  | "malware"
  | "device"
  | "user"
  | "unknown";

export const CATEGORY_ORDER: Category[] = [
  "infrastructure",
  "domain",
  "organization",
  "certificate",
  "malware",
  "device",
  "user",
  "unknown",
];

// Spec color rules. Purple is used intentionally here for "organization" per
// the engine spec (a deliberate, requested taxonomy color).
export const CATEGORY_COLOR: Record<Category, string> = {
  infrastructure: "#38bdf8", // blue
  domain: "#4ade80", // green
  organization: "#a78bfa", // purple
  certificate: "#fb923c", // orange
  malware: "#f87171", // red
  device: "#facc15", // yellow
  user: "#22d3ee", // cyan
  unknown: "#64748b", // gray
};

export const CATEGORY_LABEL: Record<Category, string> = {
  infrastructure: "Infrastructure",
  domain: "Domain",
  organization: "Organization",
  certificate: "Certificate",
  malware: "Malware / file",
  device: "Device",
  user: "User / identity",
  unknown: "Unknown",
};

// Default category for a structural kind (recognizer may refine to a more
// specific category via subtype).
const KIND_CATEGORY: Record<EntityKind, Category> = {
  ip: "infrastructure",
  asn: "infrastructure",
  domain: "domain",
  url: "domain",
  hash: "malware",
};

export function defaultCategory(kind: EntityKind): Category {
  return KIND_CATEGORY[kind] ?? "unknown";
}

export function categoryOf(e: { kind: EntityKind; category?: Category }): Category {
  return e.category ?? defaultCategory(e.kind);
}

export function categoryColor(cat: Category): string {
  return CATEGORY_COLOR[cat] ?? CATEGORY_COLOR.unknown;
}

// ---- Color system for feed vs. match coding ----

// One color means "this entity appears in more than one feed" (a match).
export const MATCH_COLOR = "#ec4899"; // magenta/pink — reserved for matches

// Distinct per-feed palette (no pink — that's reserved for matches; no purple).
export const FEED_COLORS = [
  "#22d3ee", // cyan
  "#4ade80", // green
  "#f59e0b", // amber
  "#38bdf8", // sky
  "#2dd4bf", // teal
  "#a3e635", // lime
  "#fb923c", // orange
  "#facc15", // yellow
];

export function feedColor(feedIndex: number): string {
  return FEED_COLORS[feedIndex % FEED_COLORS.length];
}

// A node/edge is colored by match state first, then by its single feed.
export function entityColor(
  item: { matched?: boolean; feeds: string[] },
  feedOrder: string[],
): string {
  if (item.matched || item.feeds.length > 1) return MATCH_COLOR;
  const idx = feedOrder.indexOf(item.feeds[0]);
  return feedColor(idx < 0 ? 0 : idx);
}

// ---- Zone (environment) color + label system ----

// A distinct near-white halo marks pivot/bridge nodes regardless of color mode.
export const BRIDGE_COLOR = "#f1f5f9";

export const ZONE_ORDER: Zone[] = ["personal", "corporate", "adversary", "unknown"];

export const ZONE_COLOR: Record<Zone, string> = {
  personal: "#38bdf8", // sky
  corporate: "#f59e0b", // amber
  adversary: "#f87171", // red
  unknown: "#64748b", // slate
};

export const ZONE_LABEL: Record<Zone, string> = {
  personal: "Personal",
  corporate: "Corporate",
  adversary: "Adversary infra",
  unknown: "Unclassified",
};

export const ZONE_DESC: Record<Zone, string> = {
  personal: "Your personal accounts, devices, and services",
  corporate: "Work identity + SaaS (Okta, Salesforce, FedEx, etc.)",
  adversary: "Attacker-controlled or malicious infrastructure",
  unknown: "Not yet classified into an environment",
};

export function zoneColor(zone?: Zone): string {
  return ZONE_COLOR[zone ?? "unknown"];
}

export const ENTITY_KIND_LABEL: Record<EntityKind, string> = {
  domain: "Domain",
  ip: "IP",
  url: "URL",
  hash: "File hash",
  asn: "ASN / Org",
};

export const EDGE_KIND_LABEL: Record<EdgeKind, string> = {
  "resolves-to": "resolves to",
  "sub-domain-of": "sub-domain of",
  "sibling-of": "sibling of",
  "communicates-with": "communicates with",
  "belongs-to": "belongs to",
  "downloaded-from": "downloaded from",
  hosts: "hosts",
  "beacons-to": "beacons to",
  executes: "executes",
  spawns: "spawns",
  "issued-by": "issued by",
  "signed-by": "signed by",
  "shares-ip": "shares IP",
  "shares-domain": "shares domain",
  "shares-cert": "shares certificate",
  "shares-hash": "shares hash",
  "shares-asn": "shares ASN",
  "shares-infrastructure": "shares infrastructure",
  "shares-device": "shares device",
  "shares-user": "shares user",
  "repeated-in": "repeated in",
  "related-to": "related to",
};

export function entityId(kind: EntityKind, value: string): string {
  return `${kind}:${value.trim().toLowerCase()}`;
}

import {
  BRIDGE_COLOR,
  MATCH_COLOR,
  CORRELATION_EDGES,
  EDGE_KIND_LABEL,
  type Entity,
  type ThreatGraph,
  type Zone,
} from "@/lib/network-types";

// The four ways two pieces of evidence can be tied together. Each one is
// computed from observable data only, so every claim in the UI can be traced.
export type Signal = "match" | "overlap" | "pivot" | "sequence";

export const SIGNAL_ORDER: Signal[] = ["match", "overlap", "pivot", "sequence"];

export const SIGNAL_LABEL: Record<Signal, string> = {
  match: "Match",
  overlap: "Overlap",
  pivot: "Pivot",
  sequence: "Sequence",
};

export const SIGNAL_DESC: Record<Signal, string> = {
  match: "Same indicator reported by 2+ feeds",
  overlap: "Shares a link that 2+ feeds agree on, or shares infrastructure",
  pivot: "Connects two different environments",
  sequence: "Its record: first seen, times seen, what it connects to and from",
};

export const SIGNAL_COLOR: Record<Signal, string> = {
  match: MATCH_COLOR,
  overlap: "#6f9e8f",
  pivot: BRIDGE_COLOR,
  sequence: "#b08d57",
};

export interface OverlapItem {
  otherId: string;
  otherValue: string;
  label: string;
  feeds: string[];
}

export interface SequenceLink {
  id: string;
  value: string;
  label: string; // relationship label, e.g. "resolves to"
  firstSeen?: string;
  seenCount?: number;
}

// The record of an indicator over time: when it was first seen, how often,
// where it connects to (outbound), and what connects to it (inbound).
// Links are ordered chronologically by their own first-seen date.
export interface SequenceInfo {
  firstSeen?: string;
  lastSeen?: string;
  seenCount?: number;
  rank: number; // 1-based chronological position among self + timed neighbors
  total: number;
  connectsTo: SequenceLink[];
  connectedFrom: SequenceLink[];
}

export interface EntitySignals {
  match: string[] | null; // feeds it appears in
  overlap: OverlapItem[] | null;
  pivot: Zone[] | null; // environments it bridges
  sequence: SequenceInfo | null;
}

export type SignalIndex = Map<string, EntitySignals>;

function ts(value?: string): number {
  if (!value) return NaN;
  const t = Date.parse(value);
  return Number.isNaN(t) ? NaN : t;
}

export function buildSignals(graph: ThreatGraph): SignalIndex {
  const byId = new Map(graph.entities.map((e) => [e.id, e]));
  const neighbors = new Map<string, Set<string>>();
  const overlaps = new Map<string, OverlapItem[]>();
  const outbound = new Map<string, Map<string, string>>(); // self -> (target -> label)
  const inbound = new Map<string, Map<string, string>>(); // self -> (source -> label)

  const link = (a: string, b: string) => {
    let set = neighbors.get(a);
    if (!set) neighbors.set(a, (set = new Set()));
    set.add(b);
  };
  const directed = (map: Map<string, Map<string, string>>, self: string, other: string, label: string) => {
    let m = map.get(self);
    if (!m) map.set(self, (m = new Map()));
    if (!m.has(other)) m.set(other, label);
  };

  for (const r of graph.relationships) {
    link(r.source, r.target);
    link(r.target, r.source);
    directed(outbound, r.source, r.target, EDGE_KIND_LABEL[r.kind]);
    directed(inbound, r.target, r.source, EDGE_KIND_LABEL[r.kind]);
    const corroborated = r.matched || r.feeds.length > 1;
    if (!corroborated && !CORRELATION_EDGES.has(r.kind)) continue;
    for (const [self, other] of [
      [r.source, r.target],
      [r.target, r.source],
    ]) {
      const o = byId.get(other);
      if (!o) continue;
      let list = overlaps.get(self);
      if (!list) overlaps.set(self, (list = []));
      list.push({ otherId: o.id, otherValue: o.value, label: EDGE_KIND_LABEL[r.kind], feeds: r.feeds });
    }
  }

  const index: SignalIndex = new Map();
  for (const e of graph.entities) {
    const near = neighbors.get(e.id);

    let pivot: Zone[] | null = null;
    if (e.isBridge && near) {
      const zones = new Set<Zone>();
      if (e.zone && e.zone !== "unknown") zones.add(e.zone);
      for (const id of near) {
        const z = byId.get(id)?.zone;
        if (z && z !== "unknown") zones.add(z);
      }
      pivot = [...zones];
    }

    let sequence: SequenceInfo | null = null;
    const selfT = ts(e.firstSeen);
    if (!Number.isNaN(selfT) && near) {
      const toLinks = (map: Map<string, string> | undefined): SequenceLink[] => {
        if (!map) return [];
        const out: SequenceLink[] = [];
        for (const [id, label] of map) {
          const n = byId.get(id);
          if (n) out.push({ id, value: n.value, label, firstSeen: n.firstSeen, seenCount: n.seenCount });
        }
        return out.sort((a, b) => {
          const ta = ts(a.firstSeen);
          const tb = ts(b.firstSeen);
          if (Number.isNaN(ta)) return Number.isNaN(tb) ? 0 : 1;
          if (Number.isNaN(tb)) return -1;
          return ta - tb;
        });
      };

      let rank = 1;
      let total = 1;
      for (const id of near) {
        const t = ts(byId.get(id)?.firstSeen);
        if (Number.isNaN(t)) continue;
        total++;
        if (t < selfT) rank++;
      }

      sequence = {
        firstSeen: e.firstSeen,
        lastSeen: e.lastSeen,
        seenCount: e.seenCount,
        rank,
        total,
        connectsTo: toLinks(outbound.get(e.id)),
        connectedFrom: toLinks(inbound.get(e.id)),
      };
    }

    index.set(e.id, {
      match: e.matched || e.feeds.length > 1 ? e.feeds : null,
      overlap: overlaps.get(e.id) ?? null,
      pivot,
      sequence,
    });
  }
  return index;
}

export function hasSignal(s: EntitySignals | undefined, signal: Signal): boolean {
  return !!s && s[signal] !== null;
}

export function signalCounts(index: SignalIndex): Record<Signal, number> {
  const counts: Record<Signal, number> = { match: 0, overlap: 0, pivot: 0, sequence: 0 };
  for (const s of index.values()) for (const k of SIGNAL_ORDER) if (s[k] !== null) counts[k]++;
  return counts;
}

// ---- Certificate-authority noise ------------------------------------------
// CA revocation / issuance hosts (OCSP, CRL, AIA) show up in nearly every
// certificate and TLS dataset. They connect everything to everything, so they
// are hidden unless they are a genuine cross-feed match.
const CA_HOST_PATTERNS: RegExp[] = [
  /^(ocsp\d*|crl\d*)\./,
  /(^|\.)lencr\.org$/,
  /(^|\.)letsencrypt\.org$/,
  /(^|\.)digicert(-cn)?\.com$/,
  /(^|\.)sectigo\.com$/,
  /(^|\.)comodoca\d*\.com$/,
  /(^|\.)usertrust\.com$/,
  /(^|\.)globalsign\.(com|net)$/,
  /(^|\.)godaddy\.com$/,
  /(^|\.)starfieldtech\.com$/,
  /(^|\.)entrust\.net$/,
  /(^|\.)identrust\.com$/,
  /(^|\.)amazontrust\.com$/,
  /(^|\.)pki\.goog$/,
  /(^|\.)geotrust\.com$/,
  /(^|\.)thawte\.com$/,
  /(^|\.)rapidssl\.com$/,
  /(^|\.)symcb\.com$/,
  /(^|\.)symcd\.com$/,
  /(^|\.)verisign\.com$/,
  /(^|\.)buypass\.(com|no)$/,
  /(^|\.)ssl\.com$/,
  /(^|\.)zerossl\.com$/,
  /(^|\.)quovadisglobal\.com$/,
  /(^|\.)certum\.pl$/,
  /^(ocsp|crl)\.(apple|microsoft)\.com$/,
  /(^|\.)pki\.(apple|microsoft)\.com$/,
];

const CA_NAME_PATTERN =
  /\b(let'?s encrypt|digicert|sectigo|comodo|globalsign|godaddy|entrust|identrust|geotrust|thawte|rapidssl|isrg|certificate authority|root ca|issuing ca|intermediate ca)\b/i;

function hostOf(e: Entity): string {
  if (e.kind === "domain") return e.value.toLowerCase();
  if (e.kind === "url") {
    try {
      return new URL(e.value).hostname.toLowerCase();
    } catch {
      return e.value.toLowerCase().replace(/^[a-z]+:\/\//, "").split(/[/:?#]/)[0];
    }
  }
  return "";
}

export function isCertAuthority(e: Entity): boolean {
  const host = hostOf(e);
  if (host && CA_HOST_PATTERNS.some((re) => re.test(host))) return true;
  if (CA_NAME_PATTERN.test(e.value)) return true;
  return !!e.asName && e.kind === "asn" && CA_NAME_PATTERN.test(e.asName);
}

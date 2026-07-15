// ===========================================================================
// Confidence scoring — every edge earns a 0-100 confidence from OBSERVABLE
// strength, never from where an indicator was hosted. Crypto-verifiable
// overlaps (cert, file hash) score highest; single-source speculation lowest.
// Provider co-tenancy is explicitly capped by the safety layer.
// ===========================================================================

import {
  CORRELATION_EDGES,
  EDGE_KIND_LABEL,
  type EdgeExplanation,
  type EdgeKind,
  type Entity,
  type Relationship,
} from "./network-types";
import { detectProvider, providerCaveat } from "./safety";

// Base confidence by edge kind (the "how strong is this KIND of link" prior).
const BASE: Record<EdgeKind, number> = {
  // cryptographically or structurally verifiable
  "shares-cert": 92,
  "shares-hash": 90,
  "signed-by": 88,
  "issued-by": 86,
  "resolves-to": 80,
  hosts: 78,
  "sub-domain-of": 78,
  "shares-device": 76,
  "shares-user": 74,
  "beacons-to": 72,
  executes: 70,
  spawns: 68,
  "belongs-to": 66,
  "shares-ip": 60,
  "downloaded-from": 60,
  "communicates-with": 58,
  "shares-domain": 56,
  "sibling-of": 52,
  "shares-asn": 40, // ASN overlap alone is weak (huge shared networks)
  "shares-infrastructure": 38,
  "repeated-in": 55,
  "related-to": 30,
};

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

export interface ScoreInput {
  kind: EdgeKind;
  feeds: string[]; // feeds that assert / corroborate the edge
  source?: Entity;
  target?: Entity;
  sharedValue?: string; // the concrete overlapping artifact (for evidence text)
  anchor?: boolean; // touches a case seed-anchor
}

export interface ScoreResult {
  confidence: number;
  explanation: EdgeExplanation;
}

// Compute confidence + a full explanation object for one relationship.
export function scoreEdge(input: ScoreInput): ScoreResult {
  const { kind, feeds, source, target, sharedValue, anchor } = input;
  let score = BASE[kind] ?? 30;
  const evidence: string[] = [];

  // Multi-source corroboration raises confidence (diminishing returns).
  const feedCount = new Set(feeds).size;
  if (feedCount >= 2) {
    score += Math.min(18, (feedCount - 1) * 9);
    evidence.push(`Corroborated by ${feedCount} independent feeds.`);
  } else {
    evidence.push(`Asserted by a single source (${feeds[0] ?? "unknown"}).`);
  }

  // The concrete overlapping artifact, when this is a correlation edge.
  if (CORRELATION_EDGES.has(kind) && sharedValue) {
    evidence.push(`Shared artifact: ${sharedValue}.`);
  }

  // Case anchor involvement is a strong prior in this investigation.
  if (anchor) {
    score += 6;
    evidence.push("Involves a case seed-anchor indicator.");
  }

  // Safety cap: if the shared artifact / endpoints are provider-owned infra,
  // co-tenancy must NOT read as attribution — cap and annotate.
  const prov = detectProvider(
    sharedValue,
    source?.asName,
    target?.asName,
    source?.value,
    target?.value,
  );
  let capped = false;
  if (prov.isProvider && (kind === "shares-ip" || kind === "shares-asn" || kind === "shares-infrastructure")) {
    score = Math.min(score, 35);
    capped = true;
    evidence.push(providerCaveat(prov.provider ?? "a major provider"));
  }

  const confidence = clamp(score);

  const why = capped
    ? `${describe(kind)} — but on shared provider infrastructure, so treated as weak evidence.`
    : describe(kind, feedCount);

  const seen = mergeSeen(source, target);

  return {
    confidence,
    explanation: {
      why,
      evidence,
      sources: [...new Set(feeds)],
      firstSeen: seen.firstSeen,
      lastSeen: seen.lastSeen,
    },
  };
}

function describe(kind: EdgeKind, feedCount = 1): string {
  const label = EDGE_KIND_LABEL[kind] ?? kind;
  if (CORRELATION_EDGES.has(kind)) {
    return `Correlated because the endpoints ${label}${feedCount >= 2 ? ", confirmed across feeds" : ""}.`;
  }
  return `Observed relationship: ${label}${feedCount >= 2 ? " (seen in multiple feeds)" : ""}.`;
}

function mergeSeen(a?: Entity, b?: Entity): { firstSeen?: string; lastSeen?: string } {
  const firsts = [a?.firstSeen, b?.firstSeen].filter(Boolean).sort();
  const lasts = [a?.lastSeen, b?.lastSeen].filter(Boolean).sort();
  return { firstSeen: firsts[0], lastSeen: lasts[lasts.length - 1] };
}

// Fill confidence + explanation for observed (feed-asserted) edges that the
// correlation pass didn't already score. Idempotent: skips edges already set.
export function scoreObservedEdges(
  relationships: Relationship[],
  byId: Map<string, Entity>,
): void {
  for (const r of relationships) {
    if (typeof r.confidence === "number" && r.explanation) continue;
    const { confidence, explanation } = scoreEdge({
      kind: r.kind,
      feeds: r.feeds,
      source: byId.get(r.source),
      target: byId.get(r.target),
      anchor: byId.get(r.source)?.isAnchor || byId.get(r.target)?.isAnchor,
    });
    r.confidence = confidence;
    r.explanation = explanation;
  }
}

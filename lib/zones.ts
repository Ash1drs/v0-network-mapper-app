// ===========================================================================
// Environment zone classification + pivot (bridge) detection.
//
// The compromise pivoted from a personal environment into a corporate one, so
// the most important structural fact is which environment each node belongs to
// and — critically — which nodes BRIDGE two environments. Those bridges are the
// pivot points where the attacker jumped from one side to the other.
// ===========================================================================

import type { Entity, ThreatGraph, Zone } from "./network-types";

// Corporate identity + SaaS the compromise touched (extend freely).
const CORPORATE_KEYWORDS = [
  "okta",
  "salesforce",
  "force.com",
  "fedex",
  "microsoftonline",
  "office365",
  "outlook.office",
  "sharepoint",
  "onmicrosoft",
  "azure",
  "workday",
  "servicenow",
  "atlassian",
  "jira",
  "confluence",
  "slack.com",
  "zoom.us",
  "duosecurity",
  "duo.com",
  "pingidentity",
  "onelogin",
  "sailpoint",
  "crowdstrike",
  "proofpoint",
  "mimecast",
  "citrix",
  "vpn",
  "sso",
  "gsuite",
  "googleworkspace",
  "admin.google",
  "box.com",
  "docusign",
  "concur",
  "adp.com",
  "volanosoftware",
  "agp.com",
];

// Consumer / personal services (best-effort; personal is often manual).
const PERSONAL_KEYWORDS = [
  "gmail.com",
  "yahoo.com",
  "icloud.com",
  "me.com",
  "hotmail.com",
  "live.com",
  "aol.com",
  "protonmail",
  "proton.me",
  "comcast.net",
  "verizon.net",
  "att.net",
  "spectrum.net",
  "cox.net",
  "facebook.com",
  "instagram.com",
  "venmo.com",
  "paypal.com",
  "cash.app",
];

// Known-bad / attacker infrastructure signals from this incident.
const ADVERSARY_KEYWORDS = ["symantke", "symantec-", "-okta.", "oktacdn", "phish"];

// Feed names that indicate the source itself is adversary intel.
const ADVERSARY_FEED = /malware|phish|adversary|threat|c2|apt|malicious|ioc/i;

// Classify a single entity when it has no explicit override. Order matters:
// adversary signals win (attacker infra impersonating corporate identity should
// read as adversary, and its edges to real corporate nodes make it a bridge).
export function classifyZone(e: Entity): Zone {
  const v = e.value.toLowerCase();

  if (ADVERSARY_KEYWORDS.some((k) => v.includes(k))) return "adversary";
  if (e.riskScore >= 60) return "adversary";
  if (e.feeds.some((f) => ADVERSARY_FEED.test(f))) return "adversary";

  if (CORPORATE_KEYWORDS.some((k) => v.includes(k))) return "corporate";
  if (PERSONAL_KEYWORDS.some((k) => v.includes(k))) return "personal";

  return "unknown";
}

export type ZoneOverrides = Record<string, Zone>;

// Return a new graph with every entity assigned a zone (override > prior >
// auto-classify), each entity flagged isBridge when it + its direct neighbors
// span >= 2 known zones, and each relationship flagged crossZone.
export function applyZones(graph: ThreatGraph, overrides: ZoneOverrides = {}): ThreatGraph {
  const zoneById = new Map<string, Zone>();
  const zonedEntities: Entity[] = graph.entities.map((e) => {
    const zone = overrides[e.id] ?? e.zone ?? classifyZone(e);
    zoneById.set(e.id, zone);
    return { ...e, zone };
  });

  // Collect the set of known (non-unknown) zones seen at each node's neighbors.
  const neighborZones = new Map<string, Set<Zone>>();
  const note = (id: string, z: Zone | undefined) => {
    if (!z || z === "unknown") return;
    let set = neighborZones.get(id);
    if (!set) neighborZones.set(id, (set = new Set()));
    set.add(z);
  };

  const relationships = graph.relationships.map((r) => {
    const sz = zoneById.get(r.source);
    const tz = zoneById.get(r.target);
    note(r.source, tz);
    note(r.target, sz);
    const crossZone =
      !!sz && !!tz && sz !== "unknown" && tz !== "unknown" && sz !== tz;
    return { ...r, crossZone };
  });

  // A pivot is a node whose direct neighbors span >= 2 different known zones.
  // (Using neighbor diversity rather than "touches another zone" keeps leaf
  // nodes from being flagged — only genuine crossover nodes light up.)
  const entities = zonedEntities.map((e) => ({
    ...e,
    isBridge: (neighborZones.get(e.id)?.size ?? 0) >= 2,
  }));

  return { entities, relationships };
}

export function zoneCounts(entities: Entity[]): Record<Zone, number> {
  const counts: Record<Zone, number> = {
    personal: 0,
    corporate: 0,
    adversary: 0,
    unknown: 0,
  };
  for (const e of entities) counts[e.zone ?? "unknown"]++;
  return counts;
}

export function bridgeCount(entities: Entity[]): number {
  return entities.filter((e) => e.isBridge).length;
}

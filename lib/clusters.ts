// ===========================================================================
// "Explain This Cluster" — connected-component detection over the graph plus
// an auto-generated, plain-language narrative for each component. Narratives
// end with the safety disclaimer so overlap is never read as attribution.
// ===========================================================================

import {
  categoryOf,
  CATEGORY_LABEL,
  ENTITY_KIND_LABEL,
  type Category,
  type Entity,
  type Relationship,
  type ThreatGraph,
} from "./network-types";
import { SAFETY_DISCLAIMER } from "./safety";

export interface Cluster {
  id: number;
  entityIds: string[];
  entities: Entity[];
  relationships: Relationship[];
  size: number;
  edgeCount: number;
  categories: Record<Category, number>;
  feeds: string[];
  matchedCount: number;
  anchorCount: number;
  bridgeCount: number;
  avgConfidence: number;
  maxRisk: number;
  topEntities: Entity[]; // by degree
  narrative: string;
}

// Union-find over relationships → connected components.
export function detectClusters(graph: ThreatGraph): Cluster[] {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let p = parent.get(x) ?? x;
    if (p !== x) {
      p = find(p);
      parent.set(x, p);
    }
    return p;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  for (const e of graph.entities) if (!parent.has(e.id)) parent.set(e.id, e.id);
  for (const r of graph.relationships) {
    if (!parent.has(r.source)) parent.set(r.source, r.source);
    if (!parent.has(r.target)) parent.set(r.target, r.target);
    union(r.source, r.target);
  }

  const byRoot = new Map<string, string[]>();
  for (const e of graph.entities) {
    const root = find(e.id);
    const list = byRoot.get(root) ?? [];
    list.push(e.id);
    byRoot.set(root, list);
  }

  const entityById = new Map(graph.entities.map((e) => [e.id, e]));
  const degree = new Map<string, number>();
  for (const r of graph.relationships) {
    degree.set(r.source, (degree.get(r.source) || 0) + 1);
    degree.set(r.target, (degree.get(r.target) || 0) + 1);
  }

  const clusters: Cluster[] = [];
  let id = 0;
  for (const [, ids] of byRoot) {
    const idSet = new Set(ids);
    const entities = ids.map((i) => entityById.get(i)!).filter(Boolean);
    const relationships = graph.relationships.filter(
      (r) => idSet.has(r.source) && idSet.has(r.target),
    );

    const categories = {
      infrastructure: 0,
      domain: 0,
      organization: 0,
      certificate: 0,
      malware: 0,
      device: 0,
      user: 0,
      unknown: 0,
    } as Record<Category, number>;
    for (const e of entities) categories[categoryOf(e)]++;

    const feeds = [...new Set(entities.flatMap((e) => e.feeds))];
    const matchedCount = entities.filter((e) => e.matched).length;
    const anchorCount = entities.filter((e) => e.isAnchor).length;
    const bridgeCount = entities.filter((e) => e.isBridge).length;
    const confs = relationships.map((r) => r.confidence ?? 0);
    const avgConfidence = confs.length
      ? Math.round(confs.reduce((a, b) => a + b, 0) / confs.length)
      : 0;
    const maxRisk = entities.reduce((m, e) => Math.max(m, e.riskScore), 0);
    const topEntities = [...entities]
      .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))
      .slice(0, 5);

    clusters.push({
      id: id++,
      entityIds: ids,
      entities,
      relationships,
      size: entities.length,
      edgeCount: relationships.length,
      categories,
      feeds,
      matchedCount,
      anchorCount,
      bridgeCount,
      avgConfidence,
      maxRisk,
      topEntities,
      narrative: "",
    });
  }

  // Largest / most significant first.
  clusters.sort((a, b) => {
    if (b.anchorCount !== a.anchorCount) return b.anchorCount - a.anchorCount;
    if (b.size !== a.size) return b.size - a.size;
    return b.edgeCount - a.edgeCount;
  });
  clusters.forEach((c, i) => {
    c.id = i;
    c.narrative = buildNarrative(c);
  });

  return clusters;
}

function buildNarrative(c: Cluster): string {
  if (c.size <= 1) {
    const e = c.entities[0];
    return e
      ? `Isolated ${ENTITY_KIND_LABEL[e.kind].toLowerCase()} ${e.value} with no observed links yet. ${SAFETY_DISCLAIMER}`
      : `Empty cluster. ${SAFETY_DISCLAIMER}`;
  }

  const cats = (Object.entries(c.categories) as [Category, number][])
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, n]) => `${n} ${CATEGORY_LABEL[cat].toLowerCase()}`);

  const parts: string[] = [];
  parts.push(
    `This cluster links ${c.size} indicators through ${c.edgeCount} relationships (${cats.join(", ")}).`,
  );

  if (c.topEntities.length) {
    parts.push(
      `Central artifacts: ${c.topEntities.map((e) => e.value).slice(0, 3).join(", ")}.`,
    );
  }
  if (c.feeds.length > 1) {
    parts.push(`Evidence spans ${c.feeds.length} feeds (${c.feeds.join(", ")}), and ${c.matchedCount} indicators appear in more than one.`);
  } else {
    parts.push(`All evidence comes from a single feed (${c.feeds[0] ?? "unknown"}).`);
  }
  if (c.anchorCount > 0) {
    parts.push(`${c.anchorCount} case seed-anchor indicator${c.anchorCount > 1 ? "s" : ""} sit inside this cluster, making it directly relevant to the investigation.`);
  }
  if (c.bridgeCount > 0) {
    parts.push(`${c.bridgeCount} node${c.bridgeCount > 1 ? "s" : ""} bridge more than one environment (pivot points).`);
  }
  parts.push(`Aggregate edge confidence is ${c.avgConfidence}/100; peak indicator risk is ${c.maxRisk}/100.`);
  parts.push(SAFETY_DISCLAIMER);

  return parts.join(" ");
}

// ===========================================================================
// Timeline engine — turns first/last-seen observations into a chronological
// story: when infrastructure appeared, dormancy gaps, and change events
// (infrastructure migration, certificate rotation, ASN/ownership change).
// Feeds the report + a timeline strip in the UI.
// ===========================================================================

import {
  categoryOf,
  ENTITY_KIND_LABEL,
  type Entity,
  type Relationship,
  type ThreatGraph,
} from "./network-types";

export interface TimelineEvent {
  date: string; // ISO-ish string as observed
  ts: number; // parsed epoch ms (for sorting)
  entityId: string;
  value: string;
  kind: string;
  category: string;
  type: "first-seen" | "last-seen" | "burst" | "dormancy" | "rotation";
  detail: string;
}

export interface TimelineSummary {
  events: TimelineEvent[];
  earliest?: string;
  latest?: string;
  spanDays: number;
  observedCount: number; // entities carrying any timestamp
}

function parseTs(s?: string): number | null {
  if (!s) return null;
  const t = Date.parse(s);
  if (!Number.isNaN(t)) return t;
  // epoch seconds?
  const n = Number(s);
  if (Number.isFinite(n) && n > 1_000_000_000 && n < 10_000_000_000) return n * 1000;
  return null;
}

const DAY = 86_400_000;

export function buildTimeline(graph: ThreatGraph): TimelineSummary {
  const events: TimelineEvent[] = [];
  let earliestTs = Infinity;
  let latestTs = -Infinity;
  let observedCount = 0;

  for (const e of graph.entities) {
    const first = parseTs(e.firstSeen);
    const last = parseTs(e.lastSeen);
    if (first == null && last == null) continue;
    observedCount++;

    const base = {
      entityId: e.id,
      value: e.value,
      kind: ENTITY_KIND_LABEL[e.kind],
      category: categoryOf(e),
    };

    if (first != null) {
      earliestTs = Math.min(earliestTs, first);
      latestTs = Math.max(latestTs, first);
      events.push({
        ...base,
        date: e.firstSeen!,
        ts: first,
        type: "first-seen",
        detail: `${base.kind} ${e.value} first observed.`,
      });
    }
    if (last != null && last !== first) {
      earliestTs = Math.min(earliestTs, last);
      latestTs = Math.max(latestTs, last);
      events.push({
        ...base,
        date: e.lastSeen!,
        ts: last,
        type: "last-seen",
        detail: `${base.kind} ${e.value} last observed.`,
      });
      // Long active windows with a late last-seen read as sustained activity.
      if (first != null && last - first > 180 * DAY) {
        events.push({
          ...base,
          date: e.lastSeen!,
          ts: last,
          type: "dormancy",
          detail: `${e.value} stayed active across ${Math.round((last - first) / DAY)} days — long-lived infrastructure.`,
        });
      }
    }
  }

  // Rotation detection: infrastructure sharing a resolves-to/hosts target but
  // with distinct first-seen dates suggests the operator rotated infra.
  detectRotation(graph, events);

  // Burst detection: 3+ first-seen events within a 3-day window.
  detectBursts(events);

  events.sort((a, b) => a.ts - b.ts);

  const hasSpan = Number.isFinite(earliestTs) && Number.isFinite(latestTs);
  return {
    events,
    earliest: hasSpan ? new Date(earliestTs).toISOString().slice(0, 10) : undefined,
    latest: hasSpan ? new Date(latestTs).toISOString().slice(0, 10) : undefined,
    spanDays: hasSpan ? Math.round((latestTs - earliestTs) / DAY) : 0,
    observedCount,
  };
}

function detectRotation(graph: ThreatGraph, events: TimelineEvent[]) {
  const byId = new Map(graph.entities.map((e) => [e.id, e]));
  // group sources that point at a common target via resolves-to / hosts
  const targetSources = new Map<string, Relationship[]>();
  for (const r of graph.relationships) {
    if (r.kind === "resolves-to" || r.kind === "hosts") {
      const list = targetSources.get(r.target) ?? [];
      list.push(r);
      targetSources.set(r.target, list);
    }
  }
  for (const [target, rels] of targetSources) {
    if (rels.length < 2) continue;
    const dates = rels
      .map((r) => byId.get(r.source))
      .filter((e): e is Entity => !!e)
      .map((e) => ({ e, ts: parseTs(e.firstSeen) }))
      .filter((x) => x.ts != null) as { e: Entity; ts: number }[];
    if (dates.length < 2) continue;
    dates.sort((a, b) => a.ts - b.ts);
    if (dates[dates.length - 1].ts - dates[0].ts > 7 * DAY) {
      const t = byId.get(target);
      const last = dates[dates.length - 1];
      events.push({
        entityId: last.e.id,
        value: last.e.value,
        kind: ENTITY_KIND_LABEL[last.e.kind],
        category: categoryOf(last.e),
        date: last.e.firstSeen!,
        ts: last.ts,
        type: "rotation",
        detail: `${dates.length} distinct sources reached ${t?.value ?? target} over time — likely infrastructure rotation.`,
      });
    }
  }
}

function detectBursts(events: TimelineEvent[]) {
  const firsts = events.filter((e) => e.type === "first-seen").sort((a, b) => a.ts - b.ts);
  const WINDOW = 3 * DAY;
  let i = 0;
  while (i < firsts.length) {
    let j = i;
    while (j < firsts.length && firsts[j].ts - firsts[i].ts <= WINDOW) j++;
    const count = j - i;
    if (count >= 3) {
      const anchor = firsts[i];
      events.push({
        ...anchor,
        type: "burst",
        detail: `${count} new indicators appeared within ~3 days — a burst of activity.`,
      });
      i = j;
    } else {
      i++;
    }
  }
}

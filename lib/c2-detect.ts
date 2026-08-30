import type { AsnGroup } from "@/lib/network-types";

// A detected command-and-control beacon channel: a domain that resolves to an
// IP with a regular, automated-looking callback cadence.
export interface C2Channel {
  id: string;
  domain: string;
  ip: string;
  asn: string;
  asName: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  spanMs: number;
  intervalMs: number;
  cadenceLabel: string;
  beaconScore: number; // 0-100 confidence
  tier: "high" | "medium" | "low";
  riskScore: number;
  color: string;
}

export interface C2DetectOptions {
  minHits?: number; // minimum callbacks to consider a beacon
  minScore?: number; // confidence threshold to surface a channel
}

const DEFAULTS = {
  minHits: 4,
  minScore: 45,
};

// Classic automated beacon cadence band: ~1 minute to ~24 hours between
// callbacks. Faster than a minute reads as noise; slower than a day is a
// weaker (but still possible) slow beacon.
const FAST_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;

export function formatInterval(ms: number): string {
  const s = ms / 1000;
  if (s < 90) return `every ~${Math.round(s)}s`;
  const m = s / 60;
  if (m < 90) return `every ~${Math.round(m)}m`;
  const h = m / 60;
  if (h < 36) return `every ~${h < 10 ? h.toFixed(1) : Math.round(h)}h`;
  const d = h / 24;
  return `every ~${d < 10 ? d.toFixed(1) : Math.round(d)}d`;
}

export function formatSpan(ms: number): string {
  const d = ms / DAY_MS;
  if (d >= 1) return `${d < 10 ? d.toFixed(1) : Math.round(d)}d window`;
  const h = ms / (60 * 60 * 1000);
  if (h >= 1) return `${Math.round(h)}h window`;
  const m = ms / (60 * 1000);
  return `${Math.round(m)}m window`;
}

// Score how "beacon-like" a domain->IP pair is, given the coarse
// first_seen/last_seen/count signal available in passive DNS data.
function scoreBeacon(count: number, spanMs: number, risk: number): { score: number; intervalMs: number } {
  if (count < 2 || spanMs <= 0) return { score: 0, intervalMs: 0 };

  const intervalMs = spanMs / (count - 1);

  // Cadence band: reward intervals that fall in the automated check-in range.
  let cadence: number;
  if (intervalMs >= FAST_MS && intervalMs <= DAY_MS) cadence = 1;
  else if (intervalMs > DAY_MS && intervalMs <= WEEK_MS) cadence = 0.5;
  else if (intervalMs < FAST_MS) cadence = 0.4;
  else cadence = 0.1;

  // More callbacks = more confidence it is a sustained channel (log scale).
  const hits = Math.min(1, Math.log10(count) / 2); // count 100 -> 1.0

  // Longer observation window = more periods observed = stronger signal.
  const spanDays = spanMs / DAY_MS;
  const span = Math.min(1, spanDays / 7); // a week -> 1.0

  const risk01 = Math.min(1, Math.max(0, risk / 100));

  const score = Math.round(
    100 * (0.45 * cadence + 0.25 * hits + 0.15 * span + 0.15 * risk01)
  );

  return { score, intervalMs };
}

export function detectC2Channels(groups: AsnGroup[], opts: C2DetectOptions = {}): C2Channel[] {
  const minHits = opts.minHits ?? DEFAULTS.minHits;
  const minScore = opts.minScore ?? DEFAULTS.minScore;

  const channels: C2Channel[] = [];

  for (const group of groups) {
    // Aggregate records per domain->IP pair in case the same pair appears
    // more than once in the upload.
    const pairs = new Map<
      string,
      { domain: string; ip: string; count: number; first: number; last: number; risk: number }
    >();

    for (const r of group.records) {
      if (!r.query || !r.answer) continue;
      const key = `${r.query}|${r.answer}`;
      const first = r.first_seen ? new Date(r.first_seen).getTime() : NaN;
      const last = r.last_seen ? new Date(r.last_seen).getTime() : NaN;
      if (Number.isNaN(first) || Number.isNaN(last)) continue;
      const risk = Math.max(r.answer_risk_score || 0, r.query_risk_score || 0);

      const existing = pairs.get(key);
      if (existing) {
        existing.count += r.count || 1;
        existing.first = Math.min(existing.first, first);
        existing.last = Math.max(existing.last, last);
        existing.risk = Math.max(existing.risk, risk);
      } else {
        pairs.set(key, { domain: r.query, ip: r.answer, count: r.count || 1, first, last, risk });
      }
    }

    for (const [key, p] of pairs) {
      if (p.count < minHits) continue;
      const spanMs = p.last - p.first;
      const { score, intervalMs } = scoreBeacon(p.count, spanMs, p.risk);
      if (score < minScore) continue;

      channels.push({
        id: `${group.asn}:${key}`,
        domain: p.domain,
        ip: p.ip,
        asn: group.asn,
        asName: group.asName,
        count: p.count,
        firstSeen: new Date(p.first).toISOString(),
        lastSeen: new Date(p.last).toISOString(),
        spanMs,
        intervalMs,
        cadenceLabel: formatInterval(intervalMs),
        beaconScore: score,
        tier: score >= 70 ? "high" : score >= 55 ? "medium" : "low",
        riskScore: p.risk,
        color: group.color,
      });
    }
  }

  channels.sort((a, b) => b.beaconScore - a.beaconScore);
  return channels;
}

// Convenience sets for the graph overlay.
export function c2OverlaySets(channels: C2Channel[]): {
  c2Ips: Set<string>;
  c2Pairs: Set<string>;
} {
  const c2Ips = new Set<string>();
  const c2Pairs = new Set<string>();
  for (const c of channels) {
    c2Ips.add(c.ip);
    c2Pairs.add(`${c.domain}|${c.ip}`);
  }
  return { c2Ips, c2Pairs };
}

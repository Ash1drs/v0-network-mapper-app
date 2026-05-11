"use client";

import { useMemo, useState } from "react";
import {
  BarChart3,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  AlertTriangle,
  Server,
  Globe,
  Hash,
} from "lucide-react";
import type { AsnGroup, DnsRecord } from "@/lib/network-types";

interface StatsDashboardProps {
  groups: AsnGroup[];
  allRecords: DnsRecord[];
}

function riskColor(score: number): string {
  if (score >= 70) return "#f87171";
  if (score >= 40) return "#fbbf24";
  if (score >= 20) return "#38bdf8";
  return "#4ade80";
}

export function StatsDashboard({ groups, allRecords }: StatsDashboardProps) {
  const [expanded, setExpanded] = useState(false);

  const stats = useMemo(() => {
    if (groups.length === 0 || allRecords.length === 0) return null;

    // Risk distribution
    const riskBuckets = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of allRecords) {
      const maxRisk = Math.max(r.query_risk_score, r.answer_risk_score);
      if (maxRisk >= 70) riskBuckets.critical++;
      else if (maxRisk >= 40) riskBuckets.high++;
      else if (maxRisk >= 20) riskBuckets.medium++;
      else riskBuckets.low++;
    }

    // Top ASNs by IP count
    const topAsnsByIps = [...groups]
      .sort((a, b) => b.ips.length - a.ips.length)
      .slice(0, 5);

    // Top ASNs by risk
    const topAsnsByRisk = [...groups]
      .sort((a, b) => b.maxRiskScore - a.maxRiskScore)
      .slice(0, 5);

    // Most observed records
    const topByCount = [...allRecords]
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Timeline stats
    const dates = allRecords
      .flatMap((r) => [r.first_seen, r.last_seen])
      .filter((d) => d)
      .map((d) => new Date(d).getTime())
      .filter((t) => !isNaN(t));
    const minDate = dates.length > 0 ? new Date(Math.min(...dates)) : null;
    const maxDate = dates.length > 0 ? new Date(Math.max(...dates)) : null;

    // Total observations
    const totalObservations = allRecords.reduce((sum, r) => sum + r.count, 0);

    return {
      riskBuckets,
      topAsnsByIps,
      topAsnsByRisk,
      topByCount,
      minDate,
      maxDate,
      totalObservations,
      uniqueIps: new Set(allRecords.map((r) => r.answer)).size,
      uniqueDomains: new Set(allRecords.map((r) => r.query)).size,
    };
  }, [groups, allRecords]);

  if (!stats) return null;

  const riskTotal =
    stats.riskBuckets.critical +
    stats.riskBuckets.high +
    stats.riskBuckets.medium +
    stats.riskBuckets.low;

  return (
    <div className="flex flex-col gap-3">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between min-h-[44px] text-left"
      >
        <div className="flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold text-foreground">
            Statistics
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        )}
      </button>

      {expanded && (
        <div className="flex flex-col gap-4 rounded-lg border border-border bg-secondary/30 p-3">
          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 gap-2">
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-2">
              <Server className="h-4 w-4 text-primary shrink-0" />
              <div>
                <div className="text-sm font-bold font-mono text-foreground">
                  {stats.uniqueIps}
                </div>
                <div className="text-xs text-muted-foreground">Unique IPs</div>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-2">
              <Globe className="h-4 w-4 text-primary shrink-0" />
              <div>
                <div className="text-sm font-bold font-mono text-foreground">
                  {stats.uniqueDomains}
                </div>
                <div className="text-xs text-muted-foreground">Domains</div>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-2">
              <Hash className="h-4 w-4 text-primary shrink-0" />
              <div>
                <div className="text-sm font-bold font-mono text-foreground">
                  {stats.totalObservations.toLocaleString()}
                </div>
                <div className="text-xs text-muted-foreground">Observations</div>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-border bg-card p-2">
              <TrendingUp className="h-4 w-4 text-primary shrink-0" />
              <div>
                <div className="text-sm font-bold font-mono text-foreground">
                  {groups.length}
                </div>
                <div className="text-xs text-muted-foreground">ASN/Orgs</div>
              </div>
            </div>
          </div>

          {/* Risk Distribution */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-xs font-medium text-muted-foreground">
                Risk Distribution
              </span>
            </div>
            <div className="flex h-6 w-full overflow-hidden rounded-md">
              {stats.riskBuckets.critical > 0 && (
                <div
                  className="flex items-center justify-center text-xs font-bold"
                  style={{
                    width: `${(stats.riskBuckets.critical / riskTotal) * 100}%`,
                    backgroundColor: "#f87171",
                    color: "#1a1a2e",
                  }}
                  title={`Critical: ${stats.riskBuckets.critical}`}
                >
                  {stats.riskBuckets.critical > riskTotal * 0.1
                    ? stats.riskBuckets.critical
                    : ""}
                </div>
              )}
              {stats.riskBuckets.high > 0 && (
                <div
                  className="flex items-center justify-center text-xs font-bold"
                  style={{
                    width: `${(stats.riskBuckets.high / riskTotal) * 100}%`,
                    backgroundColor: "#fbbf24",
                    color: "#1a1a2e",
                  }}
                  title={`High: ${stats.riskBuckets.high}`}
                >
                  {stats.riskBuckets.high > riskTotal * 0.1
                    ? stats.riskBuckets.high
                    : ""}
                </div>
              )}
              {stats.riskBuckets.medium > 0 && (
                <div
                  className="flex items-center justify-center text-xs font-bold"
                  style={{
                    width: `${(stats.riskBuckets.medium / riskTotal) * 100}%`,
                    backgroundColor: "#38bdf8",
                    color: "#1a1a2e",
                  }}
                  title={`Medium: ${stats.riskBuckets.medium}`}
                >
                  {stats.riskBuckets.medium > riskTotal * 0.1
                    ? stats.riskBuckets.medium
                    : ""}
                </div>
              )}
              {stats.riskBuckets.low > 0 && (
                <div
                  className="flex items-center justify-center text-xs font-bold"
                  style={{
                    width: `${(stats.riskBuckets.low / riskTotal) * 100}%`,
                    backgroundColor: "#4ade80",
                    color: "#1a1a2e",
                  }}
                  title={`Low: ${stats.riskBuckets.low}`}
                >
                  {stats.riskBuckets.low > riskTotal * 0.1
                    ? stats.riskBuckets.low
                    : ""}
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="flex items-center gap-1">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: "#f87171" }}
                />
                <span className="text-muted-foreground">
                  Critical: {stats.riskBuckets.critical}
                </span>
              </span>
              <span className="flex items-center gap-1">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: "#fbbf24" }}
                />
                <span className="text-muted-foreground">
                  High: {stats.riskBuckets.high}
                </span>
              </span>
              <span className="flex items-center gap-1">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: "#38bdf8" }}
                />
                <span className="text-muted-foreground">
                  Medium: {stats.riskBuckets.medium}
                </span>
              </span>
              <span className="flex items-center gap-1">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: "#4ade80" }}
                />
                <span className="text-muted-foreground">
                  Low: {stats.riskBuckets.low}
                </span>
              </span>
            </div>
          </div>

          {/* Top ASNs by IPs */}
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              Top ASNs by IP Count
            </span>
            <div className="flex flex-col gap-1">
              {stats.topAsnsByIps.map((group) => (
                <div
                  key={group.asn}
                  className="flex items-center gap-2 text-xs"
                >
                  <span
                    className="h-2 w-2 rounded-full shrink-0"
                    style={{ backgroundColor: group.color }}
                  />
                  <span className="flex-1 truncate font-mono text-foreground">
                    AS{group.asn}
                  </span>
                  <span className="font-mono text-muted-foreground">
                    {group.ips.length} IPs
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Top ASNs by Risk */}
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              Highest Risk ASNs
            </span>
            <div className="flex flex-col gap-1">
              {stats.topAsnsByRisk.map((group) => (
                <div
                  key={group.asn}
                  className="flex items-center gap-2 text-xs"
                >
                  <span
                    className="h-2 w-2 rounded-full shrink-0"
                    style={{ backgroundColor: riskColor(group.maxRiskScore) }}
                  />
                  <span className="flex-1 truncate font-mono text-foreground">
                    AS{group.asn}
                  </span>
                  <span
                    className="font-mono font-bold"
                    style={{ color: riskColor(group.maxRiskScore) }}
                  >
                    {group.maxRiskScore}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Most Observed Records */}
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              Most Observed Records
            </span>
            <div className="flex flex-col gap-1">
              {stats.topByCount.map((record, i) => (
                <div
                  key={`${record.query}-${record.answer}-${i}`}
                  className="flex items-center gap-2 text-xs"
                >
                  <span className="flex-1 truncate font-mono text-foreground">
                    {record.query}
                  </span>
                  <span className="font-mono text-muted-foreground">
                    {record.count.toLocaleString()}x
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Time Range */}
          {stats.minDate && stats.maxDate && (
            <div className="flex flex-col gap-1 rounded-md border border-border bg-card p-2">
              <span className="text-xs font-medium text-muted-foreground">
                Observation Period
              </span>
              <span className="font-mono text-xs text-foreground">
                {stats.minDate.toLocaleDateString()} -{" "}
                {stats.maxDate.toLocaleDateString()}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

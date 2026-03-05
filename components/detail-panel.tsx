"use client";

import type { AsnGroup, DnsRecord } from "@/lib/network-types";
import {
  Globe,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Clock,
  Hash,
  X,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";

function riskColor(score: number): string {
  if (score >= 70) return "#f87171"; // red
  if (score >= 40) return "#fbbf24"; // amber
  if (score >= 20) return "#38bdf8"; // sky
  return "#4ade80"; // green
}

function RiskBadge({ score, label }: { score: number; label: string }) {
  const color = riskColor(score);
  return (
    <div className="flex items-center gap-1.5">
      {score >= 70 ? (
        <ShieldAlert className="h-3.5 w-3.5" style={{ color }} />
      ) : score >= 40 ? (
        <Shield className="h-3.5 w-3.5" style={{ color }} />
      ) : (
        <ShieldCheck className="h-3.5 w-3.5" style={{ color }} />
      )}
      <span className="text-xs text-muted-foreground">{label}</span>
      <span
        className="rounded-full px-1.5 py-0.5 text-xs font-mono font-bold"
        style={{ backgroundColor: color + "20", color }}
      >
        {score}
      </span>
    </div>
  );
}

function RecordRow({ record }: { record: DnsRecord }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-b border-border/50 last:border-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-2 py-2 text-left min-h-[44px] hover:bg-secondary/30 transition-colors"
      >
        {open ? (
          <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
        )}
        <span className="flex-1 truncate text-xs font-mono text-foreground">
          {record.query}
        </span>
        <span
          className="shrink-0 rounded px-1 py-0.5 text-xs font-mono"
          style={{
            backgroundColor: riskColor(record.query_risk_score) + "20",
            color: riskColor(record.query_risk_score),
          }}
        >
          {record.query_risk_score}
        </span>
      </button>
      {open && (
        <div className="flex flex-col gap-1 bg-secondary/20 px-4 py-2 text-xs">
          <div className="flex items-center gap-2">
            <Globe className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Answer:</span>
            <span className="font-mono text-foreground">{record.answer}</span>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Answer risk:</span>
            <span className="font-mono" style={{ color: riskColor(record.answer_risk_score) }}>
              {record.answer_risk_score}
            </span>
            <span className="text-muted-foreground/70">({record.answer_risk_score_decider})</span>
          </div>
          <div className="flex items-center gap-2">
            <Hash className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Seen:</span>
            <span className="font-mono text-foreground">{record.count.toLocaleString()}x</span>
          </div>
          <div className="flex items-center gap-2">
            <Clock className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">First:</span>
            <span className="font-mono text-foreground">{record.first_seen}</span>
          </div>
          <div className="flex items-center gap-2">
            <Clock className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Last:</span>
            <span className="font-mono text-foreground">{record.last_seen}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Risk decider:</span>
            <span className="font-mono text-muted-foreground/80">{record.query_risk_score_decider}</span>
          </div>
        </div>
      )}
    </div>
  );
}

interface DetailPanelProps {
  selectedGroup: AsnGroup | null;
  groups: AsnGroup[];
  onSelectGroup: (group: AsnGroup | null) => void;
}

export function DetailPanel({ selectedGroup, groups, onSelectGroup }: DetailPanelProps) {
  if (selectedGroup) {
    return (
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">ASN Details</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => onSelectGroup(null)}
            className="h-8 w-8 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
            <span className="sr-only">Close</span>
          </Button>
        </div>
        <div className="rounded-lg border border-border bg-secondary/30 p-3">
          <div className="flex items-center gap-2 mb-2">
            <span
              className="inline-block h-3 w-3 rounded-full shrink-0"
              style={{ backgroundColor: selectedGroup.color }}
            />
            <span className="text-sm font-bold text-foreground truncate">
              {selectedGroup.asName}
            </span>
          </div>
          <div className="flex items-center gap-2 mb-3">
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-xs font-mono text-muted-foreground">
              AS{selectedGroup.asn}
            </span>
          </div>

          <div className="flex flex-col gap-2 mb-3">
            <RiskBadge score={selectedGroup.maxRiskScore} label="Max Risk" />
            <RiskBadge score={selectedGroup.avgRiskScore} label="Avg Risk" />
          </div>

          <div className="flex flex-wrap gap-1 mb-3">
            <span className="text-xs text-muted-foreground w-full mb-1">
              {selectedGroup.ips.length} IP{selectedGroup.ips.length !== 1 ? "s" : ""}:
            </span>
            {selectedGroup.ips.slice(0, 20).map((ip) => (
              <span
                key={ip}
                className="inline-block rounded-md border px-1.5 py-0.5 font-mono text-xs"
                style={{
                  borderColor: selectedGroup.color + "50",
                  color: selectedGroup.color,
                  backgroundColor: selectedGroup.color + "10",
                }}
              >
                {ip}
              </span>
            ))}
            {selectedGroup.ips.length > 20 && (
              <span className="text-xs text-muted-foreground">
                +{selectedGroup.ips.length - 20} more
              </span>
            )}
          </div>

          <div className="text-xs text-muted-foreground mb-2">
            {selectedGroup.records.length} DNS records:
          </div>
          <div className="max-h-[40vh] overflow-y-auto rounded-md border border-border bg-card">
            {selectedGroup.records.slice(0, 50).map((r, i) => (
              <RecordRow key={`${r.query}-${r.answer}-${i}`} record={r} />
            ))}
            {selectedGroup.records.length > 50 && (
              <div className="px-3 py-2 text-xs text-muted-foreground text-center">
                +{selectedGroup.records.length - 50} more records
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (groups.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">
          Infrastructure Groups
        </h2>
        <p className="text-xs text-muted-foreground">
          Upload DNS/threat intel data to see ASN groupings, risk scores, and domain-to-IP mappings.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-foreground">
        Infrastructure Groups
        <span className="ml-2 text-xs font-normal text-muted-foreground">
          ({groups.length} ASN{groups.length !== 1 ? "s" : ""})
        </span>
      </h2>
      <div className="flex flex-col gap-2 max-h-[50vh] overflow-y-auto">
        {groups.map((group) => (
          <button
            key={group.asn}
            type="button"
            onClick={() => onSelectGroup(group)}
            className="rounded-lg border border-border bg-secondary/30 p-3 text-left hover:bg-secondary/50 transition-colors min-h-[44px]"
          >
            <div className="flex items-center gap-2 mb-1">
              <span
                className="inline-block h-3 w-3 rounded-full shrink-0"
                style={{ backgroundColor: group.color }}
              />
              <span className="text-sm font-semibold text-foreground truncate flex-1">
                {group.asName}
              </span>
              <span
                className="shrink-0 rounded-full px-1.5 py-0.5 text-xs font-mono font-bold"
                style={{
                  backgroundColor: riskColor(group.maxRiskScore) + "20",
                  color: riskColor(group.maxRiskScore),
                }}
              >
                {group.maxRiskScore}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono">
              <span>AS{group.asn}</span>
              <span>{group.ips.length} IP{group.ips.length !== 1 ? "s" : ""}</span>
              <span>{group.domains.length} domain{group.domains.length !== 1 ? "s" : ""}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

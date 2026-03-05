"use client";

import { useState } from "react";
import { NetworkGraph } from "@/components/network-graph";
import { UploadPanel } from "@/components/ip-input-panel";
import { DetailPanel } from "@/components/detail-panel";
import type { DnsRecord, AsnGroup } from "@/lib/network-types";
import { Activity, ChevronDown, ChevronUp } from "lucide-react";

interface AnalysisStats {
  totalRecords: number;
  uniqueIps: number;
  uniqueDomains: number;
  uniqueAsns: number;
}

export default function Page() {
  const [groups, setGroups] = useState<AsnGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<AsnGroup | null>(null);
  const [stats, setStats] = useState<AnalysisStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);

  const handleAnalyze = async (records: DnsRecord[]) => {
    if (records.length === 0) {
      setGroups([]);
      setSelectedGroup(null);
      setStats(null);
      setError(null);
      return;
    }

    setIsLoading(true);
    setError(null);
    setSelectedGroup(null);

    try {
      const res = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ records }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Analysis failed");
        return;
      }
      setGroups(data.groups);
      setStats({
        totalRecords: data.totalRecords,
        uniqueIps: data.uniqueIps,
        uniqueDomains: data.uniqueDomains,
        uniqueAsns: data.uniqueAsns,
      });
    } catch {
      setError("Failed to analyze data");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="flex min-h-dvh flex-col bg-background">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2.5">
          <Activity className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-bold tracking-tight text-foreground font-mono">
            NetMap
          </h1>
        </div>
        <span className="text-xs font-mono text-muted-foreground hidden sm:inline">
          Infrastructure Intelligence Mapper
        </span>
      </header>

      <div className="flex flex-1 flex-col lg:flex-row">
        {/* Sidebar */}
        <aside className="flex flex-col border-b border-border lg:border-b-0 lg:border-r lg:w-80 xl:w-96">
          <button
            type="button"
            onClick={() => setPanelOpen(!panelOpen)}
            className="flex items-center justify-between px-4 py-3 lg:hidden min-h-[44px]"
          >
            <span className="text-sm font-semibold text-foreground">
              Controls
            </span>
            {panelOpen ? (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            )}
          </button>

          <div
            className={`flex flex-col gap-6 overflow-y-auto px-4 pb-4 lg:py-4 ${
              panelOpen ? "block" : "hidden lg:block"
            }`}
          >
            <UploadPanel
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              stats={stats}
            />

            {error && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}

            <DetailPanel
              selectedGroup={selectedGroup}
              groups={groups}
              onSelectGroup={setSelectedGroup}
            />
          </div>
        </aside>

        {/* Graph Area */}
        <section className="flex flex-1 flex-col p-3 lg:p-4 min-h-[350px] lg:min-h-0">
          <NetworkGraph groups={groups} onSelectGroup={setSelectedGroup} />
        </section>
      </div>
    </main>
  );
}

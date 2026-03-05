"use client";

import { useState, useCallback } from "react";
import { NetworkGraph } from "@/components/network-graph";
import { IpInputPanel } from "@/components/ip-input-panel";
import { DetailPanel } from "@/components/detail-panel";
import type { LookupResult, NetworkGroup } from "@/lib/network-types";
import { Activity, ChevronDown, ChevronUp } from "lucide-react";

export default function Page() {
  const [results, setResults] = useState<LookupResult[]>([]);
  const [groups, setGroups] = useState<NetworkGroup[]>([]);
  const [selectedIp, setSelectedIp] = useState<LookupResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);

  const handleLookup = async (ips: string[]) => {
    if (ips.length === 0) {
      setResults([]);
      setGroups([]);
      setSelectedIp(null);
      setError(null);
      return;
    }

    setIsLoading(true);
    setError(null);
    setSelectedIp(null);

    try {
      const res = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Lookup failed");
        return;
      }
      setResults(data.results);
    } catch {
      setError("Network error - could not reach lookup service");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGroupsUpdate = useCallback((newGroups: NetworkGroup[]) => {
    setGroups(newGroups);
  }, []);

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
          Network Intelligence Mapper
        </span>
      </header>

      {/* Mobile: stacked layout, Desktop: sidebar layout */}
      <div className="flex flex-1 flex-col lg:flex-row">
        {/* Sidebar */}
        <aside className="flex flex-col border-b border-border lg:border-b-0 lg:border-r lg:w-80 xl:w-96">
          {/* Mobile collapse toggle */}
          <button
            type="button"
            onClick={() => setPanelOpen(!panelOpen)}
            className="flex items-center justify-between px-4 py-3 lg:hidden min-h-[44px]"
          >
            <span className="text-sm font-semibold text-foreground">Controls</span>
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
            <IpInputPanel
              onLookup={handleLookup}
              isLoading={isLoading}
              resultCount={results.filter((r) => !r.error).length}
            />

            {error && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}

            <DetailPanel
              selectedIp={selectedIp}
              groups={groups}
              onClearSelection={() => setSelectedIp(null)}
            />
          </div>
        </aside>

        {/* Graph Area */}
        <section className="flex flex-1 flex-col p-3 lg:p-4 min-h-[350px] lg:min-h-0">
          <NetworkGraph
            results={results}
            onNodeSelect={setSelectedIp}
            onGroupsUpdate={handleGroupsUpdate}
          />
        </section>
      </div>
    </main>
  );
}

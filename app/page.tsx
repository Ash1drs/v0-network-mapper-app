"use client";

import { useState, useRef, useMemo, useCallback } from "react";
import { NetworkGraph, type NetworkGraphHandle } from "@/components/network-graph";
import { UploadPanel } from "@/components/ip-input-panel";
import { DetailPanel } from "@/components/detail-panel";
import { FilterControls, createDefaultFilters, type FilterState } from "@/components/filter-controls";
import { StatsDashboard } from "@/components/stats-dashboard";
import { TimelineSlider } from "@/components/timeline-slider";
import { ExportControls } from "@/components/export-controls";
import { LineagePanel } from "@/components/lineage-panel";
import type { DnsRecord, AsnGroup } from "@/lib/network-types";
import type { Lineage } from "@/lib/origin-trace";
import { buildLineageForAsn, buildLineageForIp } from "@/lib/origin-trace";
import { Activity, ChevronDown, ChevronUp } from "lucide-react";

interface AnalysisStats {
  totalRecords: number;
  uniqueIps: number;
  uniqueDomains: number;
  uniqueAsns: number;
}

export default function Page() {
  const [groups, setGroups] = useState<AsnGroup[]>([]);
  const [allRecords, setAllRecords] = useState<DnsRecord[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<AsnGroup | null>(null);
  const [stats, setStats] = useState<AnalysisStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);
  const [filters, setFilters] = useState<FilterState>(createDefaultFilters);
  const [dateRange, setDateRange] = useState<{ start: Date | null; end: Date | null }>({
    start: null,
    end: null,
  });
  const [lineage, setLineage] = useState<Lineage | null>(null);

  const graphRef = useRef<NetworkGraphHandle>(null);

  const handleTraceAsn = useCallback((group: AsnGroup) => {
    setLineage(buildLineageForAsn(group));
  }, []);

  const handleTraceIp = useCallback((ip: string, group: AsnGroup) => {
    setLineage(buildLineageForIp(ip, group));
  }, []);

  // Get canvas directly from graphRef when needed
  const getCanvasRef = useCallback(() => {
    return graphRef.current?.getCanvas() ?? null;
  }, []);

  // Apply filters to groups
  const filteredGroups = useMemo(() => {
    let result = groups;

    // Hide ASNs
    if (filters.hiddenAsns.size > 0) {
      result = result.filter((g) => !filters.hiddenAsns.has(g.asn));
    }

    // Search query
    if (filters.searchQuery.trim()) {
      const q = filters.searchQuery.toLowerCase();
      result = result.filter(
        (g) =>
          g.asn.toLowerCase().includes(q) ||
          g.asName.toLowerCase().includes(q) ||
          g.ips.some((ip) => ip.includes(q)) ||
          g.domains.some((d) => d.toLowerCase().includes(q))
      );
    }

    // Risk filter
    if (filters.minRiskScore > 0 || filters.maxRiskScore < 100) {
      result = result.filter(
        (g) =>
          g.maxRiskScore >= filters.minRiskScore &&
          g.maxRiskScore <= filters.maxRiskScore
      );
    }

    // Date range filter
    if (dateRange.start || dateRange.end) {
      result = result.map((g) => {
        const filteredRecords = g.records.filter((r) => {
          const firstSeen = r.first_seen ? new Date(r.first_seen).getTime() : 0;
          const lastSeen = r.last_seen ? new Date(r.last_seen).getTime() : Date.now();
          const start = dateRange.start?.getTime() ?? 0;
          const end = dateRange.end?.getTime() ?? Date.now();
          return lastSeen >= start && firstSeen <= end;
        });

        if (filteredRecords.length === 0) return null;

        return {
          ...g,
          records: filteredRecords,
          ips: [...new Set(filteredRecords.map((r) => r.answer))],
          domains: [...new Set(filteredRecords.map((r) => r.query))],
        };
      }).filter((g): g is AsnGroup => g !== null);
    }

    return result;
  }, [groups, filters, dateRange]);

  const handleAnalyze = async (records: DnsRecord[]) => {
    if (records.length === 0) {
      setGroups([]);
      setAllRecords([]);
      setSelectedGroup(null);
      setStats(null);
      setError(null);
      setFilters(createDefaultFilters());
      setDateRange({ start: null, end: null });
      setLineage(null);
      return;
    }

    setIsLoading(true);
    setError(null);
    setSelectedGroup(null);
    setLineage(null);

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
      setAllRecords(records);
      setStats({
        totalRecords: data.totalRecords,
        uniqueIps: data.uniqueIps,
        uniqueDomains: data.uniqueDomains,
        uniqueAsns: data.uniqueAsns,
      });
      setFilters(createDefaultFilters());
      setDateRange({ start: null, end: null });
    } catch {
      setError("Failed to analyze data");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDateRangeChange = (start: Date | null, end: Date | null) => {
    setDateRange({ start, end });
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
        <div className="flex items-center gap-3">
          {groups.length > 0 && (
            <ExportControls
              groups={groups}
              filteredGroups={filteredGroups}
              getCanvas={getCanvasRef}
            />
          )}
          <span className="text-xs font-mono text-muted-foreground hidden sm:inline">
            Infrastructure Intelligence Mapper
          </span>
        </div>
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
            {lineage && (
              <div className="rounded-lg border border-primary/30 bg-card p-3">
                <LineagePanel lineage={lineage} onClose={() => setLineage(null)} />
              </div>
            )}

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

            {groups.length > 0 && (
              <>
                <FilterControls
                  groups={groups}
                  filters={filters}
                  onFiltersChange={setFilters}
                />

                <TimelineSlider
                  groups={groups}
                  onDateRangeChange={handleDateRangeChange}
                />

                <StatsDashboard groups={filteredGroups} allRecords={allRecords} />
              </>
            )}

            <DetailPanel
              selectedGroup={selectedGroup}
              groups={filteredGroups}
              onSelectGroup={setSelectedGroup}
              onTraceAsn={handleTraceAsn}
              onTraceIp={handleTraceIp}
            />
          </div>
        </aside>

        {/* Graph Area */}
        <section className="flex flex-1 flex-col p-3 lg:p-4 min-h-[350px] lg:min-h-0">
          <NetworkGraph
            ref={graphRef}
            groups={filteredGroups}
            onSelectGroup={setSelectedGroup}
            selectedAsn={selectedGroup?.asn ?? null}
          />
        </section>
      </div>
    </main>
  );
}

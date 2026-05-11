"use client";

import { useState } from "react";
import {
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  X,
  Eye,
  EyeOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { AsnGroup } from "@/lib/network-types";

export interface FilterState {
  searchQuery: string;
  minRiskScore: number;
  maxRiskScore: number;
  hiddenAsns: Set<string>;
  collapsedAsns: Set<string>;
  showDomainsGlobally: boolean;
}

interface FilterControlsProps {
  groups: AsnGroup[];
  filters: FilterState;
  onFiltersChange: (filters: FilterState) => void;
}

const RISK_LEVELS = [
  { label: "All", min: 0, max: 100 },
  { label: "Critical (70+)", min: 70, max: 100 },
  { label: "High (40-69)", min: 40, max: 69 },
  { label: "Medium (20-39)", min: 20, max: 39 },
  { label: "Low (0-19)", min: 0, max: 19 },
];

export function FilterControls({
  groups,
  filters,
  onFiltersChange,
}: FilterControlsProps) {
  const [expanded, setExpanded] = useState(false);

  const updateFilter = <K extends keyof FilterState>(
    key: K,
    value: FilterState[K]
  ) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const toggleHideAsn = (asn: string) => {
    const newHidden = new Set(filters.hiddenAsns);
    if (newHidden.has(asn)) {
      newHidden.delete(asn);
    } else {
      newHidden.add(asn);
    }
    updateFilter("hiddenAsns", newHidden);
  };

  const toggleCollapseAsn = (asn: string) => {
    const newCollapsed = new Set(filters.collapsedAsns);
    if (newCollapsed.has(asn)) {
      newCollapsed.delete(asn);
    } else {
      newCollapsed.add(asn);
    }
    updateFilter("collapsedAsns", newCollapsed);
  };

  const collapseAll = () => {
    updateFilter("collapsedAsns", new Set(groups.map((g) => g.asn)));
  };

  const expandAll = () => {
    updateFilter("collapsedAsns", new Set());
  };

  const showAll = () => {
    updateFilter("hiddenAsns", new Set());
  };

  const activeFilterCount =
    (filters.searchQuery ? 1 : 0) +
    (filters.minRiskScore > 0 || filters.maxRiskScore < 100 ? 1 : 0) +
    (filters.hiddenAsns.size > 0 ? 1 : 0) +
    (filters.collapsedAsns.size > 0 ? 1 : 0);

  return (
    <div className="flex flex-col gap-3">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between min-h-[44px] text-left"
      >
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold text-foreground">
            Search & Filter
          </span>
          {activeFilterCount > 0 && (
            <span className="rounded-full bg-primary px-1.5 py-0.5 text-xs font-bold text-primary-foreground">
              {activeFilterCount}
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        )}
      </button>

      {expanded && (
        <div className="flex flex-col gap-4 rounded-lg border border-border bg-secondary/30 p-3">
          {/* Search */}
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="search-input"
              className="text-xs text-muted-foreground"
            >
              Search IP, Domain, or ASN
            </label>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                id="search-input"
                type="text"
                value={filters.searchQuery}
                onChange={(e) => updateFilter("searchQuery", e.target.value)}
                placeholder="8.8.8.8, google.com, AS15169..."
                className="w-full rounded-md border border-border bg-input pl-9 pr-8 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring min-h-[44px]"
                style={{ fontSize: "16px" }}
              />
              {filters.searchQuery && (
                <button
                  type="button"
                  onClick={() => updateFilter("searchQuery", "")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                  aria-label="Clear search"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Risk Level Filter */}
          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">
              Risk Level Filter
            </span>
            <div className="flex flex-wrap gap-1.5">
              {RISK_LEVELS.map((level) => {
                const isActive =
                  filters.minRiskScore === level.min &&
                  filters.maxRiskScore === level.max;
                return (
                  <button
                    key={level.label}
                    type="button"
                    onClick={() => {
                      updateFilter("minRiskScore", level.min);
                      updateFilter("maxRiskScore", level.max);
                    }}
                    className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors min-h-[36px] ${
                      isActive
                        ? "border-primary bg-primary/20 text-primary"
                        : "border-border bg-secondary/50 text-muted-foreground hover:text-foreground hover:bg-secondary"
                    }`}
                  >
                    {level.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Show/Hide Domains */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              Show domain nodes
            </span>
            <button
              type="button"
              onClick={() =>
                updateFilter(
                  "showDomainsGlobally",
                  !filters.showDomainsGlobally
                )
              }
              className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors min-h-[36px] ${
                filters.showDomainsGlobally
                  ? "border-primary bg-primary/20 text-primary"
                  : "border-border bg-secondary/50 text-muted-foreground"
              }`}
            >
              {filters.showDomainsGlobally ? (
                <Eye className="h-3.5 w-3.5" />
              ) : (
                <EyeOff className="h-3.5 w-3.5" />
              )}
              {filters.showDomainsGlobally ? "Shown" : "Hidden"}
            </button>
          </div>

          {/* Cluster Controls */}
          {groups.length > 0 && (
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  ASN Clusters
                </span>
                <div className="flex gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={collapseAll}
                    className="h-7 px-2 text-xs"
                  >
                    Collapse All
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={expandAll}
                    className="h-7 px-2 text-xs"
                  >
                    Expand All
                  </Button>
                  {filters.hiddenAsns.size > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={showAll}
                      className="h-7 px-2 text-xs text-primary"
                    >
                      Show All
                    </Button>
                  )}
                </div>
              </div>

              <div className="max-h-[150px] overflow-y-auto rounded-md border border-border bg-card">
                {groups.map((group) => {
                  const isHidden = filters.hiddenAsns.has(group.asn);
                  const isCollapsed = filters.collapsedAsns.has(group.asn);
                  return (
                    <div
                      key={group.asn}
                      className={`flex items-center gap-2 border-b border-border/50 px-2 py-1.5 last:border-0 ${
                        isHidden ? "opacity-50" : ""
                      }`}
                    >
                      <span
                        className="h-2.5 w-2.5 rounded-full shrink-0"
                        style={{ backgroundColor: group.color }}
                      />
                      <span className="flex-1 truncate text-xs font-mono text-foreground">
                        AS{group.asn}
                      </span>
                      <button
                        type="button"
                        onClick={() => toggleCollapseAsn(group.asn)}
                        className="p-1 text-muted-foreground hover:text-foreground min-w-[28px] min-h-[28px] flex items-center justify-center"
                        aria-label={isCollapsed ? "Expand" : "Collapse"}
                        title={isCollapsed ? "Expand" : "Collapse"}
                      >
                        {isCollapsed ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : (
                          <ChevronUp className="h-3 w-3" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => toggleHideAsn(group.asn)}
                        className="p-1 text-muted-foreground hover:text-foreground min-w-[28px] min-h-[28px] flex items-center justify-center"
                        aria-label={isHidden ? "Show" : "Hide"}
                        title={isHidden ? "Show" : "Hide"}
                      >
                        {isHidden ? (
                          <EyeOff className="h-3 w-3" />
                        ) : (
                          <Eye className="h-3 w-3" />
                        )}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function createDefaultFilters(): FilterState {
  return {
    searchQuery: "",
    minRiskScore: 0,
    maxRiskScore: 100,
    hiddenAsns: new Set(),
    collapsedAsns: new Set(),
    showDomainsGlobally: true,
  };
}

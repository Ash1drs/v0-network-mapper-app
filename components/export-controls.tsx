"use client";

import { useCallback } from "react";
import { Download, Image, FileJson, FileSpreadsheet } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { AsnGroup, DnsRecord } from "@/lib/network-types";

interface ExportControlsProps {
  groups: AsnGroup[];
  filteredGroups: AsnGroup[];
  getCanvas: () => HTMLCanvasElement | null;
}

export function ExportControls({ groups, filteredGroups, getCanvas }: ExportControlsProps) {
  const triggerDownload = useCallback((blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const exportPNG = useCallback(() => {
    const canvas = getCanvas();
    if (!canvas) return;
    
    canvas.toBlob((blob) => {
      if (blob) {
        triggerDownload(blob, `netmap-${Date.now()}.png`);
      }
    }, "image/png");
  }, [getCanvas, triggerDownload]);

  const exportJSON = useCallback(() => {
    const data = {
      exportedAt: new Date().toISOString(),
      totalGroups: filteredGroups.length,
      totalRecords: filteredGroups.reduce((sum, g) => sum + g.records.length, 0),
      groups: filteredGroups.map((g) => ({
        asn: g.asn,
        asName: g.asName,
        ipCount: g.ips.length,
        domainCount: g.domains.length,
        maxRiskScore: g.maxRiskScore,
        avgRiskScore: g.avgRiskScore,
        totalCount: g.totalCount,
        ips: g.ips,
        domains: g.domains,
        records: g.records,
      })),
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    triggerDownload(blob, `netmap-export-${Date.now()}.json`);
  }, [filteredGroups, triggerDownload]);

  const exportCSV = useCallback(() => {
    const records: DnsRecord[] = filteredGroups.flatMap((g) => g.records);

    const headers = [
      "query",
      "answer",
      "answer_asn",
      "answer_as_name",
      "query_risk_score",
      "answer_risk_score",
      "count",
      "first_seen",
      "last_seen",
      "type",
    ];

    const rows = records.map((r) => [
      r.query,
      r.answer,
      r.answer_asn,
      r.answer_as_name,
      r.query_risk_score,
      r.answer_risk_score,
      r.count,
      r.first_seen,
      r.last_seen,
      r.type,
    ]);

    const csvContent = [
      headers.join(","),
      ...rows.map((row) =>
        row
          .map((cell) => {
            const str = String(cell ?? "");
            // Escape quotes and wrap in quotes if contains comma/newline/quote
            if (str.includes(",") || str.includes("\n") || str.includes('"')) {
              return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
          })
          .join(",")
      ),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv" });
    triggerDownload(blob, `netmap-export-${Date.now()}.csv`);
  }, [filteredGroups, triggerDownload]);

  const exportSummary = useCallback(() => {
    const summary = filteredGroups.map((g) => ({
      asn: g.asn,
      organization: g.asName,
      unique_ips: g.ips.length,
      unique_domains: g.domains.length,
      max_risk_score: g.maxRiskScore,
      avg_risk_score: g.avgRiskScore,
      total_observations: g.totalCount,
    }));

    const headers = Object.keys(summary[0] || {});
    const rows = summary.map((row) => Object.values(row));

    const csvContent = [
      headers.join(","),
      ...rows.map((row) => row.map((cell) => String(cell ?? "")).join(",")),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv" });
    triggerDownload(blob, `netmap-summary-${Date.now()}.csv`);
  }, [filteredGroups, triggerDownload]);

  if (groups.length === 0) return null;

  return (
    <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-border text-muted-foreground hover:text-foreground"
          >
            <Download className="h-4 w-4" />
            Export
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuItem onClick={exportPNG} className="gap-2 cursor-pointer">
            <Image className="h-4 w-4" />
            Graph as PNG
          </DropdownMenuItem>
          <DropdownMenuItem onClick={exportJSON} className="gap-2 cursor-pointer">
            <FileJson className="h-4 w-4" />
            Full Data (JSON)
          </DropdownMenuItem>
          <DropdownMenuItem onClick={exportCSV} className="gap-2 cursor-pointer">
            <FileSpreadsheet className="h-4 w-4" />
            Records (CSV)
          </DropdownMenuItem>
          <DropdownMenuItem onClick={exportSummary} className="gap-2 cursor-pointer">
            <FileSpreadsheet className="h-4 w-4" />
            Summary by ASN (CSV)
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
  );
}

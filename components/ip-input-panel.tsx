"use client";

import { useState, useRef, useCallback } from "react";
import {
  Search,
  Loader2,
  Trash2,
  Upload,
  FileText,
  X,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { EntityKind, ThreatGraph } from "@/lib/network-types";
import { ENTITY_KIND_LABEL } from "@/lib/network-types";
import { ingest } from "@/lib/ingest";

interface UploadedFile {
  name: string;
  entityCount: number;
  edgeCount: number;
  graph: ThreatGraph;
  format: string;
}

interface AnalysisStats {
  entities: number;
  relationships: number;
  byKind: Record<EntityKind, number>;
  matchedEntities: number;
  matchedEdges: number;
  feeds: number;
}

interface UploadPanelProps {
  onAnalyze: (graphs: ThreatGraph[]) => void;
  isLoading: boolean;
  stats: AnalysisStats | null;
}

export function UploadPanel({ onAnalyze, isLoading, stats }: UploadPanelProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const totalEntities = files.reduce((sum, f) => sum + f.entityCount, 0);

  const processFile = useCallback((file: File) => {
    setParseError(null);
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const { graph, format } = ingest(text, file.name);
      if (graph.entities.length > 0) {
        setFiles((prev) => [
          ...prev,
          {
            name: file.name,
            entityCount: graph.entities.length,
            edgeCount: graph.relationships.length,
            graph,
            format,
          },
        ]);
      } else {
        setParseError(
          `Couldn't extract any indicators from "${file.name}". Supported: STIX 2.x, MISP / VirusTotal Graph, OpenIOC (AlienVault OTX), passive DNS JSON/JSONL, and CSV.`
        );
      }
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      Array.from(e.dataTransfer.files).forEach(processFile);
    },
    [processFile]
  );

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    Array.from(e.target.files || []).forEach(processFile);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
    setParseError(null);
  };

  const handleSubmit = () => {
    const graphs = files.map((f) => f.graph);
    if (graphs.length > 0) onAnalyze(graphs);
  };

  const clearAll = () => {
    setFiles([]);
    setParseError(null);
    onAnalyze([]);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground">
          Upload Intel Data
        </h2>
        {stats && (
          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary">
            {stats.feeds} feed{stats.feeds !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Drop zone */}
      <button
        type="button"
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`relative flex min-h-[120px] cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed transition-colors ${
          dragOver
            ? "border-primary bg-primary/10"
            : "border-border bg-input hover:border-muted-foreground"
        }`}
      >
        <Upload
          className={`h-6 w-6 ${
            dragOver ? "text-primary" : "text-muted-foreground"
          }`}
        />
        <span className="text-sm text-muted-foreground">
          Drop files here or{" "}
          <span className="font-medium text-primary">browse</span>
        </span>
        <span className="text-xs text-muted-foreground/70 text-center px-2">
          STIX, MISP / VirusTotal, OpenIOC / OTX &middot; JSON / XML / CSV
        </span>
      </button>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".json,.xml,.txt,.csv,.log,.pdf,.ioc,text/*,application/json,application/xml"
        onChange={handleFileSelect}
        className="hidden"
      />

      {/* Parse error */}
      {parseError && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          <span>{parseError}</span>
        </div>
      )}

      {/* Uploaded files list */}
      {files.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {files.map((file, i) => (
            <div
              key={`${file.name}-${i}`}
              className="flex items-center gap-2 rounded-md border border-border bg-secondary/50 px-3 py-2"
            >
              <FileText className="h-4 w-4 shrink-0 text-primary" />
              <div className="flex flex-1 flex-col overflow-hidden">
                <span className="truncate text-xs font-medium text-foreground">
                  {file.name}
                </span>
                <span className="text-xs text-muted-foreground font-mono">
                  {file.format} &middot; {file.entityCount.toLocaleString()}{" "}
                  node{file.entityCount !== 1 ? "s" : ""}
                  {file.edgeCount > 0 &&
                    ` \u00b7 ${file.edgeCount.toLocaleString()} edge${
                      file.edgeCount !== 1 ? "s" : ""
                    }`}
                </span>
              </div>
              <button
                type="button"
                onClick={() => removeFile(i)}
                className="min-h-[44px] min-w-[44px] flex items-center justify-center text-muted-foreground hover:text-destructive"
                aria-label={`Remove ${file.name}`}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Summary */}
      {totalEntities > 0 && (
        <div className="rounded-md bg-secondary/50 px-3 py-2 text-xs text-muted-foreground font-mono">
          {totalEntities.toLocaleString()} indicators across {files.length} feed
          {files.length !== 1 ? "s" : ""} ready to map
        </div>
      )}

      {/* Stats after analysis */}
      {stats && (
        <div className="flex flex-col gap-2">
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
              <div className="text-lg font-bold font-mono text-primary">
                {stats.entities.toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground">Entities</div>
            </div>
            <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
              <div className="text-lg font-bold font-mono text-primary">
                {stats.relationships.toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground">Relationships</div>
            </div>
          </div>

          {/* Match highlight */}
          <div
            className="rounded-md border px-3 py-2 text-center"
            style={{
              borderColor: "var(--match-color, #ec4899)55",
              backgroundColor: "var(--match-color, #ec4899)10",
            }}
          >
            <div
              className="text-lg font-bold font-mono"
              style={{ color: "var(--match-color, #ec4899)" }}
            >
              {stats.matchedEntities.toLocaleString()}
            </div>
            <div className="text-xs text-muted-foreground">
              Cross-feed matches
              {stats.matchedEdges > 0 && ` \u00b7 ${stats.matchedEdges} shared edges`}
            </div>
          </div>

          {/* Kind breakdown */}
          <div className="flex flex-wrap gap-1.5">
            {(Object.keys(stats.byKind) as EntityKind[]).map((kind) => (
              <span
                key={kind}
                className="rounded-full border border-border bg-secondary/40 px-2 py-0.5 text-xs font-mono text-muted-foreground"
              >
                {ENTITY_KIND_LABEL[kind]}: {stats.byKind[kind]}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2">
        <Button
          type="button"
          onClick={handleSubmit}
          disabled={isLoading || totalEntities === 0}
          className="flex-1 min-h-[44px] gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          {isLoading ? "Mapping..." : "Map Relationships"}
        </Button>
        {files.length > 0 && (
          <Button
            type="button"
            variant="outline"
            onClick={clearAll}
            className="min-h-[44px] gap-2 text-xs border-border text-muted-foreground hover:text-destructive hover:bg-secondary"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
    </div>
  );
}

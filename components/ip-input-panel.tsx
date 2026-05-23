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
import type { DnsRecord } from "@/lib/network-types";

interface UploadedFile {
  name: string;
  recordCount: number;
  records: DnsRecord[];
}

interface UploadPanelProps {
  onAnalyze: (records: DnsRecord[]) => void;
  isLoading: boolean;
  stats: { totalRecords: number; uniqueIps: number; uniqueDomains: number; uniqueAsns: number } | null;
}

function tryParseRecords(text: string): DnsRecord[] {
  // Try direct JSON array first
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed.records && Array.isArray(parsed.records)) return parsed.records;
    if (parsed.data && Array.isArray(parsed.data)) return parsed.data;
  } catch {
    // Not valid JSON as-is
  }

  // Try to find a JSON array embedded in text (e.g. from a PDF extraction)
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    try {
      // Clean up common PDF artifacts
      let cleaned = arrayMatch[0];
      // Fix hyphenated line breaks (word-\nbreak => wordbreak)
      cleaned = cleaned.replace(/-\s*\n\s*/g, "");
      // Fix regular line breaks
      cleaned = cleaned.replace(/\n/g, " ");
      // Normalize multiple spaces
      cleaned = cleaned.replace(/\s+/g, " ");
      // Fix spaced out letters from PDF extraction (e.g. "q u e r y" => "query")
      cleaned = cleaned.replace(/" q u e r y/g, '"query');
      cleaned = cleaned.replace(/q u e r y_/g, 'query_');
      // Fix any remaining broken field names
      cleaned = cleaned.replace(/a n s w e r/g, 'answer');
      cleaned = cleaned.replace(/c o u n t/g, 'count');
      
      const parsed = JSON.parse(cleaned);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      // Still not parseable
    }
  }

  // Try line-by-line JSON (JSONL)
  const lines = text.split("\n").filter((l) => l.trim().startsWith("{"));
  if (lines.length > 0) {
    const records: DnsRecord[] = [];
    for (const line of lines) {
      try {
        records.push(JSON.parse(line.replace(/,$/, "")));
      } catch {
        // skip bad lines
      }
    }
    if (records.length > 0) return records;
  }

  return [];
}

export function UploadPanel({
  onAnalyze,
  isLoading,
  stats,
}: UploadPanelProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const totalRecords = files.reduce((sum, f) => sum + f.recordCount, 0);

  const processFile = useCallback((file: File) => {
    setParseError(null);
    
    // PDF files can't be read as text directly
    if (file.name.endsWith(".pdf") || file.type === "application/pdf") {
      setParseError(
        `PDF files need to be converted first. Please export your INFRARUN data as JSON, or copy the JSON content into a .json or .txt file.`
      );
      return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const records = tryParseRecords(text);
      if (records.length > 0) {
        setFiles((prev) => [
          ...prev,
          { name: file.name, recordCount: records.length, records },
        ]);
      } else {
        setParseError(
          `Could not find DNS records in "${file.name}". Expected JSON with query/answer fields.`
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
    const allRecords = files.flatMap((f) => f.records);
    if (allRecords.length > 0) {
      onAnalyze(allRecords);
    }
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
            {stats.uniqueAsns} orgs
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
        <span className="text-xs text-muted-foreground/70">
          JSON files only -- export from INFRARUN or paste JSON into .txt
        </span>
      </button>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".json,.txt,.csv,.log,text/*,application/json"
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
                  {file.recordCount.toLocaleString()} DNS record
                  {file.recordCount !== 1 ? "s" : ""}
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
      {totalRecords > 0 && (
        <div className="rounded-md bg-secondary/50 px-3 py-2 text-xs text-muted-foreground font-mono">
          {totalRecords.toLocaleString()} total records ready to analyze
        </div>
      )}

      {/* Stats after analysis */}
      {stats && (
        <div className="grid grid-cols-2 gap-2">
          <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono text-primary">
              {stats.uniqueIps}
            </div>
            <div className="text-xs text-muted-foreground">Unique IPs</div>
          </div>
          <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono text-primary">
              {stats.uniqueDomains}
            </div>
            <div className="text-xs text-muted-foreground">Domains</div>
          </div>
          <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono text-primary">
              {stats.uniqueAsns}
            </div>
            <div className="text-xs text-muted-foreground">ASNs / Orgs</div>
          </div>
          <div className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono text-primary">
              {stats.totalRecords}
            </div>
            <div className="text-xs text-muted-foreground">Records</div>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2">
        <Button
          type="button"
          onClick={handleSubmit}
          disabled={isLoading || totalRecords === 0}
          className="flex-1 min-h-[44px] gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          {isLoading ? "Analyzing..." : "Map Infrastructure"}
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

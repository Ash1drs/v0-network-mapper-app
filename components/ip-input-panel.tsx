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
  format: string;
}

interface UploadPanelProps {
  onAnalyze: (records: DnsRecord[]) => void;
  isLoading: boolean;
  stats: { totalRecords: number; uniqueIps: number; uniqueDomains: number; uniqueAsns: number } | null;
}

const IP_REGEX = /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/g;
const DOMAIN_REGEX = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;

// Field name mappings for different data formats
const FIELD_MAPPINGS = {
  ip: ["ip", "ip_address", "ipaddress", "address", "src_ip", "dst_ip", "source_ip", "dest_ip", "answer", "resolved_ip", "host_ip", "client_ip", "server_ip"],
  domain: ["domain", "hostname", "host", "fqdn", "query", "dns_query", "name", "url", "site"],
  asn: ["asn", "as_number", "answer_asn", "query_asn", "autonomous_system", "as"],
  asName: ["as_name", "asname", "org", "organization", "isp", "answer_as_name", "query_as_name", "as_org"],
  risk: ["risk", "risk_score", "threat_score", "score", "severity", "answer_risk_score", "query_risk_score", "confidence"],
  count: ["count", "hits", "occurrences", "frequency", "times_seen", "observations"],
  firstSeen: ["first_seen", "firstseen", "first_observed", "created", "start_time", "timestamp"],
  lastSeen: ["last_seen", "lastseen", "last_observed", "updated", "end_time", "last_timestamp"],
  type: ["type", "record_type", "dns_type", "query_type", "rtype"],
};

function findFieldValue(obj: Record<string, unknown>, fieldType: keyof typeof FIELD_MAPPINGS): unknown {
  const possibleNames = FIELD_MAPPINGS[fieldType];
  for (const name of possibleNames) {
    // Check exact match
    if (obj[name] !== undefined) return obj[name];
    // Check case-insensitive
    const key = Object.keys(obj).find(k => k.toLowerCase() === name.toLowerCase());
    if (key && obj[key] !== undefined) return obj[key];
  }
  return undefined;
}

function normalizeRecord(obj: Record<string, unknown>): DnsRecord | null {
  const ip = findFieldValue(obj, "ip");
  const domain = findFieldValue(obj, "domain");
  
  // Must have at least an IP or domain
  if (!ip && !domain) return null;
  
  const asn = findFieldValue(obj, "asn");
  const asName = findFieldValue(obj, "asName");
  const risk = findFieldValue(obj, "risk");
  const count = findFieldValue(obj, "count");
  const firstSeen = findFieldValue(obj, "firstSeen");
  const lastSeen = findFieldValue(obj, "lastSeen");
  const type = findFieldValue(obj, "type");
  
  return {
    query: String(domain || ""),
    query_risk_score: typeof risk === "number" ? risk : 0,
    query_risk_score_decider: "",
    query_asn: "",
    query_as_name: "",
    answer: String(ip || ""),
    answer_risk_score: typeof risk === "number" ? risk : 0,
    answer_risk_score_decider: "",
    answer_asn: String(asn || "UNKNOWN"),
    answer_as_name: String(asName || "Unknown Organization"),
    count: typeof count === "number" ? count : 1,
    first_seen: String(firstSeen || new Date().toISOString()),
    last_seen: String(lastSeen || new Date().toISOString()),
    type: String(type || "A"),
  };
}

function parseCSV(text: string): DnsRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  
  // Parse header - handle both comma and tab delimiters
  const delimiter = lines[0].includes("\t") ? "\t" : ",";
  const headers = lines[0].split(delimiter).map(h => h.trim().replace(/^["']|["']$/g, "").toLowerCase());
  
  const records: DnsRecord[] = [];
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(delimiter).map(v => v.trim().replace(/^["']|["']$/g, ""));
    if (values.length !== headers.length) continue;
    
    const obj: Record<string, unknown> = {};
    headers.forEach((h, idx) => {
      const val = values[idx];
      // Try to parse numbers
      const num = parseFloat(val);
      obj[h] = !isNaN(num) && val !== "" ? num : val;
    });
    
    const record = normalizeRecord(obj);
    if (record) records.push(record);
  }
  
  return records;
}

function parseJSON(text: string): DnsRecord[] {
  // Clean up common artifacts
  let cleaned = text;
  cleaned = cleaned.replace(/-\s*\n\s*/g, "");
  cleaned = cleaned.replace(/\n/g, " ");
  cleaned = cleaned.replace(/\s+/g, " ");
  
  try {
    let parsed = JSON.parse(cleaned);
    
    // Handle wrapper objects
    if (!Array.isArray(parsed)) {
      if (parsed.records && Array.isArray(parsed.records)) parsed = parsed.records;
      else if (parsed.data && Array.isArray(parsed.data)) parsed = parsed.data;
      else if (parsed.results && Array.isArray(parsed.results)) parsed = parsed.results;
      else if (parsed.items && Array.isArray(parsed.items)) parsed = parsed.items;
      else return [];
    }
    
    return parsed.map((obj: Record<string, unknown>) => normalizeRecord(obj)).filter(Boolean) as DnsRecord[];
  } catch {
    return [];
  }
}

function parseJSONL(text: string): DnsRecord[] {
  const lines = text.split("\n").filter(l => l.trim().startsWith("{"));
  const records: DnsRecord[] = [];
  
  for (const line of lines) {
    try {
      const obj = JSON.parse(line.replace(/,$/, ""));
      const record = normalizeRecord(obj);
      if (record) records.push(record);
    } catch {
      // skip bad lines
    }
  }
  
  return records;
}

function parseIPsFromText(text: string): DnsRecord[] {
  const ips = [...new Set(text.match(IP_REGEX) || [])];
  const domains = [...new Set(text.match(DOMAIN_REGEX) || [])];
  
  // Create records from IPs found
  const records: DnsRecord[] = ips.map(ip => ({
    query: "",
    query_risk_score: 0,
    query_risk_score_decider: "",
    query_asn: "",
    query_as_name: "",
    answer: ip,
    answer_risk_score: 0,
    answer_risk_score_decider: "",
    answer_asn: "UNKNOWN",
    answer_as_name: "Unknown (extracted from text)",
    count: 1,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    type: "A",
  }));
  
  // Add domains that aren't already associated with IPs
  for (const domain of domains) {
    if (!records.some(r => r.query === domain)) {
      records.push({
        query: domain,
        query_risk_score: 0,
        query_risk_score_decider: "",
        query_asn: "",
        query_as_name: "",
        answer: "",
        answer_risk_score: 0,
        answer_risk_score_decider: "",
        answer_asn: "UNKNOWN",
        answer_as_name: "Unknown (extracted from text)",
        count: 1,
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        type: "A",
      });
    }
  }
  
  return records;
}

interface ParseResult {
  records: DnsRecord[];
  format: string;
}

function tryParseRecords(text: string, filename: string): ParseResult {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  
  // Try CSV first if it looks like CSV
  if (ext === "csv" || ext === "tsv" || (text.includes(",") && text.split("\n")[0].split(",").length > 2)) {
    const records = parseCSV(text);
    if (records.length > 0) return { records, format: "CSV" };
  }
  
  // Try JSON array
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    const records = parseJSON(arrayMatch[0]);
    if (records.length > 0) return { records, format: "JSON" };
  }
  
  // Try direct JSON object/array
  if (text.trim().startsWith("{") || text.trim().startsWith("[")) {
    const records = parseJSON(text);
    if (records.length > 0) return { records, format: "JSON" };
  }
  
  // Try JSONL (newline-delimited JSON)
  if (text.includes("}\n{") || text.includes("}\r\n{")) {
    const records = parseJSONL(text);
    if (records.length > 0) return { records, format: "JSONL" };
  }
  
  // Fall back to IP/domain extraction from plain text
  const records = parseIPsFromText(text);
  if (records.length > 0) return { records, format: "Plain text (IPs/domains extracted)" };
  
  return { records: [], format: "Unknown" };
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
        `PDF files can't be read directly. Copy the data and paste into a .txt or .json file, or export as CSV.`
      );
      return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const { records, format } = tryParseRecords(text, file.name);
      if (records.length > 0) {
        setFiles((prev) => [
          ...prev,
          { name: file.name, recordCount: records.length, records, format },
        ]);
      } else {
        setParseError(
          `Could not extract data from "${file.name}". Try JSON, CSV, or plain text with IPs/domains.`
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
          JSON, CSV, TXT, logs -- any file with IPs or network data
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
                  {file.recordCount.toLocaleString()} record{file.recordCount !== 1 ? "s" : ""} ({file.format})
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

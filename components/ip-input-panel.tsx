"use client";

import { useState, useRef, useCallback } from "react";
import {
  Search,
  Loader2,
  Trash2,
  Shuffle,
  Upload,
  FileText,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const SAMPLE_IPS = [
  "8.8.8.8",
  "8.8.4.4",
  "1.1.1.1",
  "1.0.0.1",
  "208.67.222.222",
  "208.67.220.220",
  "9.9.9.9",
  "149.112.112.112",
  "76.76.2.0",
  "76.76.10.0",
  "64.233.160.0",
  "64.233.160.1",
  "172.217.14.206",
  "151.101.1.69",
  "151.101.65.69",
  "104.16.132.229",
  "104.16.133.229",
];

const IP_REGEX =
  /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/g;

function extractIps(text: string): string[] {
  const matches = text.match(IP_REGEX);
  if (!matches) return [];
  return [...new Set(matches)];
}

interface UploadedFile {
  name: string;
  ipCount: number;
  ips: string[];
}

interface IpInputPanelProps {
  onLookup: (ips: string[]) => void;
  isLoading: boolean;
  resultCount: number;
}

export function IpInputPanel({
  onLookup,
  isLoading,
  resultCount,
}: IpInputPanelProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [pasteInput, setPasteInput] = useState("");
  const [showPaste, setShowPaste] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const totalIps = files.reduce((sum, f) => sum + f.ipCount, 0) +
    extractIps(pasteInput).length;

  const processFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      const ips = extractIps(text);
      if (ips.length > 0) {
        setFiles((prev) => [
          ...prev,
          { name: file.name, ipCount: ips.length, ips },
        ]);
      }
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const items = Array.from(e.dataTransfer.files);
      items.forEach(processFile);
    },
    [processFile]
  );

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const items = Array.from(e.target.files || []);
    items.forEach(processFile);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = () => {
    const allIps = [
      ...files.flatMap((f) => f.ips),
      ...extractIps(pasteInput),
    ];
    const unique = [...new Set(allIps)];
    if (unique.length > 0) {
      onLookup(unique);
    }
  };

  const loadSample = () => {
    const shuffled = [...SAMPLE_IPS]
      .sort(() => Math.random() - 0.5)
      .slice(0, 12);
    setFiles([
      { name: "sample-ips.txt", ipCount: shuffled.length, ips: shuffled },
    ]);
    setPasteInput("");
  };

  const clearAll = () => {
    setFiles([]);
    setPasteInput("");
    setShowPaste(false);
    onLookup([]);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground">IP Addresses</h2>
        {resultCount > 0 && (
          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary">
            {resultCount} mapped
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
          CSV, TXT, JSON, LOG -- any text file with IPs
        </span>
      </button>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".csv,.txt,.json,.log,.tsv,.xml,.conf,.cfg,.ini,.yaml,.yml,text/*"
        onChange={handleFileSelect}
        className="hidden"
      />

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
                  {file.ipCount} IP{file.ipCount !== 1 ? "s" : ""} found
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

      {/* Toggle paste input */}
      {!showPaste ? (
        <button
          type="button"
          onClick={() => setShowPaste(true)}
          className="min-h-[44px] text-xs text-muted-foreground hover:text-primary transition-colors text-left"
        >
          + or paste IPs manually
        </button>
      ) : (
        <div className="flex flex-col gap-1.5">
          <label
            htmlFor="paste-input"
            className="text-xs text-muted-foreground"
          >
            Paste additional IPs
          </label>
          <textarea
            id="paste-input"
            value={pasteInput}
            onChange={(e) => setPasteInput(e.target.value)}
            placeholder={"8.8.8.8\n1.1.1.1\n104.16.132.229"}
            className="h-24 w-full resize-none rounded-md border border-border bg-input px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            spellCheck={false}
            style={{ fontSize: "16px" }}
          />
        </div>
      )}

      {/* Summary + actions */}
      {totalIps > 0 && (
        <div className="rounded-md bg-secondary/50 px-3 py-2 text-xs text-muted-foreground font-mono">
          {totalIps} unique IP{totalIps !== 1 ? "s" : ""} ready to scan
          {totalIps > 500 && (
            <span className="block text-destructive mt-1">
              Max 500 per request -- only the first 500 will be processed
            </span>
          )}
        </div>
      )}

      <div className="flex gap-2">
        <Button
          type="button"
          onClick={handleSubmit}
          disabled={isLoading || totalIps === 0}
          className="flex-1 min-h-[44px] gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          {isLoading ? "Scanning..." : "Map Network"}
        </Button>
      </div>

      <div className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={loadSample}
          className="flex-1 min-h-[44px] gap-2 text-xs border-border text-muted-foreground hover:text-foreground hover:bg-secondary"
        >
          <Shuffle className="h-3.5 w-3.5" />
          Sample IPs
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={clearAll}
          className="min-h-[44px] gap-2 text-xs border-border text-muted-foreground hover:text-destructive hover:bg-secondary"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";
import { Search, Loader2, Trash2, Shuffle } from "lucide-react";
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

interface IpInputPanelProps {
  onLookup: (ips: string[]) => void;
  isLoading: boolean;
  resultCount: number;
}

export function IpInputPanel({ onLookup, isLoading, resultCount }: IpInputPanelProps) {
  const [input, setInput] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const ips = input
      .split(/[\n,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (ips.length > 0) {
      onLookup(ips);
    }
  };

  const loadSample = () => {
    const shuffled = [...SAMPLE_IPS].sort(() => Math.random() - 0.5).slice(0, 10);
    setInput(shuffled.join("\n"));
  };

  const clearAll = () => {
    setInput("");
    onLookup([]);
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground">IP Addresses</h2>
        {resultCount > 0 && (
          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary">
            {resultCount} mapped
          </span>
        )}
      </div>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={"Paste IPs here...\n8.8.8.8\n1.1.1.1\n104.16.132.229"}
        className="h-36 w-full resize-none rounded-md border border-border bg-input px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring md:h-48"
        spellCheck={false}
        style={{ fontSize: "16px" }}
      />
      <div className="flex gap-2">
        <Button
          type="submit"
          disabled={isLoading || !input.trim()}
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
    </form>
  );
}

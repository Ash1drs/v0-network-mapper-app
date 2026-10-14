"use client";

import { SIGNAL_ICON } from "@/components/filter-controls";
import { ZONE_LABEL } from "@/lib/network-types";
import {
  SIGNAL_COLOR,
  SIGNAL_LABEL,
  SIGNAL_ORDER,
  type EntitySignals,
  type Signal,
} from "@/lib/signals";

interface SignalBreakdownProps {
  signals: EntitySignals | undefined;
  onJump: (id: string) => void;
}

const MAX_OVERLAPS = 6;

function shortDate(value: string): string {
  const t = Date.parse(value);
  return Number.isNaN(t) ? value : new Date(t).toISOString().slice(0, 10);
}

export function SignalBreakdown({ signals, onJump }: SignalBreakdownProps) {
  const present = SIGNAL_ORDER.filter((s) => signals?.[s] != null);

  if (!signals || present.length === 0) {
    return (
      <div className="mb-3 rounded-md border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
        No match, overlap, pivot, or sequence evidence &mdash; this entity is only
        linked by a single source.
      </div>
    );
  }

  const jump = (id: string, label: string) => (
    <button
      type="button"
      onClick={() => onJump(id)}
      className="font-mono text-foreground underline decoration-border underline-offset-2 hover:decoration-foreground break-all"
    >
      {label}
    </button>
  );

  const body = (sig: Signal) => {
    switch (sig) {
      case "match":
        return (
          <span>
            Reported by {signals.match!.length} feeds:{" "}
            <span className="font-mono text-foreground">{signals.match!.join(", ")}</span>
          </span>
        );
      case "overlap": {
        const items = signals.overlap!;
        return (
          <ul className="flex flex-col gap-1">
            {items.slice(0, MAX_OVERLAPS).map((o, i) => (
              <li key={`${o.otherId}-${i}`}>
                {o.label} {jump(o.otherId, o.otherValue)}
                {o.feeds.length > 1 && (
                  <span className="text-muted-foreground/80"> &middot; {o.feeds.length} feeds agree</span>
                )}
              </li>
            ))}
            {items.length > MAX_OVERLAPS && (
              <li className="text-muted-foreground/80">+{items.length - MAX_OVERLAPS} more</li>
            )}
          </ul>
        );
      }
      case "pivot":
        return (
          <span>
            Bridges{" "}
            <span className="text-foreground">
              {signals.pivot!.length > 0
                ? signals.pivot!.map((z) => ZONE_LABEL[z]).join(" \u2194 ")
                : "multiple environments"}
            </span>
          </span>
        );
      case "sequence": {
        const s = signals.sequence!;
        return (
          <span className="flex flex-col gap-0.5">
            <span>
              <span className="text-foreground">
                #{s.rank} of {s.total}
              </span>{" "}
              among its linked entities &middot; first seen {shortDate(s.firstSeen)}
            </span>
            {s.before && (
              <span>
                After {jump(s.before.id, s.before.value)} ({shortDate(s.before.at)})
              </span>
            )}
            {s.after && (
              <span>
                Before {jump(s.after.id, s.after.value)} ({shortDate(s.after.at)})
              </span>
            )}
          </span>
        );
      }
    }
  };

  return (
    <section aria-label="Why this entity is connected" className="mb-3 flex flex-col gap-1.5">
      <span className="text-xs text-muted-foreground">Why it&apos;s connected</span>
      {present.map((sig) => {
        const Icon = SIGNAL_ICON[sig];
        const color = SIGNAL_COLOR[sig];
        return (
          <div
            key={sig}
            className="flex gap-2 rounded-md border px-2.5 py-2 text-xs leading-relaxed text-muted-foreground"
            style={{ borderColor: color + "40", backgroundColor: color + "0d" }}
          >
            <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" style={{ color }} aria-hidden="true" />
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="font-semibold" style={{ color }}>
                {SIGNAL_LABEL[sig]}
              </span>
              {body(sig)}
            </div>
          </div>
        );
      })}
    </section>
  );
}

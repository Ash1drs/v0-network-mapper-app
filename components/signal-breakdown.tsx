"use client";

import { SIGNAL_ICON } from "@/components/filter-controls";
import { ZONE_LABEL } from "@/lib/network-types";
import {
  SIGNAL_COLOR,
  SIGNAL_LABEL,
  SIGNAL_ORDER,
  type EntitySignals,
  type SequenceLink,
  type Signal,
} from "@/lib/signals";

interface SignalBreakdownProps {
  signals: EntitySignals | undefined;
  onJump: (id: string) => void;
}

const MAX_OVERLAPS = 6;
const MAX_LINKS = 8;

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
        const linkList = (title: string, links: SequenceLink[]) =>
          links.length > 0 && (
            <div className="flex flex-col gap-0.5">
              <span className="text-muted-foreground/80">
                {title} ({links.length})
              </span>
              <ol className="flex flex-col gap-0.5 border-l border-border pl-2">
                {links.slice(0, MAX_LINKS).map((l) => (
                  <li key={l.id} className="flex flex-wrap items-baseline gap-x-1.5">
                    <span className="font-mono text-muted-foreground/80 tabular-nums">
                      {l.firstSeen ? shortDate(l.firstSeen) : "\u2014"}
                    </span>
                    <span>{l.label}</span>
                    {jump(l.id, l.value)}
                    {l.seenCount ? (
                      <span className="text-muted-foreground/80">&times;{l.seenCount.toLocaleString()}</span>
                    ) : null}
                  </li>
                ))}
                {links.length > MAX_LINKS && (
                  <li className="text-muted-foreground/80">+{links.length - MAX_LINKS} more</li>
                )}
              </ol>
            </div>
          );
        return (
          <div className="flex flex-col gap-1.5">
            <dl className="grid grid-cols-3 gap-2">
              <div className="flex flex-col">
                <dt className="text-muted-foreground/80">First seen</dt>
                <dd className="font-mono text-foreground">{s.firstSeen ? shortDate(s.firstSeen) : "\u2014"}</dd>
              </div>
              <div className="flex flex-col">
                <dt className="text-muted-foreground/80">Last seen</dt>
                <dd className="font-mono text-foreground">{s.lastSeen ? shortDate(s.lastSeen) : "\u2014"}</dd>
              </div>
              <div className="flex flex-col">
                <dt className="text-muted-foreground/80">Times seen</dt>
                <dd className="font-mono text-foreground">{s.seenCount ? s.seenCount.toLocaleString() : "\u2014"}</dd>
              </div>
            </dl>
            <span className="text-muted-foreground/80">
              #{s.rank} of {s.total} to appear among its linked entities
            </span>
            {linkList("Connects to", s.connectsTo)}
            {linkList("Connected from", s.connectedFrom)}
          </div>
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

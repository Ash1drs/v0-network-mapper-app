import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  ENTITY_KIND_LABEL,
  EDGE_KIND_LABEL,
  feedColor,
  confidenceBand,
  type EntityKind,
  type ThreatGraph,
} from "./network-types";
import { detectClusters } from "./clusters";
import { buildTimeline } from "./timeline";
import { SAFETY_DISCLAIMER } from "./safety";

export interface ReportStats {
  entities: number;
  relationships: number;
  byKind: Record<EntityKind, number>;
  matchedEntities: number;
  matchedEdges: number;
  feeds: number;
}

interface ReportInput {
  graph: ThreatGraph;
  feedOrder: string[];
  stats: ReportStats;
  graphImage: string | null; // PNG data URL of the current map
}

// Theme accents (hex) used across the PDF.
const INK = "#0f1420";
const ACCENT = "#22b8cf";
const MATCH = "#ec4899";
const MUTED = "#64748b";
const LIGHT = "#eef2f6";

// ---------------------------------------------------------------------------
// PNG export: composite the (transparent) live canvas onto a solid background
// so the downloaded image matches what's shown on screen.
// ---------------------------------------------------------------------------
export function canvasToPng(source: HTMLCanvasElement, background: string): string | null {
  const out = document.createElement("canvas");
  out.width = source.width;
  out.height = source.height;
  const ctx = out.getContext("2d");
  if (!ctx) return null;
  ctx.fillStyle = background || "#0f1420";
  ctx.fillRect(0, 0, out.width, out.height);
  ctx.drawImage(source, 0, 0);
  return out.toDataURL("image/png");
}

export function downloadDataUrl(dataUrl: string, filename: string) {
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function timestamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
}

export function exportPng(source: HTMLCanvasElement, background: string) {
  const url = canvasToPng(source, background);
  if (url) downloadDataUrl(url, `netmap-${timestamp()}.png`);
}

// ---------------------------------------------------------------------------
// PDF report
// ---------------------------------------------------------------------------
const MAX_TABLE_ROWS = 500;

export function generatePdfReport({ graph, feedOrder, stats, graphImage }: ReportInput) {
  const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 40;
  const now = new Date();

  // Derived analysis (pure, runs on whatever graph is being reported).
  const clusters = detectClusters(graph);
  const timeline = buildTimeline(graph);
  const anchors = graph.entities.filter((e) => e.isAnchor);
  const bridges = graph.entities.filter((e) => e.isBridge);

  // Move y down, adding a page when the next block would overflow.
  const ensureSpace = (needed: number) => {
    if (y + needed > pageH - margin) {
      doc.addPage();
      y = margin;
    }
  };

  // Wrapped body text; advances y. Returns the new y.
  const writeParagraph = (text: string, opts?: { size?: number; color?: string }) => {
    const size = opts?.size ?? 9.5;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(size);
    doc.setTextColor(opts?.color ?? "#334155");
    const lines = doc.splitTextToSize(text, pageW - margin * 2) as string[];
    const lineH = size + 3;
    for (const line of lines) {
      ensureSpace(lineH + 2);
      doc.text(line, margin, y);
      y += lineH;
    }
    y += 4;
  };

  const sectionHeading = (title: string, color = INK) => {
    ensureSpace(30);
    doc.setTextColor(color);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(title, margin, y);
    y += 16;
  };

  // ---- Cover header band ----
  doc.setFillColor(INK);
  doc.rect(0, 0, pageW, 84, "F");
  doc.setTextColor("#ffffff");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.text("NetMap", margin, 40);
  doc.setTextColor(ACCENT);
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.text("Threat Intelligence Relationship Report", margin, 58);
  doc.setTextColor("#9aa7b4");
  doc.setFontSize(9);
  doc.text(`Generated ${now.toLocaleString()}`, margin, 72);

  let y = 108;

  // ---- Summary metrics ----
  doc.setTextColor(INK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Summary", margin, y);
  y += 8;

  const metrics: [string, string][] = [
    ["Entities", String(stats.entities)],
    ["Relationships", String(stats.relationships)],
    ["Cross-feed matches", String(stats.matchedEntities)],
    ["Shared edges", String(stats.matchedEdges)],
    ["Feeds ingested", String(stats.feeds)],
  ];
  const cardW = (pageW - margin * 2 - 16) / metrics.length;
  metrics.forEach(([label, value], i) => {
    const x = margin + i * (cardW + 4);
    doc.setFillColor(LIGHT);
    doc.roundedRect(x, y, cardW, 46, 4, 4, "F");
    doc.setTextColor(i === 2 ? MATCH : ACCENT);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(17);
    doc.text(value, x + cardW / 2, y + 22, { align: "center" });
    doc.setTextColor(MUTED);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.text(label.toUpperCase(), x + cardW / 2, y + 36, { align: "center" });
  });
  y += 46 + 20;

  // ---- Executive Summary ----
  sectionHeading("Executive Summary");
  const spanText =
    timeline.spanDays > 0
      ? `Observed activity spans ${timeline.spanDays} day${timeline.spanDays === 1 ? "" : "s"}` +
        (timeline.earliest && timeline.latest ? ` (${timeline.earliest} to ${timeline.latest}).` : ".")
      : "No reliable time span could be derived from the supplied timestamps.";
  writeParagraph(
    `This report correlates ${stats.entities} indicators and ${stats.relationships} relationships drawn from ` +
      `${stats.feeds} data source${stats.feeds === 1 ? "" : "s"}. ${stats.matchedEntities} indicator` +
      `${stats.matchedEntities === 1 ? "" : "s"} were observed in more than one source, and ${clusters.length} ` +
      `distinct cluster${clusters.length === 1 ? "" : "s"} of related infrastructure were detected. ${spanText} ` +
      `${anchors.length} case seed-anchor${anchors.length === 1 ? "" : "s"} and ${bridges.length} pivot node` +
      `${bridges.length === 1 ? "" : "s"} (bridging separate environments) are present. Confidence scores are earned ` +
      `through cross-source correlation, not assigned by hosting provider.`,
  );

  // ---- Key Findings ----
  sectionHeading("Key Findings");
  const findings: string[] = [];
  const topMatches = graph.entities
    .filter((e) => e.matched)
    .sort((a, b) => b.feeds.length - a.feeds.length || b.riskScore - a.riskScore)
    .slice(0, 5);
  for (const e of topMatches) {
    findings.push(
      `${e.value} (${ENTITY_KIND_LABEL[e.kind]}) observed across ${e.feeds.length} sources: ${e.feeds.join(", ")}.`,
    );
  }
  for (const a of anchors.slice(0, 5)) {
    findings.push(`Seed-anchor present: ${a.value} — links observed activity back to the case anchor set.`);
  }
  if (bridges.length) {
    findings.push(
      `${bridges.length} pivot node${bridges.length === 1 ? "" : "s"} bridge separate environments, e.g. ` +
        bridges.slice(0, 3).map((b) => b.value).join(", ") + ".",
    );
  }
  if (findings.length === 0) findings.push("No cross-source overlaps were detected in the supplied data.");
  for (const f of findings) {
    ensureSpace(16);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor("#334155");
    const lines = doc.splitTextToSize(`•  ${f}`, pageW - margin * 2 - 6) as string[];
    for (const line of lines) {
      ensureSpace(13);
      doc.text(line, margin + 4, y);
      y += 13;
    }
    y += 2;
  }
  y += 10;

  // ---- Entity-kind breakdown ----
  const kinds = (Object.keys(stats.byKind) as EntityKind[]).filter((k) => stats.byKind[k] > 0);
  if (kinds.length) {
    doc.setTextColor(INK);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text("Entity types", margin, y);
    y += 6;
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Type", "Count"]],
      body: kinds.map((k) => [ENTITY_KIND_LABEL[k], String(stats.byKind[k])]),
      theme: "grid",
      styles: { fontSize: 9, cellPadding: 4 },
      headStyles: { fillColor: INK, textColor: "#ffffff" },
      columnStyles: { 1: { halign: "right", cellWidth: 80 } },
    });
    // @ts-expect-error lastAutoTable is added by the plugin at runtime
    y = doc.lastAutoTable.finalY + 20;
  }

  // ---- Feeds legend ----
  doc.setTextColor(INK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("Feeds", margin, y);
  y += 6;
  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [["", "Feed", "Color"]],
    body: feedOrder.map((f, i) => [" ", f, feedColor(i).toUpperCase()]),
    theme: "grid",
    styles: { fontSize: 9, cellPadding: 4 },
    headStyles: { fillColor: INK, textColor: "#ffffff" },
    columnStyles: { 0: { cellWidth: 20 }, 2: { cellWidth: 90 } },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 0) {
        data.cell.styles.fillColor = feedColor(data.row.index);
      }
    },
  });
  // @ts-expect-error runtime plugin property
  y = doc.lastAutoTable.finalY + 20;

  // ---- Embedded graph image ----
  if (graphImage) {
    try {
      const props = doc.getImageProperties(graphImage);
      const maxW = pageW - margin * 2;
      const imgH = (props.height / props.width) * maxW;
      const drawH = Math.min(imgH, 320);
      const drawW = (props.width / props.height) * drawH;
      if (y + drawH + 30 > pageH - margin) {
        doc.addPage();
        y = margin;
      }
      doc.setTextColor(INK);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.text("Network map", margin, y);
      y += 10;
      // dark backing panel to match the app canvas
      doc.setFillColor?.(INK);
      doc.setFillColor(INK);
      doc.roundedRect(margin, y, maxW, drawH + 16, 4, 4, "F");
      const imgX = margin + (maxW - drawW) / 2;
      doc.addImage(graphImage, "PNG", imgX, y + 8, drawW, drawH);
      y += drawH + 16 + 20;
    } catch {
      // ignore image failures — report still useful without it
    }
  }

  // ---- id -> value lookup for relationship rows ----
  const idToValue = new Map(graph.entities.map((e) => [e.id, e.value]));

  // ---- Cross-feed matches ----
  const matches = graph.entities.filter((e) => e.matched);
  if (matches.length) {
    doc.addPage();
    y = margin;
    doc.setTextColor(MATCH);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(`Cross-feed matches (${matches.length})`, margin, y);
    y += 6;
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Indicator", "Type", "Risk", "Seen in feeds"]],
      body: matches
        .slice(0, MAX_TABLE_ROWS)
        .sort((a, b) => b.riskScore - a.riskScore)
        .map((e) => [
          e.value,
          ENTITY_KIND_LABEL[e.kind],
          e.riskScore ? `${e.riskScore}` : "—",
          e.feeds.join(", "),
        ]),
      theme: "striped",
      styles: { fontSize: 8, cellPadding: 3, overflow: "linebreak" },
      headStyles: { fillColor: MATCH, textColor: "#ffffff" },
      columnStyles: {
        0: { cellWidth: 200, font: "courier" },
        2: { halign: "right", cellWidth: 40 },
      },
    });
  }

  // ---- Relationships grouped by confidence band (spec output format) ----
  if (graph.relationships.length) {
    doc.addPage();
    y = margin;
    const bands: { title: string; color: string; min: number; max: number }[] = [
      { title: "High Confidence Relationships", color: "#16a34a", min: 80, max: 100 },
      { title: "Moderate Confidence Relationships", color: "#ca8a04", min: 50, max: 79 },
      { title: "Low Confidence Relationships", color: "#dc2626", min: 20, max: 49 },
      { title: "Unknown Relationships", color: MUTED, min: 0, max: 19 },
    ];
    const sortedRels = [...graph.relationships].sort(
      (a, b) => (b.confidence ?? 0) - (a.confidence ?? 0),
    );
    for (const band of bands) {
      const inBand = sortedRels.filter((r) => {
        const c = r.confidence ?? 0;
        return c >= band.min && c <= band.max;
      });
      if (!inBand.length) continue;
      sectionHeading(`${band.title} (${inBand.length})`, band.color);
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [["Source", "Relationship", "Target", "Conf", "Why"]],
        body: inBand.slice(0, MAX_TABLE_ROWS).map((r) => [
          idToValue.get(r.source) || r.source,
          EDGE_KIND_LABEL[r.kind] || r.kind,
          idToValue.get(r.target) || r.target,
          String(r.confidence ?? 0),
          r.explanation?.why || "",
        ]),
        theme: "grid",
        styles: { fontSize: 7.5, cellPadding: 3, overflow: "linebreak", font: "courier" },
        headStyles: { fillColor: INK, textColor: "#ffffff", font: "helvetica" },
        columnStyles: {
          0: { cellWidth: 110 },
          1: { font: "helvetica", cellWidth: 70 },
          2: { cellWidth: 110 },
          3: { halign: "right", cellWidth: 30, font: "helvetica" },
          4: { font: "helvetica" },
        },
      });
      // @ts-expect-error runtime plugin property
      y = doc.lastAutoTable.finalY + 18;
      if (inBand.length > MAX_TABLE_ROWS) {
        writeParagraph(
          `Showing first ${MAX_TABLE_ROWS} of ${inBand.length} in this band.`,
          { size: 8, color: MUTED },
        );
      }
    }
  }

  // ---- Explain This Cluster ----
  if (clusters.length) {
    doc.addPage();
    y = margin;
    sectionHeading("Explain This Cluster");
    for (const c of clusters.slice(0, 8)) {
      ensureSpace(40);
      doc.setTextColor(ACCENT);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10.5);
      doc.text(
        `Cluster ${c.id} — ${c.size} nodes, ${c.edgeCount} relationships, avg confidence ${c.avgConfidence}%`,
        margin,
        y,
      );
      y += 14;
      writeParagraph(c.narrative);
    }
  }

  // ---- Timeline ----
  if (timeline.events.length) {
    doc.addPage();
    y = margin;
    sectionHeading("Timeline");
    writeParagraph(
      timeline.spanDays > 0
        ? `${timeline.observedCount} indicators carry timestamps, spanning ${timeline.spanDays} day` +
            `${timeline.spanDays === 1 ? "" : "s"} from ${timeline.earliest} to ${timeline.latest}.`
        : `${timeline.observedCount} indicators carry timestamps.`,
      { size: 9 },
    );
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Date", "Event", "Indicator", "Detail"]],
      body: timeline.events.slice(0, MAX_TABLE_ROWS).map((ev) => [
        ev.date,
        ev.type,
        ev.value,
        ev.detail,
      ]),
      theme: "striped",
      styles: { fontSize: 8, cellPadding: 3, overflow: "linebreak" },
      headStyles: { fillColor: INK, textColor: "#ffffff" },
      columnStyles: {
        0: { cellWidth: 90, font: "courier" },
        1: { cellWidth: 64 },
        2: { cellWidth: 130, font: "courier" },
      },
    });
    // @ts-expect-error runtime plugin property
    y = doc.lastAutoTable.finalY + 18;
  }

  // ---- Full entity inventory ----
  if (graph.entities.length) {
    doc.addPage();
    y = margin;
    doc.setTextColor(INK);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(`Entity inventory (${graph.entities.length})`, margin, y);
    y += 6;
    const sorted = [...graph.entities].sort((a, b) => {
      if (!!b.matched !== !!a.matched) return (b.matched ? 1 : 0) - (a.matched ? 1 : 0);
      return b.riskScore - a.riskScore;
    });
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Indicator", "Type", "Risk", "ASN", "Feeds"]],
      body: sorted.slice(0, MAX_TABLE_ROWS).map((e) => [
        e.value,
        ENTITY_KIND_LABEL[e.kind],
        e.riskScore ? `${e.riskScore}` : "—",
        e.asn || "—",
        e.feeds.join(", "),
      ]),
      theme: "striped",
      styles: { fontSize: 8, cellPadding: 3, overflow: "linebreak" },
      headStyles: { fillColor: INK, textColor: "#ffffff" },
      columnStyles: {
        0: { cellWidth: 180, font: "courier" },
        2: { halign: "right", cellWidth: 34 },
      },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 0) {
          const e = sorted[data.row.index];
          if (e?.matched) data.cell.styles.textColor = MATCH;
        }
      },
    });
    if (graph.entities.length > MAX_TABLE_ROWS) {
      // @ts-expect-error runtime plugin property
      const fy = doc.lastAutoTable.finalY + 14;
      doc.setTextColor(MUTED);
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.text(
        `Showing first ${MAX_TABLE_ROWS} of ${graph.entities.length} entities (matches and highest-risk first).`,
        margin,
        fy,
      );
    }
  }

  // ---- Recommended Next Investigation ----
  doc.addPage();
  y = margin;
  sectionHeading("Recommended Next Investigation");
  const recs: string[] = [];
  const unresolvedMatches = graph.entities.filter((e) => e.matched && e.riskScore === 0);
  if (anchors.length)
    recs.push(
      `Enrich the ${anchors.length} seed-anchor node${anchors.length === 1 ? "" : "s"} with current WHOIS, ` +
        `passive DNS, and TLS certificate data to confirm whether infrastructure has migrated.`,
    );
  if (bridges.length)
    recs.push(
      `Investigate the ${bridges.length} pivot node${bridges.length === 1 ? "" : "s"} first — they connect ` +
        `otherwise separate environments and are the most probable crossover points.`,
    );
  if (unresolvedMatches.length)
    recs.push(
      `Submit the ${unresolvedMatches.length} cross-source indicator${unresolvedMatches.length === 1 ? "" : "s"} ` +
        `that currently have no risk score for reputation/detection lookup.`,
    );
  recs.push(
    "Preserve source files and hashes alongside this report so every relationship remains traceable to its origin.",
  );
  for (const r of recs) {
    ensureSpace(16);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor("#334155");
    const lines = doc.splitTextToSize(`•  ${r}`, pageW - margin * 2 - 6) as string[];
    for (const line of lines) {
      ensureSpace(13);
      doc.text(line, margin + 4, y);
      y += 13;
    }
    y += 2;
  }
  y += 12;

  // ---- Safety / methodology note ----
  sectionHeading("Methodology & Safety", MUTED);
  writeParagraph(SAFETY_DISCLAIMER, { size: 8.5, color: MUTED });

  // ---- Page footers ----
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setTextColor(MUTED);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.text("NetMap — Threat Intel Relationship Mapper", margin, pageH - 20);
    doc.text(`Page ${p} of ${pages}`, pageW - margin, pageH - 20, { align: "right" });
  }

  doc.save(`netmap-report-${timestamp()}.pdf`);
}

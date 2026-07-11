import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  ENTITY_KIND_LABEL,
  EDGE_KIND_LABEL,
  feedColor,
  type EntityKind,
  type ThreatGraph,
} from "./network-types";

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

  // ---- Relationships ----
  if (graph.relationships.length) {
    doc.addPage();
    y = margin;
    doc.setTextColor(INK);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(`Relationships (${graph.relationships.length})`, margin, y);
    y += 6;
    const rels = graph.relationships.slice(0, MAX_TABLE_ROWS);
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Source", "Relationship", "Target", "Match"]],
      body: rels.map((r) => [
        idToValue.get(r.source) || r.source,
        EDGE_KIND_LABEL[r.kind] || r.kind,
        idToValue.get(r.target) || r.target,
        r.matched ? "yes" : "",
      ]),
      theme: "grid",
      styles: { fontSize: 8, cellPadding: 3, overflow: "linebreak", font: "courier" },
      headStyles: { fillColor: INK, textColor: "#ffffff", font: "helvetica" },
      columnStyles: {
        1: { font: "helvetica", cellWidth: 90 },
        3: { halign: "center", cellWidth: 44, font: "helvetica" },
      },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 3 && data.cell.raw === "yes") {
          data.cell.styles.textColor = MATCH;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
    if (graph.relationships.length > MAX_TABLE_ROWS) {
      // @ts-expect-error runtime plugin property
      const fy = doc.lastAutoTable.finalY + 14;
      doc.setTextColor(MUTED);
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.text(
        `Showing first ${MAX_TABLE_ROWS} of ${graph.relationships.length} relationships.`,
        margin,
        fy,
      );
    }
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

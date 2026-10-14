import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  ENTITY_KIND_LABEL,
  EDGE_KIND_LABEL,
  confidenceBand,
  type Entity,
  type Relationship,
  type ThreatGraph,
} from "./network-types";
import { buildTimeline } from "./timeline";
import { detectClusters } from "./clusters";
import { SAFETY_DISCLAIMER } from "./safety";
import type { SavedReportFull } from "./saved-reports";

const INK = "#232325";
const GOLD = "#b8962e";
const MUTED = "#64748b";
const LIGHT = "#f4efe2";

export interface MergedEntity extends Entity {
  reportIds: string[];
}

export interface MergedRelationship extends Relationship {
  reportIds: string[];
}

export interface CaseAggregate {
  graph: ThreatGraph;
  entities: MergedEntity[];
  relationships: MergedRelationship[];
  recurringEntities: MergedEntity[];
  recurringRelationships: MergedRelationship[];
  anchors: MergedEntity[];
  pivots: MergedEntity[];
  feeds: string[];
}

function minDate(a?: string, b?: string) {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a) <= Date.parse(b) ? a : b;
}

function maxDate(a?: string, b?: string) {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a) >= Date.parse(b) ? a : b;
}

// Union every saved snapshot into one case graph, remembering which reports
// observed each entity and relationship. Cross-report recurrence is the core
// signal of a case review: the same infrastructure surfacing in separate analyses.
export function aggregateReports(reports: SavedReportFull[]): CaseAggregate {
  const entities = new Map<string, MergedEntity>();
  const relationships = new Map<string, MergedRelationship>();
  const feeds = new Set<string>();

  for (const report of reports) {
    for (const f of report.feed_order ?? []) feeds.add(f);
    for (const e of report.graph?.entities ?? []) {
      const prev = entities.get(e.id);
      if (!prev) {
        entities.set(e.id, { ...e, feeds: [...e.feeds], reportIds: [report.id] });
        continue;
      }
      if (!prev.reportIds.includes(report.id)) prev.reportIds.push(report.id);
      prev.feeds = Array.from(new Set([...prev.feeds, ...e.feeds]));
      prev.riskScore = Math.max(prev.riskScore, e.riskScore);
      prev.firstSeen = minDate(prev.firstSeen, e.firstSeen);
      prev.lastSeen = maxDate(prev.lastSeen, e.lastSeen);
      prev.matched = prev.matched || e.matched;
      prev.isAnchor = prev.isAnchor || e.isAnchor;
      prev.isBridge = prev.isBridge || e.isBridge;
      prev.asn ??= e.asn;
      prev.asName ??= e.asName;
      if ((!prev.zone || prev.zone === "unknown") && e.zone) prev.zone = e.zone;
    }
    for (const r of report.graph?.relationships ?? []) {
      const prev = relationships.get(r.id);
      if (!prev) {
        relationships.set(r.id, { ...r, feeds: [...r.feeds], reportIds: [report.id] });
        continue;
      }
      if (!prev.reportIds.includes(report.id)) prev.reportIds.push(report.id);
      prev.feeds = Array.from(new Set([...prev.feeds, ...r.feeds]));
      prev.confidence = Math.max(prev.confidence ?? 0, r.confidence ?? 0);
      prev.matched = prev.matched || r.matched;
      prev.crossZone = prev.crossZone || r.crossZone;
    }
  }

  const entityList = Array.from(entities.values());
  const relList = Array.from(relationships.values());
  const byRecurrence = <T extends { reportIds: string[] }>(a: T, b: T) => b.reportIds.length - a.reportIds.length;

  return {
    graph: { entities: entityList, relationships: relList },
    entities: entityList,
    relationships: relList,
    recurringEntities: entityList
      .filter((e) => e.reportIds.length > 1)
      .sort((a, b) => byRecurrence(a, b) || b.riskScore - a.riskScore),
    recurringRelationships: relList
      .filter((r) => r.reportIds.length > 1)
      .sort((a, b) => byRecurrence(a, b) || (b.confidence ?? 0) - (a.confidence ?? 0)),
    anchors: entityList.filter((e) => e.isAnchor),
    pivots: entityList.filter((e) => e.isBridge),
    feeds: Array.from(feeds),
  };
}

function keyFindings(reports: SavedReportFull[], agg: CaseAggregate): string[] {
  const out: string[] = [];
  const n = reports.length;
  out.push(
    `${n} saved report${n === 1 ? "" : "s"} consolidated into ${agg.entities.length} unique entities and ${agg.relationships.length} unique relationships across ${agg.feeds.length} source feed${agg.feeds.length === 1 ? "" : "s"}.`,
  );
  if (agg.recurringEntities.length > 0) {
    const top = agg.recurringEntities.slice(0, 3).map((e) => `${e.value} (${e.reportIds.length}/${n})`);
    out.push(
      `${agg.recurringEntities.length} indicator${agg.recurringEntities.length === 1 ? "" : "s"} recur across multiple reports. Most persistent: ${top.join(", ")}.`,
    );
  } else if (n > 1) {
    out.push("No indicator recurs across reports — the analyses describe non-overlapping infrastructure.");
  }
  if (agg.recurringRelationships.length > 0) {
    out.push(
      `${agg.recurringRelationships.length} relationship${agg.recurringRelationships.length === 1 ? " was" : "s were"} independently re-observed in more than one report, strengthening those links.`,
    );
  }
  if (agg.anchors.length > 0) {
    out.push(`${agg.anchors.length} seed-anchor indicator${agg.anchors.length === 1 ? "" : "s"} present in the case.`);
  }
  if (agg.pivots.length > 0) {
    out.push(
      `${agg.pivots.length} pivot point${agg.pivots.length === 1 ? "" : "s"} bridge distinct environments (personal / corporate / adversary).`,
    );
  }
  const highRisk = agg.entities.filter((e) => e.riskScore >= 70).length;
  if (highRisk > 0) out.push(`${highRisk} entities carry a risk score of 70 or higher.`);
  return out;
}

export function generateCaseReviewPdf({
  caseName,
  caseDescription,
  reports,
}: {
  caseName: string;
  caseDescription?: string | null;
  reports: SavedReportFull[];
}) {
  const agg = aggregateReports(reports);
  const timeline = buildTimeline(agg.graph);
  const clusters = detectClusters(agg.graph);
  const reportIndex = new Map(reports.map((r, i) => [r.id, `R${i + 1}`]));
  const refs = (ids: string[]) => ids.map((id) => reportIndex.get(id) ?? "?").join(", ");
  const label = (id: string) => agg.graph.entities.find((e) => e.id === id)?.value ?? id;

  const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 40;
  let y = 0;

  const ensureSpace = (needed: number) => {
    if (y + needed > pageH - margin) {
      doc.addPage();
      y = margin;
    }
  };
  const paragraph = (text: string, opts?: { size?: number; color?: string; indent?: number }) => {
    const size = opts?.size ?? 9.5;
    const indent = opts?.indent ?? 0;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(size);
    doc.setTextColor(opts?.color ?? "#334155");
    const lines = doc.splitTextToSize(text, pageW - margin * 2 - indent) as string[];
    for (const line of lines) {
      ensureSpace(size + 5);
      doc.text(line, margin + indent, y);
      y += size + 3;
    }
    y += 4;
  };
  const heading = (title: string) => {
    ensureSpace(34);
    doc.setDrawColor(GOLD);
    doc.setLineWidth(1);
    doc.line(margin, y - 4, margin + 24, y - 4);
    doc.setTextColor(INK);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(title, margin, y + 10);
    y += 24;
  };
  const table = (head: string[], body: string[][], columnStyles?: Record<number, object>) => {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [head],
      body,
      theme: "grid",
      styles: { fontSize: 8.5, cellPadding: 4, overflow: "linebreak" },
      headStyles: { fillColor: INK, textColor: "#f3ead2" },
      alternateRowStyles: { fillColor: LIGHT },
      columnStyles,
    });
    // @ts-expect-error lastAutoTable is added by the plugin at runtime
    y = doc.lastAutoTable.finalY + 20;
  };

  // Cover band
  doc.setFillColor(INK);
  doc.rect(0, 0, pageW, 110, "F");
  doc.setTextColor("#f3ead2");
  doc.setFont("times", "bold");
  doc.setFontSize(24);
  doc.text("Theia", margin, 42);
  doc.setTextColor(GOLD);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text("CASE REVIEW FINDINGS", margin, 62);
  doc.setTextColor("#f3ead2");
  doc.setFontSize(13);
  doc.setFont("helvetica", "bold");
  doc.text(doc.splitTextToSize(caseName, pageW - margin * 2)[0] as string, margin, 84);
  doc.setTextColor("#a8a29e");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toLocaleString()}  ·  ${reports.length} report(s) consolidated`, margin, 100);
  y = 138;

  if (caseDescription) {
    heading("Case Summary");
    paragraph(caseDescription);
  }

  heading("Key Findings");
  for (const f of keyFindings(reports, agg)) {
    ensureSpace(14);
    doc.setFillColor(GOLD);
    doc.circle(margin + 3, y - 3, 1.8, "F");
    paragraph(f, { indent: 12 });
  }

  heading("Reports Included");
  table(
    ["Ref", "Title", "Saved", "Feeds", "Entities", "Rel.", "Matches"],
    reports.map((r, i) => [
      `R${i + 1}`,
      r.title,
      new Date(r.created_at).toLocaleDateString(),
      String(r.feed_order?.length ?? 0),
      String(r.entity_count),
      String(r.relationship_count),
      String(r.match_count),
    ]),
    { 0: { cellWidth: 30 }, 4: { halign: "right" }, 5: { halign: "right" }, 6: { halign: "right" } },
  );

  heading("Cross-Report Recurring Indicators");
  if (agg.recurringEntities.length === 0) {
    paragraph("No indicator appears in more than one of the selected reports.", { color: MUTED });
  } else {
    table(
      ["Indicator", "Type", "Seen in", "Risk", "ASN", "Flags"],
      agg.recurringEntities.slice(0, 150).map((e) => [
        e.value,
        ENTITY_KIND_LABEL[e.kind],
        `${e.reportIds.length}/${reports.length} (${refs(e.reportIds)})`,
        String(e.riskScore),
        e.asn ? `${e.asn}${e.asName ? ` ${e.asName}` : ""}` : "—",
        [e.isAnchor && "anchor", e.isBridge && "pivot", e.matched && "match"].filter(Boolean).join(", ") || "—",
      ]),
      { 3: { halign: "right", cellWidth: 34 } },
    );
  }

  if (agg.recurringRelationships.length > 0) {
    heading("Re-observed Relationships");
    table(
      ["Source", "Relationship", "Target", "Seen in", "Confidence"],
      agg.recurringRelationships.slice(0, 120).map((r) => [
        label(r.source),
        EDGE_KIND_LABEL[r.kind],
        label(r.target),
        refs(r.reportIds),
        r.confidence != null ? `${r.confidence} (${confidenceBand(r.confidence)})` : "—",
      ]),
    );
  }

  if (agg.anchors.length > 0 || agg.pivots.length > 0) {
    heading("Anchors and Pivot Points");
    const rows = [
      ...agg.anchors.map((e) => [e.value, "Seed anchor", e.zone ?? "unknown", refs(e.reportIds)]),
      ...agg.pivots
        .filter((e) => !e.isAnchor)
        .map((e) => [e.value, "Pivot (cross-environment)", e.zone ?? "unknown", refs(e.reportIds)]),
    ];
    table(["Indicator", "Role", "Zone", "Reports"], rows);
  }

  if (clusters.length > 0) {
    heading("Consolidated Infrastructure Clusters");
    for (const c of clusters.slice(0, 8)) {
      ensureSpace(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(INK);
      doc.text(`Cluster ${c.id + 1} — ${c.size} entities, ${c.edgeCount} links`, margin, y);
      y += 13;
      paragraph(c.narrative);
    }
  }

  if (timeline.events.length > 0) {
    heading("Consolidated Timeline");
    paragraph(
      `Observed activity spans ${timeline.spanDays} day(s)${timeline.earliest ? `, from ${timeline.earliest}` : ""}${timeline.latest ? ` to ${timeline.latest}` : ""}.`,
      { color: MUTED },
    );
    table(
      ["Date", "Event", "Indicator", "Detail"],
      timeline.events.slice(0, 80).map((ev) => [ev.date, ev.type, ev.value, ev.detail]),
      { 0: { cellWidth: 80 }, 1: { cellWidth: 60 } },
    );
  }

  const withNotes = reports.filter((r) => r.notes);
  if (withNotes.length > 0) {
    heading("Analyst Notes");
    for (const r of withNotes) {
      ensureSpace(28);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(INK);
      doc.text(`${reportIndex.get(r.id)} · ${r.title}`, margin, y);
      y += 13;
      paragraph(r.notes!);
    }
  }

  heading("Handling Note");
  paragraph(SAFETY_DISCLAIMER, { color: MUTED, size: 8.5 });

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(MUTED);
    doc.text(`Theia · Case Review Findings · ${caseName}`, margin, pageH - 20);
    doc.text(`${i} / ${pages}`, pageW - margin, pageH - 20, { align: "right" });
  }

  const slug = caseName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "case";
  doc.save(`theia-case-review-${slug}-${new Date().toISOString().slice(0, 10)}.pdf`);
}

import { createClient } from "@/lib/supabase/client";
import type { ThreatGraph } from "@/lib/network-types";
import type { ReportStats } from "@/lib/report";

export interface CaseRow {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
}

export interface SavedReportMeta {
  id: string;
  case_id: string | null;
  title: string;
  notes: string | null;
  feed_order: string[];
  entity_count: number;
  relationship_count: number;
  match_count: number;
  created_at: string;
}

export interface SavedReportFull extends SavedReportMeta {
  stats: ReportStats;
  graph: ThreatGraph;
}

const META_COLUMNS =
  "id, case_id, title, notes, feed_order, entity_count, relationship_count, match_count, created_at";

export async function fetchUser() {
  const { data } = await createClient().auth.getUser();
  return data.user;
}

export async function fetchCases(): Promise<CaseRow[]> {
  const { data, error } = await createClient()
    .from("cases")
    .select("id, name, description, created_at")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data ?? [];
}

export async function fetchReportList(): Promise<SavedReportMeta[]> {
  const { data, error } = await createClient()
    .from("saved_reports")
    .select(META_COLUMNS)
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data ?? [];
}

export async function fetchFullReports(ids: string[]): Promise<SavedReportFull[]> {
  if (ids.length === 0) return [];
  const { data, error } = await createClient()
    .from("saved_reports")
    .select(`${META_COLUMNS}, stats, graph`)
    .in("id", ids)
    .order("created_at", { ascending: true });
  if (error) throw error;
  return (data ?? []) as SavedReportFull[];
}

export async function createCase(name: string, description?: string): Promise<CaseRow> {
  const { data, error } = await createClient()
    .from("cases")
    .insert({ name: name.trim().slice(0, 200), description: description?.trim().slice(0, 5000) || null })
    .select("id, name, description, created_at")
    .single();
  if (error) throw error;
  return data;
}

export async function deleteCase(id: string) {
  const { error } = await createClient().from("cases").delete().eq("id", id);
  if (error) throw error;
}

export async function saveReport(input: {
  title: string;
  notes?: string;
  caseId: string | null;
  feedOrder: string[];
  stats: ReportStats;
  graph: ThreatGraph;
}) {
  const { error } = await createClient()
    .from("saved_reports")
    .insert({
      title: input.title.trim().slice(0, 200),
      notes: input.notes?.trim().slice(0, 10000) || null,
      case_id: input.caseId,
      feed_order: input.feedOrder,
      stats: input.stats,
      graph: input.graph,
      entity_count: input.stats.entities,
      relationship_count: input.stats.relationships,
      match_count: input.stats.matchedEntities,
    });
  if (error) throw error;
}

export async function moveReport(id: string, caseId: string | null) {
  const { error } = await createClient().from("saved_reports").update({ case_id: caseId }).eq("id", id);
  if (error) throw error;
}

export async function deleteReport(id: string) {
  const { error } = await createClient().from("saved_reports").delete().eq("id", id);
  if (error) throw error;
}

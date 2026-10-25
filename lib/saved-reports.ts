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

const GRAPH_BUCKET = "report-graphs";

async function gzipJson(value: unknown): Promise<Blob> {
  const stream = new Blob([JSON.stringify(value)]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Response(stream).blob();
}

async function gunzipJson<T>(blob: Blob): Promise<T> {
  const stream = blob.stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(stream).text()) as T;
}

async function downloadGraph(path: string): Promise<ThreatGraph> {
  const { data, error } = await createClient().storage.from(GRAPH_BUCKET).download(path);
  if (error || !data) throw error ?? new Error("Could not download report graph");
  return gunzipJson<ThreatGraph>(data);
}

async function removeGraphFiles(paths: (string | null)[]) {
  const files = paths.filter((p): p is string => Boolean(p));
  if (files.length > 0) await createClient().storage.from(GRAPH_BUCKET).remove(files);
}

export async function fetchFullReports(ids: string[]): Promise<SavedReportFull[]> {
  if (ids.length === 0) return [];
  const { data, error } = await createClient()
    .from("saved_reports")
    .select(`${META_COLUMNS}, stats, graph, graph_path`)
    .in("id", ids)
    .order("created_at", { ascending: true });
  if (error) throw error;
  const rows = (data ?? []) as (SavedReportFull & { graph: ThreatGraph | null; graph_path: string | null })[];
  return Promise.all(
    rows.map(async ({ graph_path, ...row }) => ({
      ...row,
      graph: row.graph ?? (graph_path ? await downloadGraph(graph_path) : { nodes: [], edges: [] } as unknown as ThreatGraph),
    })),
  );
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
  const supabase = createClient();
  const { data } = await supabase.from("saved_reports").select("id, graph_path").eq("case_id", id);
  const { error } = await supabase.from("cases").delete().eq("id", id);
  if (error) throw error;
  const ids = (data ?? []).map((r) => r.id);
  if (ids.length === 0) return;
  const { data: survivors } = await supabase.from("saved_reports").select("id").in("id", ids);
  const kept = new Set((survivors ?? []).map((r) => r.id));
  await removeGraphFiles((data ?? []).filter((r) => !kept.has(r.id)).map((r) => r.graph_path));
}

export async function saveReport(input: {
  title: string;
  notes?: string;
  caseId: string | null;
  feedOrder: string[];
  stats: ReportStats;
  graph: ThreatGraph;
}) {
  const supabase = createClient();
  const user = await fetchUser();
  if (!user) throw new Error("You need to be signed in to save reports");

  const graphPath = `${user.id}/${crypto.randomUUID()}.json.gz`;
  const { error: uploadError } = await supabase.storage
    .from(GRAPH_BUCKET)
    .upload(graphPath, await gzipJson(input.graph), { contentType: "application/gzip", upsert: false });
  if (uploadError) throw uploadError;

  const { error } = await supabase.from("saved_reports").insert({
    title: input.title.trim().slice(0, 200),
    notes: input.notes?.trim().slice(0, 10000) || null,
    case_id: input.caseId,
    feed_order: input.feedOrder,
    stats: input.stats,
    graph: null,
    graph_path: graphPath,
    entity_count: input.stats.entities,
    relationship_count: input.stats.relationships,
    match_count: input.stats.matchedEntities,
  });
  if (error) {
    await removeGraphFiles([graphPath]);
    throw error;
  }
}

export async function moveReport(id: string, caseId: string | null) {
  const { error } = await createClient().from("saved_reports").update({ case_id: caseId }).eq("id", id);
  if (error) throw error;
}

export async function deleteReport(id: string) {
  const supabase = createClient();
  const { data } = await supabase.from("saved_reports").select("graph_path").eq("id", id).maybeSingle();
  const { error } = await supabase.from("saved_reports").delete().eq("id", id);
  if (error) throw error;
  await removeGraphFiles([data?.graph_path ?? null]);
}

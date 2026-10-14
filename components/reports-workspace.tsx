"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { ArrowLeft, FileStack, FolderPlus, LogOut, Orbit, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { createClient } from "@/lib/supabase/client";
import {
  createCase,
  deleteCase,
  deleteReport,
  fetchCases,
  fetchFullReports,
  fetchReportList,
  fetchUser,
  moveReport,
  type CaseRow,
} from "@/lib/saved-reports";
import { generateCaseReviewPdf } from "@/lib/case-review";

const ALL = "__all";
const UNFILED = "__unfiled";

export function ReportsWorkspace() {
  const router = useRouter();
  const { data: user } = useSWR("auth-user", fetchUser);
  const { data: cases, mutate: mutateCases } = useSWR("cases", fetchCases);
  const { data: reports, mutate: mutateReports, isLoading } = useSWR("saved-reports", fetchReportList);

  const [activeCase, setActiveCase] = useState<string>(ALL);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [newCaseName, setNewCaseName] = useState("");
  const [newCaseDesc, setNewCaseDesc] = useState("");
  const [creating, setCreating] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const caseById = useMemo(() => new Map((cases ?? []).map((c) => [c.id, c])), [cases]);
  const activeCaseRow: CaseRow | undefined = caseById.get(activeCase);

  const visible = useMemo(() => {
    const list = reports ?? [];
    if (activeCase === ALL) return list;
    if (activeCase === UNFILED) return list.filter((r) => !r.case_id);
    return list.filter((r) => r.case_id === activeCase);
  }, [reports, activeCase]);

  const countFor = (key: string) =>
    (reports ?? []).filter((r) => (key === UNFILED ? !r.case_id : r.case_id === key)).length;

  const selectedVisible = visible.filter((r) => selected.has(r.id));
  const allVisibleSelected = visible.length > 0 && selectedVisible.length === visible.length;

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const toggleAll = () =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) visible.forEach((r) => next.delete(r.id));
      else visible.forEach((r) => next.add(r.id));
      return next;
    });

  const run = async (fn: () => Promise<void>) => {
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : "Something went wrong.");
    }
  };

  const handleCreateCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;
    setCreating(true);
    run(async () => {
      const created = await createCase(newCaseName, newCaseDesc);
      await mutateCases();
      setActiveCase(created.id);
      setNewCaseName("");
      setNewCaseDesc("");
    }).finally(() => setCreating(false));
  };

  const handleDeleteCase = (c: CaseRow) => {
    if (!window.confirm(`Delete case "${c.name}"? Its reports are kept and become unfiled.`)) return;
    run(async () => {
      await deleteCase(c.id);
      setActiveCase(ALL);
      await Promise.all([mutateCases(), mutateReports()]);
    });
  };

  const handleDeleteReport = (id: string, title: string) => {
    if (!window.confirm(`Delete saved report "${title}"?`)) return;
    run(async () => {
      await deleteReport(id);
      setSelected((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      await mutateReports();
    });
  };

  const handleMove = (id: string, value: string) =>
    run(async () => {
      await moveReport(id, value === UNFILED ? null : value);
      await mutateReports();
    });

  const handleGenerate = () => {
    if (selectedVisible.length === 0) return;
    setGenerating(true);
    run(async () => {
      const full = await fetchFullReports(selectedVisible.map((r) => r.id));
      generateCaseReviewPdf({
        caseName: activeCaseRow?.name ?? (activeCase === UNFILED ? "Unfiled reports" : "Combined review"),
        caseDescription: activeCaseRow?.description,
        reports: full,
      });
    }).finally(() => setGenerating(false));
  };

  const handleSignOut = async () => {
    await createClient().auth.signOut();
    router.push("/");
    router.refresh();
  };

  const navItem = (key: string, label: string, count: number, row?: CaseRow) => (
    <li key={key} className="group flex items-center">
      <button
        type="button"
        onClick={() => setActiveCase(key)}
        aria-current={activeCase === key ? "page" : undefined}
        className={`flex min-h-[40px] flex-1 items-center justify-between gap-2 rounded-md px-3 text-left text-sm transition-colors ${
          activeCase === key
            ? "bg-primary/15 text-primary"
            : "text-muted-foreground hover:bg-secondary hover:text-foreground"
        }`}
      >
        <span className="truncate">{label}</span>
        <span className="font-mono text-xs">{count}</span>
      </button>
      {row && (
        <button
          type="button"
          onClick={() => handleDeleteCase(row)}
          className="ml-1 rounded p-2 text-muted-foreground opacity-0 transition-opacity hover:text-destructive focus-visible:opacity-100 group-hover:opacity-100"
          aria-label={`Delete case ${row.name}`}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      )}
    </li>
  );

  return (
    <main className="flex min-h-dvh flex-col bg-background">
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <Link href="/" className="flex items-center gap-3">
          <Orbit className="h-6 w-6 text-primary" aria-hidden="true" />
          <span className="flex flex-col leading-none">
            <span
              className="font-serif text-2xl font-semibold tracking-wide text-foreground"
              style={{ fontFamily: "var(--font-garamond), 'EB Garamond', serif" }}
            >
              Theia
            </span>
            <span className="mt-1 text-[0.65rem] uppercase tracking-[0.28em] text-muted-foreground">
              Infrastructure Link Analysis
            </span>
          </span>
        </Link>
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href="/">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to map
            </Link>
          </Button>
          <span className="hidden font-mono text-xs text-muted-foreground md:inline">{user?.email}</span>
          <Button variant="ghost" size="sm" onClick={handleSignOut} aria-label="Sign out">
            <LogOut className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>
      </header>

      <div className="flex flex-1 flex-col lg:flex-row">
        <aside className="flex flex-col gap-6 border-b border-border p-4 lg:w-72 lg:border-b-0 lg:border-r">
          <nav aria-label="Cases" className="flex flex-col gap-2">
            <h2 className="px-3 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">Cases</h2>
            <ul className="flex flex-col gap-0.5">
              {navItem(ALL, "All reports", reports?.length ?? 0)}
              {navItem(UNFILED, "Unfiled", countFor(UNFILED))}
              {(cases ?? []).map((c) => navItem(c.id, c.name, countFor(c.id), c))}
            </ul>
          </nav>

          <form onSubmit={handleCreateCase} className="flex flex-col gap-2 border-t border-border pt-4">
            <h2 className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">New case</h2>
            <Input
              aria-label="Case name"
              placeholder="Case name"
              maxLength={200}
              value={newCaseName}
              onChange={(e) => setNewCaseName(e.target.value)}
            />
            <Textarea
              aria-label="Case summary"
              placeholder="Summary (appears in findings)"
              rows={3}
              maxLength={5000}
              value={newCaseDesc}
              onChange={(e) => setNewCaseDesc(e.target.value)}
            />
            <Button type="submit" variant="outline" size="sm" disabled={creating || !newCaseName.trim()}>
              <FolderPlus className="h-4 w-4" aria-hidden="true" />
              {creating ? "Creating..." : "Create case"}
            </Button>
          </form>
        </aside>

        <section className="flex flex-1 flex-col gap-5 p-4 lg:p-6">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="flex flex-col gap-1">
              <h1
                className="font-serif text-3xl font-semibold text-foreground text-balance"
                style={{ fontFamily: "var(--font-garamond), 'EB Garamond', serif" }}
              >
                {activeCaseRow?.name ?? (activeCase === UNFILED ? "Unfiled reports" : "Saved reports")}
              </h1>
              <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground text-pretty">
                {activeCaseRow?.description ||
                  "Select saved reports and generate Case Review Findings: a consolidated PDF of recurring indicators, re-observed links, pivots, and a merged timeline."}
              </p>
            </div>
            <Button onClick={handleGenerate} disabled={generating || selectedVisible.length === 0}>
              <FileStack className="h-4 w-4" aria-hidden="true" />
              {generating
                ? "Building findings..."
                : `Case Review Findings${selectedVisible.length ? ` (${selectedVisible.length})` : ""}`}
            </Button>
          </div>

          {error && (
            <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          )}

          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading reports...</p>
          ) : visible.length === 0 ? (
            <div className="flex flex-col items-start gap-3 rounded-lg border border-dashed border-border p-8">
              <p className="text-sm text-foreground">No saved reports here yet.</p>
              <p className="text-sm leading-relaxed text-muted-foreground">
                Map your feeds, then use <span className="text-primary">Save report</span> above the graph to keep a snapshot.
              </p>
              <Button asChild variant="outline" size="sm">
                <Link href="/">Go to the map</Link>
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-card text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th scope="col" className="w-10 px-3 py-3">
                      <Checkbox
                        checked={allVisibleSelected}
                        onCheckedChange={toggleAll}
                        aria-label="Select all reports"
                      />
                    </th>
                    <th scope="col" className="px-3 py-3 font-medium">Report</th>
                    <th scope="col" className="px-3 py-3 text-right font-medium">Entities</th>
                    <th scope="col" className="px-3 py-3 text-right font-medium">Links</th>
                    <th scope="col" className="px-3 py-3 text-right font-medium">Matches</th>
                    <th scope="col" className="px-3 py-3 font-medium">Case</th>
                    <th scope="col" className="w-10 px-3 py-3">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {visible.map((r) => (
                    <tr key={r.id} className={selected.has(r.id) ? "bg-primary/5" : undefined}>
                      <td className="px-3 py-3 align-top">
                        <Checkbox
                          checked={selected.has(r.id)}
                          onCheckedChange={() => toggle(r.id)}
                          aria-label={`Select ${r.title}`}
                        />
                      </td>
                      <td className="px-3 py-3 align-top">
                        <div className="flex flex-col gap-1">
                          <span className="font-medium text-foreground">{r.title}</span>
                          <span className="font-mono text-xs text-muted-foreground">
                            {new Date(r.created_at).toLocaleString()} · {r.feed_order.join(", ") || "no feeds"}
                          </span>
                          {r.notes && (
                            <p className="line-clamp-2 max-w-xl text-xs leading-relaxed text-muted-foreground">{r.notes}</p>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3 text-right align-top font-mono">{r.entity_count}</td>
                      <td className="px-3 py-3 text-right align-top font-mono">{r.relationship_count}</td>
                      <td className="px-3 py-3 text-right align-top font-mono text-primary">{r.match_count}</td>
                      <td className="px-3 py-3 align-top">
                        <Select value={r.case_id ?? UNFILED} onValueChange={(v) => handleMove(r.id, v)}>
                          <SelectTrigger size="sm" className="w-44" aria-label={`Case for ${r.title}`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value={UNFILED}>Unfiled</SelectItem>
                            {(cases ?? []).map((c) => (
                              <SelectItem key={c.id} value={c.id}>
                                {c.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </td>
                      <td className="px-3 py-3 align-top">
                        <button
                          type="button"
                          onClick={() => handleDeleteReport(r.id, r.title)}
                          className="rounded p-2 text-muted-foreground transition-colors hover:text-destructive"
                          aria-label={`Delete ${r.title}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

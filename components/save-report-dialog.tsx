"use client";

import { useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { BookmarkPlus, Check } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { createCase, fetchCases, fetchUser, saveReport } from "@/lib/saved-reports";
import type { ThreatGraph } from "@/lib/network-types";
import type { ReportStats } from "@/lib/report";

const NO_CASE = "__none";
const NEW_CASE = "__new";

export function SaveReportDialog({
  disabled,
  getSnapshot,
}: {
  disabled: boolean;
  getSnapshot: () => { graph: ThreatGraph; feedOrder: string[]; stats: ReportStats };
}) {
  const [open, setOpen] = useState(false);
  const { data: user, isLoading: userLoading } = useSWR(open ? "auth-user" : null, fetchUser);
  const { data: cases, mutate: mutateCases } = useSWR(user ? "cases" : null, fetchCases);

  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const [caseChoice, setCaseChoice] = useState<string>(NO_CASE);
  const [newCaseName, setNewCaseName] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (next) {
      const snap = getSnapshot();
      setTitle(`${snap.feedOrder.slice(0, 2).join(" + ") || "Analysis"} — ${new Date().toLocaleDateString()}`);
      setNotes("");
      setError(null);
      setSaved(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      let caseId: string | null = caseChoice === NO_CASE || caseChoice === NEW_CASE ? null : caseChoice;
      if (caseChoice === NEW_CASE) {
        if (!newCaseName.trim()) throw new Error("Name the new case.");
        const created = await createCase(newCaseName);
        caseId = created.id;
        mutateCases();
        setCaseChoice(created.id);
        setNewCaseName("");
      }
      await saveReport({ ...getSnapshot(), title, notes, caseId });
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : "Could not save the report.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          className="inline-flex min-h-[36px] items-center gap-1.5 rounded-md border border-primary/60 bg-card px-3 text-xs font-medium text-primary transition-colors hover:bg-primary/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <BookmarkPlus className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Save report</span>
        </button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Save report</DialogTitle>
          <DialogDescription>
            Saves the current filtered map as a snapshot. File it under a case to roll it into case review findings.
          </DialogDescription>
        </DialogHeader>

        {userLoading ? (
          <p className="text-sm text-muted-foreground">Checking your session...</p>
        ) : !user ? (
          <div className="flex flex-col gap-4">
            <p className="text-sm leading-relaxed text-muted-foreground">
              Saved reports are private to your account. Sign in to keep this analysis.
            </p>
            <Button asChild>
              <Link href="/auth/login?next=/">Sign in to save</Link>
            </Button>
          </div>
        ) : saved ? (
          <div className="flex flex-col gap-4">
            <p className="flex items-center gap-2 text-sm text-foreground">
              <Check className="h-4 w-4 text-primary" aria-hidden="true" />
              Report saved.
            </p>
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>
                Close
              </Button>
              <Button asChild>
                <Link href="/reports">Open saved reports</Link>
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={handleSave} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="report-title">Title</Label>
              <Input id="report-title" required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="report-case">Case</Label>
              <Select value={caseChoice} onValueChange={setCaseChoice}>
                <SelectTrigger id="report-case" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_CASE}>Unfiled</SelectItem>
                  {(cases ?? []).map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.name}
                    </SelectItem>
                  ))}
                  <SelectItem value={NEW_CASE}>+ New case...</SelectItem>
                </SelectContent>
              </Select>
              {caseChoice === NEW_CASE && (
                <Input
                  aria-label="New case name"
                  placeholder="Case name, e.g. Operation Volano"
                  maxLength={200}
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                />
              )}
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="report-notes">Analyst notes</Label>
              <Textarea
                id="report-notes"
                rows={4}
                maxLength={10000}
                placeholder="What this snapshot shows, assumptions, next steps..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <DialogFooter>
              <Button type="submit" disabled={saving}>
                {saving ? "Saving..." : "Save report"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

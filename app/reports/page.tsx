import type { Metadata } from "next";
import { ReportsWorkspace } from "@/components/reports-workspace";

export const metadata: Metadata = {
  title: "Saved Reports — Theia",
  description: "Saved Theia analyses, organized into cases and aggregated into case review findings.",
};

export default function ReportsPage() {
  return <ReportsWorkspace />;
}

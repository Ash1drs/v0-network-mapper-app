import Link from "next/link";
import { Orbit } from "lucide-react";

export function AuthShell({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <main className="flex min-h-dvh w-full items-center justify-center bg-background p-6">
      <div className="flex w-full max-w-sm flex-col gap-8">
        <Link href="/" className="flex items-center gap-3 self-center">
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
        <section className="flex flex-col gap-6 rounded-lg border border-border bg-card p-6">
          <header className="flex flex-col gap-1.5">
            <h1 className="text-xl font-semibold text-foreground text-balance">{title}</h1>
            <p className="text-sm leading-relaxed text-muted-foreground text-pretty">{description}</p>
          </header>
          {children}
        </section>
      </div>
    </main>
  );
}

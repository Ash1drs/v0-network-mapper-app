"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AuthShell } from "@/components/auth-shell";
import { createConfirmedAccount } from "./actions";

function signUpErrorMessage(error: unknown): string {
  const { code, status } = (error ?? {}) as { code?: string; status?: number };
  if (code === "weak_password") return "That password is too weak. Use at least 8 characters with a mix of types.";
  if (code === "over_email_send_rate_limit" || code === "over_request_rate_limit" || status === 429)
    return "Too many attempts. Please wait a moment and try again.";
  if (code === "email_address_invalid") return "Please use a valid email address.";
  return "Something went wrong. Please try again.";
}

function SignUpForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const nextParam = useSearchParams().get("next");
  const next = nextParam && nextParam.startsWith("/") && !nextParam.startsWith("//") ? nextParam : "/reports";

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== repeat) {
      setError("Passwords do not match.");
      return;
    }
    setIsLoading(true);
    const result = await createConfirmedAccount(email, password);
    if (!result.ok) {
      setIsLoading(false);
      setError(result.error);
      return;
    }
    const { error } = await createClient().auth.signInWithPassword({ email: email.trim().toLowerCase(), password });
    setIsLoading(false);
    if (error) {
      setError(signUpErrorMessage(error));
      return;
    }
    router.push(next);
    router.refresh();
  };

  return (
    <form onSubmit={handleSignUp} className="flex flex-col gap-5">
      <div className="flex flex-col gap-2">
        <Label htmlFor="email">Email</Label>
        <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="password">Password</Label>
        <Input id="password" type="password" autoComplete="new-password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="repeat-password">Repeat password</Label>
        <Input id="repeat-password" type="password" autoComplete="new-password" required value={repeat} onChange={(e) => setRepeat(e.target.value)} />
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={isLoading}>
        {isLoading ? "Creating account..." : "Create account"}
      </Button>
      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link href="/auth/login" className="text-primary underline underline-offset-4">
          Sign in
        </Link>
      </p>
    </form>
  );
}

export default function SignUpPage() {
  return (
    <AuthShell title="Create an account" description="Your saved reports and cases are private to your account.">
      <Suspense>
        <SignUpForm />
      </Suspense>
    </AuthShell>
  );
}

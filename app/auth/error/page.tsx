import Link from "next/link";
import { AuthShell } from "@/components/auth-shell";

export default function AuthErrorPage() {
  return (
    <AuthShell
      title="Sign-in link problem"
      description="That confirmation link is invalid or has expired. Try signing in, or request a new link by signing up again."
    >
      <Link href="/auth/login" className="text-sm text-primary underline underline-offset-4">
        Back to sign in
      </Link>
    </AuthShell>
  );
}

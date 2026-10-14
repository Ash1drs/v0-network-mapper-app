import Link from "next/link";
import { AuthShell } from "@/components/auth-shell";

export default function SignUpSuccessPage() {
  return (
    <AuthShell
      title="Check your email"
      description="We sent you a confirmation link. Confirm your address, then sign in to start saving reports."
    >
      <Link href="/auth/login" className="text-sm text-primary underline underline-offset-4">
        Back to sign in
      </Link>
    </AuthShell>
  );
}

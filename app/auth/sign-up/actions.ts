"use server";

import { createClient } from "@supabase/supabase-js";

export type SignUpResult = { ok: true } | { ok: false; error: string };

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Accounts are created pre-confirmed with the admin API so sign-up never depends on
// an emailed confirmation link (which requires Supabase dashboard URL configuration).
export async function createConfirmedAccount(email: string, password: string): Promise<SignUpResult> {
  const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.length > 254) {
    return { ok: false, error: "Please use a valid email address." };
  }
  if (typeof password !== "string" || password.length < 8 || password.length > 72) {
    return { ok: false, error: "Password must be between 8 and 72 characters." };
  }

  const url = process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY;
  if (!url || !serviceKey) {
    return { ok: false, error: "Sign-up is not configured. Please try again later." };
  }

  const admin = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { error } = await admin.auth.admin.createUser({
    email: normalizedEmail,
    password,
    email_confirm: true,
  });

  if (error) {
    const code = (error as { code?: string }).code;
    if (code === "email_exists" || code === "user_already_exists") {
      return { ok: false, error: "An account with that email already exists. Sign in instead." };
    }
    if (code === "weak_password") {
      return { ok: false, error: "That password is too weak. Use at least 8 characters with a mix of types." };
    }
    return { ok: false, error: "Something went wrong. Please try again." };
  }

  return { ok: true };
}

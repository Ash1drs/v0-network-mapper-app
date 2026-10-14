import type { CookieOptions } from "@supabase/ssr";

// The v0 preview renders the app inside a cross-site iframe, where SameSite=Lax
// cookies are dropped — the session would never persist. Production stays Lax.
export const supabaseCookieOptions: CookieOptions =
  process.env.NODE_ENV === "production"
    ? { sameSite: "lax", secure: true }
    : { sameSite: "none", secure: true };

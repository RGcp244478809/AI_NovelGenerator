"use client";

import { FormEvent, useState } from "react";
import { useParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { login } from "@/lib/auth";

function safeNextPath(locale: string): string {
  const candidate = new URLSearchParams(window.location.search).get("next");
  if (!candidate || !candidate.startsWith(`/${locale}`) || candidate.startsWith(`/${locale}/login`)) {
    return `/${locale}`;
  }
  return candidate;
}

export default function LoginPage() {
  const t = useTranslations("auth");
  const params = useParams<{ locale: string }>();
  const locale = params.locale === "en" ? "en" : "zh";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError("");
    try {
      await login(username, password);
      window.location.replace(safeNextPath(locale));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : t("loginFailed"));
      setSubmitting(false);
    }
  };

  const switchLocale = (nextLocale: "zh" | "en") => {
    if (nextLocale === locale) return;
    const next = new URLSearchParams(window.location.search).get("next");
    const translatedNext = next?.replace(/^\/(zh|en)(?=\/|$)/, `/${nextLocale}`);
    const query = translatedNext ? `?next=${encodeURIComponent(translatedNext)}` : "";
    window.location.assign(`/${nextLocale}/login${query}`);
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4 py-10">
      <div className="pointer-events-none absolute inset-0 opacity-70" aria-hidden="true">
        <div className="absolute left-[8%] top-[12%] size-64 rounded-full bg-accent/10 blur-3xl" />
        <div className="absolute bottom-[8%] right-[10%] size-80 rounded-full bg-warm-300/20 blur-3xl" />
      </div>

      <section className="relative w-full max-w-md rounded-2xl border border-border bg-surface-raised p-7 shadow-[0_24px_80px_-32px_rgb(0_0_0/0.35)] sm:p-9">
        <div className="mb-8 flex items-start justify-between gap-4">
          <div>
            <div className="mb-4 flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
              <svg className="size-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
                <path d="M4 4.5h6a3 3 0 0 1 3 3V21a4 4 0 0 0-4-2H4z" />
                <path d="M13 7.5a3 3 0 0 1 3-3h4V19h-3a4 4 0 0 0-4 2" />
              </svg>
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">{t("title")}</h1>
            <p className="mt-2 text-sm text-muted">{t("description")}</p>
          </div>
          <div className="flex rounded-lg border border-border bg-surface-secondary p-0.5">
            {(["zh", "en"] as const).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => switchLocale(value)}
                aria-pressed={locale === value}
                className={`min-h-8 rounded-md px-2 text-xs font-medium transition-colors ${
                  locale === value ? "bg-accent text-accent-foreground" : "text-muted hover:text-foreground"
                }`}
              >
                {value === "zh" ? "中文" : "EN"}
              </button>
            ))}
          </div>
        </div>

        <form className="grid gap-5" onSubmit={submit}>
          <label className="grid gap-2 text-sm font-medium text-foreground">
            {t("username")}
            <input
              autoComplete="username"
              autoFocus
              required
              maxLength={128}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="h-11 rounded-lg border border-border bg-background px-3 text-foreground outline-none transition focus:border-accent focus:ring-2 focus:ring-accent/15"
            />
          </label>
          <label className="grid gap-2 text-sm font-medium text-foreground">
            {t("password")}
            <input
              type="password"
              autoComplete="current-password"
              required
              maxLength={1024}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="h-11 rounded-lg border border-border bg-background px-3 text-foreground outline-none transition focus:border-accent focus:ring-2 focus:ring-accent/15"
            />
          </label>

          {error && (
            <p role="alert" className="rounded-lg border border-danger/25 bg-danger/10 px-3 py-2.5 text-sm text-danger">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="mt-1 flex h-11 items-center justify-center rounded-lg bg-accent px-4 font-medium text-accent-foreground transition hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? t("signingIn") : t("signIn")}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-muted">{t("securityHint")}</p>
      </section>
    </div>
  );
}

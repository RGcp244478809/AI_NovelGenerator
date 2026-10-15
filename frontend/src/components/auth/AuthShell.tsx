/* eslint-disable react-hooks/set-state-in-effect */
"use client";

import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  AUTH_REQUIRED_EVENT,
  getAuthSession,
} from "@/lib/auth";
import { WorkspacePages } from "@/components/layout/WorkspacePages";

type AuthState = "checking" | "authenticated" | "unauthenticated";

export function AuthShell({
  children,
  locale,
  modal,
  navigation,
}: {
  children: React.ReactNode;
  locale: string;
  modal: React.ReactNode;
  navigation: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [state, setState] = useState<AuthState>("checking");
  const loginPath = `/${locale}/login`;
  const isLoginPage = pathname === loginPath;

  const redirectToLogin = useCallback(() => {
    setState("unauthenticated");
    const next = pathname && pathname !== loginPath ? `?next=${encodeURIComponent(pathname)}` : "";
    router.replace(`${loginPath}${next}`);
  }, [loginPath, pathname, router]);

  useEffect(() => {
    if (isLoginPage) return;

    const controller = new AbortController();
    void getAuthSession(controller.signal)
      .then((session) => {
        if (session.authenticated) {
          setState("authenticated");
        } else {
          redirectToLogin();
        }
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        redirectToLogin();
      });
    return () => controller.abort();
  }, [isLoginPage, redirectToLogin]);

  useEffect(() => {
    if (isLoginPage) return;
    window.addEventListener(AUTH_REQUIRED_EVENT, redirectToLogin);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, redirectToLogin);
  }, [isLoginPage, redirectToLogin]);

  if (isLoginPage) {
    return <main className="flex min-h-screen flex-col">{children}</main>;
  }

  if (state !== "authenticated") {
    return (
      <main className="flex min-h-screen items-center justify-center bg-background">
        <div
          className="size-8 animate-spin rounded-full border-2 border-border border-t-accent"
          aria-label={state === "checking" ? "Checking session" : "Redirecting to login"}
        />
      </main>
    );
  }

  return (
    <>
      {navigation}
      <main className="flex min-h-0 flex-1 flex-col">
        <WorkspacePages>{children}</WorkspacePages>
      </main>
      {modal}
    </>
  );
}

const AUTH_SESSION_PATH = "/api/auth/session";
const AUTH_LOGIN_PATH = "/api/auth/login";
const AUTH_LOGOUT_PATH = "/api/auth/logout";

export const AUTH_REQUIRED_EVENT = "novel-generator:auth-required";

export interface AuthSession {
  authenticated: boolean;
  username: string | null;
}

type ErrorPayload = {
  detail?: string | { message?: string };
};

async function errorMessage(response: Response): Promise<string> {
  const fallback = `Request failed: ${response.status}`;
  try {
    const payload = (await response.json()) as ErrorPayload;
    if (typeof payload.detail === "string" && payload.detail) return payload.detail;
    if (
      typeof payload.detail === "object" &&
      payload.detail !== null &&
      typeof payload.detail.message === "string" &&
      payload.detail.message
    ) {
      return payload.detail.message;
    }
  } catch {
    // 非 JSON 代理错误使用稳定的状态码消息，避免把 HTML 返回给界面。
  }
  return fallback;
}

async function authRequest(path: string, init?: RequestInit): Promise<AuthSession> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
  return response.json() as Promise<AuthSession>;
}

export function getAuthSession(signal?: AbortSignal): Promise<AuthSession> {
  return authRequest(AUTH_SESSION_PATH, { method: "GET", signal });
}

export function login(username: string, password: string): Promise<AuthSession> {
  return authRequest(AUTH_LOGIN_PATH, {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function logout(): Promise<AuthSession> {
  return authRequest(AUTH_LOGOUT_PATH, { method: "POST" });
}

export function notifyAuthenticationRequired(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
  }
}

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Retrieve the Wayve auth token from localStorage.
 * Wayve's MSAL stores tokens under 'wayve_auth_tokens' (set by AuthContext.tsx).
 * Since Paperclip UI is served from the same origin (gowayve.com/agents/*),
 * it has access to the same localStorage.
 */
function getWayveToken(): string | null {
  try {
    const stored = localStorage.getItem("wayve_auth_tokens");
    if (!stored) return null;
    const tokens = JSON.parse(stored) as { accessToken?: string; idToken?: string; expiresAt?: number };
    // Wayve uses idToken as the Bearer token (see AuthContext.tsx line 204)
    return tokens.idToken ?? tokens.accessToken ?? null;
  } catch {
    return null;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers ?? undefined);
  const body = init?.body;
  if (!(body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  // Attach Wayve JWT as Bearer token if available (for Wayve-integrated mode)
  const wayveToken = getWayveToken();
  if (wayveToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${wayveToken}`);
  }

  const res = await fetch(`${BASE}${path}`, {
    headers,
    credentials: "include", // Keep cookie auth as fallback for standalone Paperclip mode
    ...init,
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new ApiError(
      (errorBody as { error?: string } | null)?.error ?? `Request failed: ${res.status}`,
      res.status,
      errorBody,
    );
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body) }),
  postForm: <T>(path: string, body: FormData) =>
    request<T>(path, { method: "POST", body }),
  put: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

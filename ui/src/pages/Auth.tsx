/**
 * Auth page — Wayve Integration
 *
 * In Wayve-integrated mode, users authenticate via Wayve's MSAL login.
 * This page checks for an existing Wayve token in localStorage.
 * If found, it uses it to authenticate with Paperclip's API.
 * If not found, it redirects to the Wayve app login.
 */

import { useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "@/lib/router";
import { authApi } from "../api/auth";
import { queryKeys } from "../lib/queryKeys";

function hasWayveToken(): boolean {
  try {
    const stored = localStorage.getItem("wayve_auth_tokens");
    if (!stored) return false;
    const tokens = JSON.parse(stored) as { idToken?: string; expiresAt?: number };
    if (!tokens.idToken) return false;
    // Check if token is not expired (with 60s buffer)
    if (tokens.expiresAt && tokens.expiresAt < Date.now() / 1000 + 60) return false;
    return true;
  } catch {
    return false;
  }
}

export function AuthPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const nextPath = useMemo(() => searchParams.get("next") || "/", [searchParams]);

  // Try to get a session using the Wayve token (if available)
  const { data: session, isLoading } = useQuery({
    queryKey: queryKeys.auth.session,
    queryFn: () => authApi.getSession(),
    retry: false,
  });

  useEffect(() => {
    // If we already have a session, navigate to the requested page
    if (session) {
      navigate(nextPath, { replace: true });
      return;
    }

    // If session check is done and no session:
    if (!isLoading && !session) {
      if (hasWayveToken()) {
        // Wayve token exists but session failed — might be a timing issue, retry
        // The token will be sent as Bearer header by the API client
        return;
      }

      // No Wayve token — redirect to Wayve login
      // After Wayve login, user navigates back to /agents/* and the token will be available
      const wayveLoginUrl = window.location.origin + "/auth";
      window.location.href = wayveLoginUrl;
    }
  }, [session, isLoading, navigate, nextPath]);

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-background">
      <div className="text-center">
        <p className="text-sm text-muted-foreground">
          {isLoading ? "Connecting to Wayve..." : "Redirecting to Wayve login..."}
        </p>
      </div>
    </div>
  );
}

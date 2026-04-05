/**
 * Auth page — Wayve Integration
 *
 * In Wayve-integrated mode, users authenticate via Wayve's MSAL/native login.
 * This page checks for an existing Wayve token in localStorage or sessionStorage.
 * If found, it authenticates with Paperclip's API using the Bearer token.
 * If not found, it redirects to the Wayve app login.
 */

import { useEffect, useMemo, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "@/lib/router";
import { authApi } from "../api/auth";
import { queryKeys } from "../lib/queryKeys";
import { hasWayveToken } from "../lib/wayve-token";

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

export function AuthPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const nextPath = useMemo(() => searchParams.get("next") || "/", [searchParams]);
  const retryCount = useRef(0);

  const { data: session, isLoading, error, refetch } = useQuery({
    queryKey: queryKeys.auth.session,
    queryFn: () => authApi.getSession(),
    retry: false,
  });

  useEffect(() => {
    // If we have a session, navigate to the requested page
    if (session) {
      navigate(nextPath, { replace: true });
      return;
    }

    // Still loading — wait
    if (isLoading) return;

    // Session check is done, no session found
    if (hasWayveToken()) {
      // Token exists but session failed — retry a few times
      // (could be JWKS cache cold start, network hiccup, etc.)
      if (retryCount.current < MAX_RETRIES) {
        retryCount.current++;
        const timer = setTimeout(() => {
          void refetch();
        }, RETRY_DELAY_MS);
        return () => clearTimeout(timer);
      }

      // Retries exhausted — token might be invalid or server misconfigured
      // Redirect to Wayve login to get a fresh token
      console.warn("Wayve token exists but Paperclip session failed after retries. Redirecting to Wayve login.");
    }

    // No Wayve token or retries exhausted — redirect to Wayve auth bridge
    // The auth bridge on gowayve.com reads the token and redirects back with it in the hash
    const returnUrl = encodeURIComponent(window.location.origin);
    window.location.href = `https://www.gowayve.com/auth-bridge?return=${returnUrl}`;
  }, [session, isLoading, error, navigate, nextPath, refetch]);

  const message = isLoading
    ? "Connecting to Wayve..."
    : retryCount.current > 0
      ? `Authenticating... (attempt ${retryCount.current}/${MAX_RETRIES})`
      : "Redirecting to Wayve login...";

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-background">
      <div className="text-center">
        <p className="text-sm text-muted-foreground">{message}</p>
      </div>
    </div>
  );
}

/**
 * Wayve Token Helper — reads auth tokens from Wayve's storage.
 *
 * Wayve has two auth paths:
 * 1. Native auth (email/password) → tokens stored in localStorage('wayve_auth_tokens')
 * 2. MSAL (social login / popup) → tokens stored in sessionStorage by MSAL
 *
 * This helper checks both sources and returns a valid JWT token for API calls.
 */

interface StoredNativeTokens {
  accessToken?: string;
  idToken?: string;
  expiresAt?: number;
}

/**
 * Get a valid Wayve auth token from either native auth or MSAL storage.
 * Returns the idToken (preferred) or accessToken, or null if not authenticated.
 *
 * Also checks URL hash for tokens passed from gowayve.com via cross-domain navigation.
 */
export function getWayveToken(): string | null {
  // 0. Check if token was passed via URL hash (cross-domain from gowayve.com)
  receiveTokenFromUrl();

  // 1. Try native auth tokens (email/password login)
  const nativeToken = getNativeAuthToken();
  if (nativeToken) return nativeToken;

  // 2. Try MSAL tokens (social login / popup)
  const msalToken = getMsalToken();
  if (msalToken) return msalToken;

  return null;
}

/**
 * Check if a valid Wayve token exists (without returning it).
 */
export function hasWayveToken(): boolean {
  return getWayveToken() !== null;
}

// ── Native Auth (localStorage) ─────────────────────────────────────────────

function getNativeAuthToken(): string | null {
  try {
    const stored = localStorage.getItem("wayve_auth_tokens");
    if (!stored) return null;

    const tokens = JSON.parse(stored) as StoredNativeTokens;
    if (!tokens.idToken && !tokens.accessToken) return null;

    // Check expiry — expiresAt is in MILLISECONDS (set by AuthContext.tsx:172,339,380,432)
    if (tokens.expiresAt && tokens.expiresAt < Date.now() + 60_000) {
      return null; // Expired or about to expire (60 sec buffer)
    }

    // Wayve uses idToken as Bearer token (AuthContext.tsx:209,228,234)
    return tokens.idToken ?? tokens.accessToken ?? null;
  } catch {
    return null;
  }
}

// ── MSAL Auth (sessionStorage) ─────────────────────────────────────────────

function getMsalToken(): string | null {
  try {
    // MSAL stores tokens in sessionStorage (AuthContext.tsx:29: cacheLocation: "sessionStorage")
    // MSAL cache keys follow the pattern: msal.<clientId>.<type>
    // We look for idtoken entries which contain the JWT

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (!key) continue;

      // MSAL stores credential cache entries with keys containing "idtoken"
      // Format varies by MSAL version, but the value is always JSON with a "secret" field
      if (!key.toLowerCase().includes("idtoken")) continue;

      try {
        const value = sessionStorage.getItem(key);
        if (!value) continue;

        const parsed = JSON.parse(value) as Record<string, unknown>;
        const secret = parsed.secret as string | undefined;

        if (secret && typeof secret === "string" && secret.includes(".")) {
          // Validate it looks like a JWT (3 dot-separated parts)
          const parts = secret.split(".");
          if (parts.length === 3) {
            // Check if not expired by decoding the payload
            try {
              const payload = JSON.parse(atob(parts[1])) as { exp?: number };
              if (payload.exp && payload.exp < Date.now() / 1000 + 60) {
                continue; // Expired
              }
            } catch {
              // Can't decode — still return it, server will validate
            }
            return secret;
          }
        }
      } catch {
        continue;
      }
    }

    return null;
  } catch {
    return null;
  }
}

// ── Cross-domain token transfer (URL hash) ─────────────────────────────────

let urlTokenReceived = false;

/**
 * Check if a Wayve auth token was passed via URL hash from gowayve.com.
 * Format: #wayve_token=<base64-encoded JSON of wayve_auth_tokens>
 *
 * If found, stores it in localStorage and cleans up the URL hash.
 * This enables cross-domain auth between gowayve.com and agents.gowayve.com.
 */
function receiveTokenFromUrl(): void {
  if (urlTokenReceived) return; // Only check once per page load
  urlTokenReceived = true;

  try {
    const hash = window.location.hash;
    if (!hash || !hash.includes("wayve_token=")) return;

    const params = new URLSearchParams(hash.slice(1)); // Remove '#'
    const encoded = params.get("wayve_token");
    if (!encoded) return;

    const decoded = atob(encoded);
    const tokens = JSON.parse(decoded) as StoredNativeTokens;

    // Validate it looks like a real token object
    if (!tokens.idToken && !tokens.accessToken) return;

    // Store in this domain's localStorage
    localStorage.setItem("wayve_auth_tokens", decoded);

    // Clean up URL hash (remove token from address bar)
    const cleanHash = hash
      .replace(/[#&]?wayve_token=[^&]*/, "")
      .replace(/^#$/, "");
    if (cleanHash) {
      window.location.hash = cleanHash;
    } else {
      // Remove hash entirely
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  } catch {
    // Silently ignore — token transfer is best-effort
  }
}

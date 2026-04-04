/**
 * Wayve JWT Authentication Middleware
 *
 * Validates Microsoft Entra External ID tokens (same as Wayve's .NET AuthMiddleware.cs)
 * and auto-provisions users + companies in Paperclip's database.
 *
 * Token flow:
 *   Wayve frontend (MSAL) → idToken in localStorage → Bearer header → this middleware
 *
 * Auto-provisioning:
 *   First request from a Wayve user creates:
 *   1. An authUsers record (Paperclip's user table)
 *   2. A companies record (Paperclip's company/workspace)
 *   3. A companyMemberships record (user → company link)
 *
 * This middleware is called from actorMiddleware() when a Bearer token is present
 * and is NOT an agent API key or agent JWT.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Db } from "@paperclipai/db";
import { authUsers, companies, companyMemberships } from "@paperclipai/db";
import { eq, and } from "drizzle-orm";
import { logger } from "./logger.js";

// ── Configuration ──────────────────────────────────────────────────────────

interface WayveAuthConfig {
  tenantId: string;
  tenantSubdomain: string;
  clientId: string;
}

function loadWayveAuthConfig(): WayveAuthConfig | null {
  const tenantId = process.env.WAYVE_ENTRA_TENANT_ID;
  const tenantSubdomain = process.env.WAYVE_ENTRA_TENANT_SUBDOMAIN;
  const clientId = process.env.WAYVE_ENTRA_CLIENT_ID;

  if (!tenantId || !tenantSubdomain || !clientId) {
    return null;
  }

  return { tenantId, tenantSubdomain, clientId };
}

// ── JWKS Cache ─────────────────────────────────────────────────────────────

let cachedJWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedConfig: WayveAuthConfig | null = null;

function getJWKS(config: WayveAuthConfig) {
  // Reuse cached JWKS if config hasn't changed
  if (cachedJWKS && cachedConfig?.tenantId === config.tenantId) {
    return cachedJWKS;
  }

  const jwksUrl = new URL(
    `https://${config.tenantSubdomain}.ciamlogin.com/${config.tenantId}/discovery/v2.0/keys`,
  );

  cachedJWKS = createRemoteJWKSet(jwksUrl);
  cachedConfig = config;

  logger.info({ jwksUrl: jwksUrl.toString() }, "Wayve JWKS endpoint configured");
  return cachedJWKS;
}

// ── Claims Extraction ──────────────────────────────────────────────────────

interface WayveUserClaims {
  userId: string;
  email: string;
  name: string;
}

function extractClaims(payload: JWTPayload): WayveUserClaims | null {
  // User ID: try oid → sub (same order as Wayve's AuthMiddleware.cs line 183-199)
  const userId =
    (payload.oid as string) ??
    (payload.sub as string) ??
    null;

  if (!userId) {
    logger.warn("Wayve JWT missing both 'oid' and 'sub' claims");
    return null;
  }

  // Email: try email → emails → preferred_username
  const email =
    (payload.email as string) ??
    (Array.isArray(payload.emails) ? (payload.emails[0] as string) : null) ??
    (payload.preferred_username as string) ??
    "";

  // Name: try name → given_name
  const name =
    (payload.name as string) ??
    (payload.given_name as string) ??
    "";

  return { userId, email, name };
}

// ── User & Company Auto-Provisioning ───────────────────────────────────────

interface ProvisionResult {
  userId: string;
  companyIds: string[];
  email: string;
  name: string;
}

// In-memory cache to avoid DB lookups on every request
const provisionCache = new Map<string, { result: ProvisionResult; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function findOrCreateUser(
  db: Db,
  claims: WayveUserClaims,
): Promise<ProvisionResult> {
  // Check cache first
  const cached = provisionCache.get(claims.userId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.result;
  }

  // 1. Check if user already exists
  const existingUser = await db
    .select({ id: authUsers.id })
    .from(authUsers)
    .where(eq(authUsers.id, claims.userId))
    .then((rows: Array<{ id: string }>) => rows[0] ?? null);

  if (existingUser) {
    // User exists — fetch their company memberships
    const memberships = await db
      .select({ companyId: companyMemberships.companyId })
      .from(companyMemberships)
      .where(
        and(
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, claims.userId),
          eq(companyMemberships.status, "active"),
        ),
      );

    const companyIds = memberships.map((m: { companyId: string }) => m.companyId);

    // If user has no companies yet, create one
    if (companyIds.length === 0) {
      const companyId = await createDefaultCompany(db, claims);
      companyIds.push(companyId);
    }

    const result = { userId: claims.userId, companyIds, email: claims.email, name: claims.name };
    provisionCache.set(claims.userId, { result, expiresAt: Date.now() + CACHE_TTL_MS });
    return result;
  }

  // 2. User doesn't exist — create user + company + membership
  logger.info(
    { wayveUserId: claims.userId, email: claims.email },
    "Auto-provisioning new Wayve user in Paperclip",
  );

  const now = new Date();

  await db.insert(authUsers).values({
    id: claims.userId,
    name: claims.name || claims.email || "Wayve User",
    email: claims.email || `${claims.userId}@wayve.local`,
    emailVerified: true, // Wayve/Entra already verified the email
    createdAt: now,
    updatedAt: now,
  });

  const companyId = await createDefaultCompany(db, claims);

  // 3. Grant instance admin role (this is the user's own Paperclip instance)
  // Not granting instance_admin — each Wayve user is just a regular board member
  // of their own company. Instance admin is reserved for the platform operator.

  const result = { userId: claims.userId, companyIds: [companyId], email: claims.email, name: claims.name };
  provisionCache.set(claims.userId, { result, expiresAt: Date.now() + CACHE_TTL_MS });
  return result;
}

async function createDefaultCompany(db: Db, claims: WayveUserClaims): Promise<string> {
  // Create a company with a unique issue prefix
  const companyName = claims.name
    ? `${claims.name}'s Agent Team`
    : "My Agent Team";

  // Derive a 3-letter prefix from the name or email
  const prefixBase = derivePrefix(claims.name || claims.email || "WAY");

  // Try creating with the prefix, retry with numeric suffix on conflict
  let company: { id: string } | null = null;
  for (let attempt = 1; attempt <= 100; attempt++) {
    const prefix = attempt === 1 ? prefixBase : `${prefixBase}${attempt}`;
    try {
      const rows = await db
        .insert(companies)
        .values({
          name: companyName,
          issuePrefix: prefix.toUpperCase(),
          status: "active",
        })
        .returning();
      company = rows[0];
      break;
    } catch (error: unknown) {
      // Unique constraint violation on issuePrefix — try next suffix
      const isConflict =
        error instanceof Error &&
        "code" in error &&
        (error as { code?: string }).code === "23505";
      if (!isConflict) throw error;
    }
  }

  if (!company) {
    throw new Error("Failed to create company after 100 attempts");
  }

  // Create company membership (user → company, as owner)
  await db.insert(companyMemberships).values({
    companyId: company.id,
    principalType: "user",
    principalId: claims.userId,
    status: "active",
    membershipRole: "owner",
  });

  logger.info(
    { companyId: company.id, companyName, userId: claims.userId },
    "Created default company for Wayve user",
  );

  return company.id;
}

function derivePrefix(input: string): string {
  // Take first 3 uppercase letters from input
  const letters = input.replace(/[^a-zA-Z]/g, "").toUpperCase();
  if (letters.length >= 3) return letters.slice(0, 3);
  if (letters.length > 0) return letters.padEnd(3, "X");
  return "WAY";
}

// ── Main Validation Function ───────────────────────────────────────────────

export interface WayveAuthResult {
  userId: string;
  companyIds: string[];
  email: string;
  name: string;
}

/**
 * Attempts to validate a Bearer token as a Wayve JWT (Microsoft Entra ID token).
 * Returns the authenticated user info if valid, or null if the token is not a Wayve JWT.
 *
 * This function is designed to be called from actorMiddleware() as the first
 * authentication check for Bearer tokens.
 */
export async function tryWayveJwtAuth(
  db: Db,
  token: string,
): Promise<WayveAuthResult | null> {
  const config = loadWayveAuthConfig();
  if (!config) {
    // Wayve auth not configured — skip
    return null;
  }

  // Quick heuristic: Entra JWTs are typically 800+ characters with 2 dots.
  // Agent API keys and Paperclip agent JWTs are shorter.
  // This avoids expensive JWKS lookups for non-Entra tokens.
  const dotCount = token.split(".").length - 1;
  if (dotCount !== 2 || token.length < 500) {
    return null;
  }

  // Valid issuers (same as Wayve's AuthMiddleware.cs lines 159-165)
  const validIssuers = [
    `https://${config.tenantSubdomain}.ciamlogin.com/${config.tenantId}/v2.0`,
    `https://${config.tenantId}.ciamlogin.com/${config.tenantId}/v2.0`,
    `https://sts.windows.net/${config.tenantId}/`,
    `https://login.microsoftonline.com/${config.tenantId}/v2.0`,
  ];

  try {
    const jwks = getJWKS(config);

    const { payload } = await jwtVerify(token, jwks, {
      audience: config.clientId,
      issuer: validIssuers,
      clockTolerance: 300, // 5 minutes, same as Wayve's AuthMiddleware.cs
    });

    const claims = extractClaims(payload);
    if (!claims) {
      return null;
    }

    // Auto-provision user + company if needed
    const result = await findOrCreateUser(db, claims);

    logger.debug(
      { userId: result.userId, companies: result.companyIds.length },
      "Wayve JWT authenticated",
    );

    return result;
  } catch (error) {
    // Not a valid Wayve JWT — let other auth methods try
    // This is expected for agent API keys and Paperclip agent JWTs
    logger.debug({ err: error }, "Token is not a valid Wayve JWT (falling through)");
    return null;
  }
}

/**
 * Clear the provision cache for a specific user (useful for testing).
 */
export function clearProvisionCache(userId?: string) {
  if (userId) {
    provisionCache.delete(userId);
  } else {
    provisionCache.clear();
  }
}

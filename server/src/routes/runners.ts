/**
 * Runner API routes — endpoints for the Wayve CLI Agent Runner.
 *
 * Security model:
 * - All endpoints require board-level authentication (Wayve JWT)
 * - Data is scoped by companyIds from the authenticated actor
 * - Authorization is checked BEFORE any writes
 * - Cost data is clamped to non-negative values
 * - adapterConfig secrets are stripped via allowlist
 * - Duplicate finalization is rejected
 * - In-memory rate limiting per user
 */

import { Router } from "express";
import { and, eq, inArray } from "drizzle-orm";
import type { Request } from "express";
import type { Db } from "@paperclipai/db";
import {
  agents,
  heartbeatRuns,
  agentRuntimeState,
  costEvents,
} from "@paperclipai/db";
import { assertBoard, assertCompanyAccess } from "./authz.js";
import { logger } from "../middleware/logger.js";
import { createLocalAgentJwt } from "../agent-auth-jwt.js";

// ── Security helpers ───────────────────────────────────────────────────────

const SENSITIVE_KEY_PATTERN = /(key|token|secret|password|passwd|auth|credential|bearer|private)/i;

/** Allowlist of safe adapterConfig fields to send to the runner. */
function sanitizeAdapterConfig(config: Record<string, unknown>): Record<string, unknown> {
  return {
    model: config.model,
    cwd: config.cwd,
    promptTemplate: config.promptTemplate,
    timeoutSec: config.timeoutSec,
    graceSec: config.graceSec,
    maxTurnsPerRun: config.maxTurnsPerRun,
    dangerouslySkipPermissions: config.dangerouslySkipPermissions,
    extraArgs: config.extraArgs,
  };
}

/** Strip sensitive env vars using broad pattern matching. */
function sanitizeEnv(env: Record<string, string> | undefined): Record<string, string> {
  if (!env) return {};
  const safe: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (!SENSITIVE_KEY_PATTERN.test(key)) {
      safe[key] = value;
    }
  }
  return safe;
}

/** Clamp to non-negative integer. Prevents budget manipulation via negative values. */
function clampNonNeg(value: number | null | undefined): number {
  return Math.max(0, Math.floor(Number(value) || 0));
}

// ── Rate limiting (in-memory, per userId) ──────────────────────────────────

const rateLimitMap = new Map<string, number[]>();
const RATE_LIMIT_WINDOW_MS = 60_000;

function isRateLimited(userId: string, maxPerMinute: number): boolean {
  const now = Date.now();
  const timestamps = rateLimitMap.get(userId) ?? [];
  const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  if (recent.length >= maxPerMinute) {
    rateLimitMap.set(userId, recent);
    return true;
  }

  recent.push(now);
  rateLimitMap.set(userId, recent);
  return false;
}

// Clean up stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamps] of rateLimitMap.entries()) {
    const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (recent.length === 0) {
      rateLimitMap.delete(key);
    } else {
      rateLimitMap.set(key, recent);
    }
  }
}, 5 * 60_000).unref();

// ── Routes ─────────────────────────────────────────────────────────────────

export function runnerRoutes(db: Db) {
  const router = Router();

  // ── GET /runners/pending ─────────────────────────────────────────────
  router.get("/runners/pending", async (req, res) => {
    try { assertBoard(req); } catch {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const userId = req.actor.userId ?? "unknown";
    if (isRateLimited(`pending:${userId}`, 10)) {
      res.status(429).json({ error: "Too many requests. Max 10/min for polling." });
      return;
    }

    const companyIds = req.actor.companyIds ?? [];
    if (companyIds.length === 0) {
      res.json([]);
      return;
    }

    try {
      const queuedRuns = await db
        .select({
          runId: heartbeatRuns.id,
          agentId: heartbeatRuns.agentId,
          companyId: heartbeatRuns.companyId,
          invocationSource: heartbeatRuns.invocationSource,
          contextSnapshot: heartbeatRuns.contextSnapshot,
          agentName: agents.name,
          adapterType: agents.adapterType,
          adapterConfig: agents.adapterConfig,
        })
        .from(heartbeatRuns)
        .innerJoin(agents, eq(heartbeatRuns.agentId, agents.id))
        .where(
          and(
            eq(heartbeatRuns.status, "queued"),
            inArray(heartbeatRuns.companyId, companyIds),
          ),
        )
        .limit(10);

      const pending = [];
      for (const run of queuedRuns) {
        const adapterType = run.adapterType ?? "claude_local";
        if (!adapterType.startsWith("remote_") && adapterType !== "claude_local") continue;

        const context = (run.contextSnapshot ?? {}) as Record<string, unknown>;
        const config = (run.adapterConfig ?? {}) as Record<string, unknown>;

        const runtimeState = await db
          .select({ stateJson: agentRuntimeState.stateJson })
          .from(agentRuntimeState)
          .where(eq(agentRuntimeState.agentId, run.agentId))
          .then((rows: Array<{ stateJson: Record<string, unknown> }>) => rows[0] ?? null);

        const promptTemplate = (config.promptTemplate as string) ?? "";
        const prompt = promptTemplate || ((context.prompt as string) ?? `You are ${run.agentName}. Complete your assigned tasks.`);

        pending.push({
          wakeupId: run.runId,
          agentId: run.agentId,
          agentName: run.agentName,
          companyId: run.companyId,
          adapterType,
          adapterConfig: sanitizeAdapterConfig(config),
          prompt,
          env: sanitizeEnv(config.env as Record<string, string> | undefined),
          sessionState: (runtimeState?.stateJson as Record<string, unknown>) ?? null,
          taskId: (context.issueId as string) ?? undefined,
          taskTitle: (context.taskTitle as string) ?? undefined,
          wakeReason: (context.wakeReason as string) ?? run.invocationSource ?? "on_demand",
        });
      }

      res.json(pending);
    } catch (err) {
      logger.error({ err }, "Failed to fetch pending runs for runner");
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ── POST /runners/claim/:runId ───────────────────────────────────────
  // Authorization is checked BEFORE any writes.
  router.post("/runners/claim/:runId", async (req, res) => {
    try { assertBoard(req); } catch {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const { runId } = req.params;

    try {
      // Step 1: READ the run (no writes yet)
      const runRow = await db
        .select({
          id: heartbeatRuns.id,
          agentId: heartbeatRuns.agentId,
          companyId: heartbeatRuns.companyId,
          status: heartbeatRuns.status,
        })
        .from(heartbeatRuns)
        .where(eq(heartbeatRuns.id, runId))
        .then((rows: Array<{ id: string; agentId: string; companyId: string; status: string }>) => rows[0] ?? null);

      if (!runRow) {
        res.status(404).json({ error: "Run not found" });
        return;
      }

      if (runRow.status !== "queued") {
        res.status(409).json({ error: "Run already claimed or completed" });
        return;
      }

      // Step 2: AUTHORIZE before any writes
      try {
        assertCompanyAccess(req, runRow.companyId);
      } catch {
        res.status(403).json({ error: "No access to this company" });
        return;
      }

      // Step 3: WRITE — atomic claim (still check status=queued for race safety)
      const claimed = await db
        .update(heartbeatRuns)
        .set({ status: "running", startedAt: new Date(), updatedAt: new Date() })
        .where(and(eq(heartbeatRuns.id, runId), eq(heartbeatRuns.status, "queued")))
        .returning()
        .then((rows: Array<{ id: string; agentId: string; companyId: string }>) => rows[0] ?? null);

      if (!claimed) {
        res.status(409).json({ error: "Run was claimed by another runner" });
        return;
      }

      const agentJwt = createLocalAgentJwt(claimed.agentId, claimed.companyId, "remote_claude_local", runId);
      logger.info({ runId, agentId: claimed.agentId }, "Run claimed by external runner");

      res.json({ runId: claimed.id, shortLivedToken: agentJwt ?? "" });
    } catch (err) {
      logger.error({ err, runId }, "Failed to claim run");
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ── POST /runners/heartbeat-done ─────────────────────────────────────
  // Rejects duplicates, clamps costs to non-negative.
  router.post("/runners/heartbeat-done", async (req, res) => {
    try { assertBoard(req); } catch {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const userId = req.actor.userId ?? "unknown";
    if (isRateLimited(`done:${userId}`, 60)) {
      res.status(429).json({ error: "Too many requests. Max 60/min." });
      return;
    }

    const body = req.body as {
      runId: string;
      status: "completed" | "failed";
      exitCode: number | null;
      costCents: number;
      provider: string;
      model: string;
      inputTokens: number;
      outputTokens: number;
      cachedInputTokens?: number;
      stdoutExcerpt: string;
      sessionState: Record<string, unknown> | null;
      error: string | null;
      summary: string | null;
    };

    if (!body.runId) {
      res.status(400).json({ error: "runId is required" });
      return;
    }

    const safeCost = clampNonNeg(body.costCents);
    const safeIn = clampNonNeg(body.inputTokens);
    const safeOut = clampNonNeg(body.outputTokens);
    const safeCached = clampNonNeg(body.cachedInputTokens);

    try {
      const run = await db
        .select()
        .from(heartbeatRuns)
        .where(eq(heartbeatRuns.id, body.runId))
        .then((rows) => rows[0] ?? null);

      if (!run) {
        res.status(404).json({ error: "Run not found" });
        return;
      }

      // Reject duplicate finalization
      if (run.status !== "running") {
        res.status(409).json({ error: `Run is already ${run.status}` });
        return;
      }

      assertCompanyAccess(req, run.companyId);

      const finishStatus = body.status === "completed" ? "completed" : "failed";

      await db.update(heartbeatRuns).set({
        status: finishStatus,
        finishedAt: new Date(),
        exitCode: body.exitCode,
        error: body.error ?? null,
        stdoutExcerpt: body.stdoutExcerpt?.slice(0, 32 * 1024) ?? null,
        usageJson: { inputTokens: safeIn, outputTokens: safeOut, cachedInputTokens: safeCached },
        resultJson: { costUsd: safeCost / 100, provider: body.provider, model: body.model, summary: body.summary },
        updatedAt: new Date(),
      }).where(eq(heartbeatRuns.id, body.runId));

      if (safeCost > 0) {
        await db.insert(costEvents).values({
          companyId: run.companyId,
          agentId: run.agentId,
          heartbeatRunId: run.id,
          provider: body.provider ?? "anthropic",
          biller: "api",
          billingType: "api",
          model: body.model ?? "unknown",
          inputTokens: safeIn,
          cachedInputTokens: safeCached,
          outputTokens: safeOut,
          costCents: safeCost,
          occurredAt: new Date(),
        });
      } else if (safeIn + safeOut > 0) {
        logger.warn({ runId: body.runId, inputTokens: safeIn, outputTokens: safeOut },
          "Run reported zero cost with non-zero tokens");
      }

      // Update agent spend (safeCost is already >= 0)
      const agent = await db
        .select({ spentMonthlyCents: agents.spentMonthlyCents })
        .from(agents)
        .where(eq(agents.id, run.agentId))
        .then((rows: Array<{ spentMonthlyCents: number }>) => rows[0] ?? null);

      if (agent) {
        await db.update(agents).set({
          spentMonthlyCents: agent.spentMonthlyCents + safeCost,
          lastHeartbeatAt: new Date(),
          updatedAt: new Date(),
        }).where(eq(agents.id, run.agentId));
      }

      // Persist session state for next run
      if (body.sessionState) {
        const existing = await db
          .select({ agentId: agentRuntimeState.agentId })
          .from(agentRuntimeState)
          .where(eq(agentRuntimeState.agentId, run.agentId))
          .then((rows: Array<{ agentId: string }>) => rows[0] ?? null);

        if (existing) {
          await db.update(agentRuntimeState).set({
            stateJson: body.sessionState, updatedAt: new Date(),
          }).where(eq(agentRuntimeState.agentId, run.agentId));
        } else {
          const agentRecord = await db
            .select({ adapterType: agents.adapterType })
            .from(agents)
            .where(eq(agents.id, run.agentId))
            .then((rows: Array<{ adapterType: string }>) => rows[0] ?? null);

          await db.insert(agentRuntimeState).values({
            agentId: run.agentId,
            companyId: run.companyId,
            adapterType: agentRecord?.adapterType ?? "remote_claude_local",
            stateJson: body.sessionState,
          });
        }
      }

      logger.info({ runId: body.runId, status: finishStatus, costCents: safeCost }, "Runner reported heartbeat result");
      res.json({ ok: true });
    } catch (err) {
      logger.error({ err, runId: body.runId }, "Failed to process heartbeat result");
      res.status(500).json({ error: "Internal server error" });
    }
  });

  return router;
}

/**
 * Runner API routes — endpoints for the Wayve CLI Agent Runner.
 *
 * These endpoints allow external runners (on user's laptops) to:
 * 1. Poll for queued heartbeat runs that need remote execution
 * 2. Claim a run atomically (preventing double execution)
 * 3. Report execution results (costs, tokens, session state)
 *
 * All endpoints require board-level authentication (Wayve JWT).
 */

import { Router } from "express";
import { and, eq, inArray } from "drizzle-orm";
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

export function runnerRoutes(db: Db) {
  const router = Router();

  // ── GET /runners/pending ─────────────────────────────────────────────
  // Returns queued heartbeat runs for agents with remote adapter types.
  // The runner polls this endpoint every 30 seconds.
  router.get("/runners/pending", async (req, res) => {
    try {
      assertBoard(req);
    } catch {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const companyIds = req.actor.companyIds ?? [];
    if (companyIds.length === 0) {
      res.json([]);
      return;
    }

    try {
      // Find queued runs for agents with remote_* adapter types
      const queuedRuns = await db
        .select({
          runId: heartbeatRuns.id,
          agentId: heartbeatRuns.agentId,
          companyId: heartbeatRuns.companyId,
          invocationSource: heartbeatRuns.invocationSource,
          triggerDetail: heartbeatRuns.triggerDetail,
          contextSnapshot: heartbeatRuns.contextSnapshot,
          wakeupRequestId: heartbeatRuns.wakeupRequestId,
          createdAt: heartbeatRuns.createdAt,
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

      // Filter for remote adapter types and build response
      const pending = [];
      for (const run of queuedRuns) {
        const adapterType = run.adapterType ?? "claude_local";
        // Accept both remote_* prefixed adapters and regular adapters
        // (the runner can handle any adapter type it supports)
        if (!adapterType.startsWith("remote_") && adapterType !== "claude_local") {
          continue;
        }

        const context = (run.contextSnapshot ?? {}) as Record<string, unknown>;
        const config = (run.adapterConfig ?? {}) as Record<string, unknown>;

        // Resolve session state for this agent
        const runtimeState = await db
          .select({ sessionParams: agentRuntimeState.sessionParams })
          .from(agentRuntimeState)
          .where(eq(agentRuntimeState.agentId, run.agentId))
          .then((rows: Array<{ sessionParams: unknown }>) => rows[0] ?? null);

        // Build prompt from adapter config template or context
        const promptTemplate = (config.promptTemplate as string) ?? "";
        const prompt = promptTemplate || (context.prompt as string) ?? `You are ${run.agentName}. Complete your assigned tasks.`;

        // Resolve environment variables (secrets are NOT sent — runner must have them locally)
        const env: Record<string, string> = {};
        const configEnv = config.env as Record<string, string> | undefined;
        if (configEnv) {
          for (const [key, value] of Object.entries(configEnv)) {
            // Only pass non-secret env vars (secrets should be on the runner machine)
            if (!key.toLowerCase().includes("secret") && !key.toLowerCase().includes("password")) {
              env[key] = value;
            }
          }
        }

        pending.push({
          wakeupId: run.runId, // Use run ID as the claim identifier
          agentId: run.agentId,
          agentName: run.agentName,
          companyId: run.companyId,
          adapterType,
          adapterConfig: config,
          prompt,
          env,
          sessionState: (runtimeState?.sessionParams as Record<string, unknown>) ?? null,
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
  // Atomically claim a queued run. Returns 409 if already claimed.
  router.post("/runners/claim/:runId", async (req, res) => {
    try {
      assertBoard(req);
    } catch {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const { runId } = req.params;

    try {
      // Atomic claim: only update if status is still "queued"
      const claimed = await db
        .update(heartbeatRuns)
        .set({
          status: "running",
          startedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(heartbeatRuns.id, runId),
            eq(heartbeatRuns.status, "queued"),
          ),
        )
        .returning()
        .then((rows: Array<{ id: string; agentId: string; companyId: string }>) => rows[0] ?? null);

      if (!claimed) {
        res.status(409).json({ error: "Run already claimed or not found" });
        return;
      }

      // Verify company access
      try {
        assertCompanyAccess(req, claimed.companyId);
      } catch {
        // Revert claim if no access
        await db
          .update(heartbeatRuns)
          .set({ status: "queued", startedAt: null, updatedAt: new Date() })
          .where(eq(heartbeatRuns.id, runId));
        res.status(403).json({ error: "No access to this company" });
        return;
      }

      // Generate a short-lived agent JWT for the runner's Claude process
      const agentJwt = createLocalAgentJwt(
        claimed.agentId,
        claimed.companyId,
        "remote_claude_local",
        runId,
      );

      logger.info({ runId, agentId: claimed.agentId }, "Run claimed by external runner");

      res.json({
        runId: claimed.id,
        shortLivedToken: agentJwt ?? "",
      });
    } catch (err) {
      logger.error({ err, runId }, "Failed to claim run");
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // ── POST /runners/heartbeat-done ─────────────────────────────────────
  // Report execution results from the runner.
  router.post("/runners/heartbeat-done", async (req, res) => {
    try {
      assertBoard(req);
    } catch {
      res.status(401).json({ error: "Unauthorized" });
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

      // Verify company access
      assertCompanyAccess(req, run.companyId);

      // Update the heartbeat run with results
      const finishStatus = body.status === "completed" ? "completed" : "failed";
      await db
        .update(heartbeatRuns)
        .set({
          status: finishStatus,
          finishedAt: new Date(),
          exitCode: body.exitCode,
          error: body.error ?? null,
          stdoutExcerpt: body.stdoutExcerpt?.slice(0, 32 * 1024) ?? null,
          usageJson: {
            inputTokens: body.inputTokens ?? 0,
            outputTokens: body.outputTokens ?? 0,
            cachedInputTokens: body.cachedInputTokens ?? 0,
          },
          resultJson: {
            costUsd: (body.costCents ?? 0) / 100,
            provider: body.provider,
            model: body.model,
            summary: body.summary,
          },
          updatedAt: new Date(),
        })
        .where(eq(heartbeatRuns.id, body.runId));

      // Record cost event
      if (body.costCents > 0) {
        await db.insert(costEvents).values({
          companyId: run.companyId,
          agentId: run.agentId,
          heartbeatRunId: run.id,
          provider: body.provider ?? "anthropic",
          biller: "api",
          billingType: "api",
          model: body.model ?? "unknown",
          inputTokens: body.inputTokens ?? 0,
          cachedInputTokens: body.cachedInputTokens ?? 0,
          outputTokens: body.outputTokens ?? 0,
          costCents: body.costCents,
          occurredAt: new Date(),
        });
      }

      // Update agent's monthly spend and last heartbeat timestamp
      const agent = await db
        .select({ spentMonthlyCents: agents.spentMonthlyCents })
        .from(agents)
        .where(eq(agents.id, run.agentId))
        .then((rows: Array<{ spentMonthlyCents: number }>) => rows[0] ?? null);

      if (agent) {
        await db
          .update(agents)
          .set({
            spentMonthlyCents: agent.spentMonthlyCents + (body.costCents ?? 0),
            lastHeartbeatAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(agents.id, run.agentId));
      }

      // Persist session state for next run
      if (body.sessionState) {
        const existing = await db
          .select({ id: agentRuntimeState.id })
          .from(agentRuntimeState)
          .where(eq(agentRuntimeState.agentId, run.agentId))
          .then((rows: Array<{ id: string }>) => rows[0] ?? null);

        if (existing) {
          await db
            .update(agentRuntimeState)
            .set({
              sessionParams: body.sessionState,
              updatedAt: new Date(),
            })
            .where(eq(agentRuntimeState.agentId, run.agentId));
        } else {
          await db.insert(agentRuntimeState).values({
            agentId: run.agentId,
            companyId: run.companyId,
            sessionParams: body.sessionState,
          });
        }
      }

      logger.info(
        {
          runId: body.runId,
          status: finishStatus,
          costCents: body.costCents,
          tokens: (body.inputTokens ?? 0) + (body.outputTokens ?? 0),
        },
        "External runner reported heartbeat result",
      );

      res.json({ ok: true });
    } catch (err) {
      logger.error({ err, runId: body.runId }, "Failed to process heartbeat result");
      res.status(500).json({ error: "Internal server error" });
    }
  });

  return router;
}

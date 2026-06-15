/**
 * Authentication Controller
 * Handles user registration, login, logout, MFA, and device management
 */

import type { Request, Response } from "express";
import {
  asyncHandler,
  AuthenticationError,
  ErrorCode,
} from "@hermit/error-handling";
import { authWrapper } from "../wrappers/auth.wrapper";
import { syncUserFromClerk, deleteUserByClerkId } from "../services/clerk.service";
import config from "../config";
import { log } from "@hermit/logger";

/**
 * Handle Clerk Webhooks
 * POST /api/v1/auth/webhooks/clerk
 */
export const clerkWebhook = asyncHandler(async (req: Request, res: Response) => {
  const payload = req.body;
  const eventType = payload.type;

  log.info("Clerk Webhook received", { eventType });

  // Note: In production, you MUST verify the Svix signature
  // This implementation assumes signature verification is handled by middleware or skipped for dev

  switch (eventType) {
    case "user.created":
    case "user.updated":
      const { id: createdId } = payload.data;
      await syncUserFromClerk(createdId);
      break;
    
    case "user.deleted":
      const { id: deletedId } = payload.data;
      await deleteUserByClerkId(deletedId);
      break;

    default:
      log.debug("Unhandled Clerk event type", { eventType });
  }

  res.json({ success: true });
});

/**
 * Register a new user
 * POST /api/v1/auth/register
 */
export const register = asyncHandler(async (req: Request, res: Response) => {
  const result = await authWrapper.register({
    ...req.body,
    ipAddress: req.ip || "unknown",
    userAgent: req.headers["user-agent"] || "unknown",
  });

  res.status(201).json({
    success: true,
    data: result,
    message: "User registered successfully",
  });
});

/**
 * Login user
 * POST /api/v1/auth/login
 */
export const login = asyncHandler(async (req: Request, res: Response) => {
  const result = await authWrapper.login({
    ...req.body,
    ipAddress: req.ip || "unknown",
    userAgent: req.headers["user-agent"] || "unknown",
  });

  res.json({
    success: true,
    data: result,
  });
});

/**
 * Logout user
 * POST /api/v1/auth/logout
 */
export const logout = asyncHandler(async (req: Request, res: Response) => {
  const result = await authWrapper.logout({
    refreshToken: req.body.refreshToken,
    userId: req.user?.id,
    ipAddress: req.ip || "unknown",
    userAgent: req.headers["user-agent"] || "unknown",
  });

  res.json({
    success: true,
    message: "Logged out successfully",
  });
});

/**
 * Refresh access token
 * POST /api/v1/auth/refresh
 */
export const refreshToken = asyncHandler(
  async (req: Request, res: Response) => {
    const result = await authWrapper.refreshToken(req.body);

    res.json({
      success: true,
      data: result,
    });
  },
);

/**
 * Setup MFA (get QR code)
 * POST /api/v1/auth/mfa/setup
 */
export const setupMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const result = await authWrapper.setupMfa(req.user.id);

  res.json({
    success: true,
    data: result,
    message:
      "Scan the QR code with your authenticator app, then verify with a token to enable MFA",
  });
});

/**
 * Enable MFA (verify and activate)
 * POST /api/v1/auth/mfa/enable
 */
export const enableMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const result = await authWrapper.enableMfa(req.user.id, req.body.token);

  res.json({
    success: true,
    data: result,
    message:
      "MFA enabled successfully. Save these backup codes in a secure location.",
  });
});

/**
 * Disable MFA
 * POST /api/v1/auth/mfa/disable
 */
export const disableMfa = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  await authWrapper.disableMfa(
    req.user.id,
    req.body.password,
    req.body.mfaToken,
  );

  res.json({
    success: true,
    message: "MFA disabled successfully",
  });
});

/**
 * Get user's devices
 * GET /api/v1/auth/devices
 */
export const getDevices = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const result = await authWrapper.getDevices(req.user.id);

  res.json({
    success: true,
    data: result,
  });
});

/**
 * Remove a device
 * DELETE /api/v1/auth/devices/:id
 */
export const removeDevice = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    await authWrapper.removeDevice(req.user.id, req.params.id);

    res.json({
      success: true,
      message: "Device removed successfully",
    });
  },
);

/**
 * Enroll the current device as an official CLI device
 * POST /api/v1/auth/cli/enroll
 */
export const enrollCliDevice = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user?.deviceId) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const result = await authWrapper.enrollCliDevice(req.user.id, req.user.deviceId, {
    cliPublicKey: req.body.cliPublicKey,
    cliLabel: req.body.cliLabel,
    hardwareFingerprint: req.body.hardwareFingerprint,
  });

  res.json({
    success: true,
    data: result,
    message: "CLI device enrolled successfully",
  });
});

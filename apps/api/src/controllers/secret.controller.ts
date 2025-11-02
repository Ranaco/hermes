/**
 * Secret Controller
 * Handles secure secret storage with encryption via HashiCorp Vault Transit Engine
 *
 * Three-tier security model:
 * 1. Secret-level password (highest) - requires password to decrypt specific secret
 * 2. Vault-level password (medium) - requires password to access any secret in vault
 * 3. Authentication only (basic) - just requires login
 */

import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import {
  asyncHandler,
  AuthenticationError,
  ValidationError,
  ErrorCode,
  NotFoundError,
  ForbiddenError,
} from "@hermes/error-handling";
import getPrismaClient from "../services/prisma.service";
import encryptionService from "../services/encryption.service";
import { createAuditLog } from "../services/audit.service";
import config from "../config";

/**
 * Create a new secret
 * POST /api/v1/secrets
 */
export const createSecret = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    const {
      name,
      description,
      value,
      vaultId,
      keyId,
      password,
      metadata,
      tags,
      expiresAt,
    } = req.body;

    if (!name || !value || !vaultId || !keyId) {
      throw new ValidationError(
        ErrorCode.VALIDATION_ERROR,
        "Name, value, vaultId, and keyId are required",
      );
    }

    const prisma = getPrismaClient();

    // Check vault access and get vault details
    const vault = await prisma.vault.findFirst({
      where: {
        id: vaultId,
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ["EDIT", "ADMIN"] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: { userId: req.user.id },
                  },
                },
                permissionLevel: { in: ["EDIT", "ADMIN"] },
              },
            },
          },
        ],
      },
    });

    if (!vault) {
      throw new NotFoundError(
        ErrorCode.VAULT_NOT_FOUND,
        "Vault not found or insufficient permissions",
      );
    }

    // Verify key exists and belongs to the vault
    const key = await prisma.key.findFirst({
      where: {
        id: keyId,
        vaultId,
      },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          take: 1,
        },
      },
    });

    if (!key || !key.versions[0]) {
      throw new NotFoundError(
        ErrorCode.KEY_NOT_FOUND,
        "Key not found in this vault",
      );
    }

    // Get the vault transit key name from the key version
    const vaultKeyName = key.versions[0].encryptedValue;

    // Encrypt the secret value using HashiCorp Vault Transit Engine
    const encryptedValue = await encryptionService.encrypt(vaultKeyName, value);

    // Hash the secret password if provided (secret-level protection)
    let passwordHash: string | undefined;
    if (password) {
      passwordHash = await bcrypt.hash(password, config.security.bcryptRounds);
    }

    // Create secret with first version
    const secret = await prisma.secret.create({
      data: {
        name,
        description,
        vaultId,
        keyId,
        passwordHash,
        metadata,
        tags: tags || [],
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdById: req.user.id,
        versions: {
          create: {
            versionNumber: 1,
            encryptedValue,
            encryptionContext: {
              keyId,
              vaultKeyName,
              algorithm: "aes256-gcm96",
            },
            createdById: req.user.id,
          },
        },
      },
      include: {
        vault: {
          select: {
            id: true,
            name: true,
          },
        },
        key: {
          select: {
            id: true,
            name: true,
          },
        },
        versions: {
          orderBy: { versionNumber: "desc" },
          take: 1,
          select: {
            id: true,
            versionNumber: true,
            createdAt: true,
          },
        },
      },
    });

    // Update currentVersionId
    await prisma.secret.update({
      where: { id: secret.id },
      data: { currentVersionId: secret.versions[0].id },
    });

    await createAuditLog({
      userId: req.user.id,
      action: "CREATE_SECRET",
      resourceType: "SECRET",
      resourceId: secret.id,
      details: {
        secretName: name,
        vaultId,
        keyId,
        hasPassword: !!password,
        versionNumber: 1,
      },
      ipAddress: req.ip || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    res.status(201).json({
      success: true,
      data: { secret },
      message: "Secret created successfully",
    });
  },
);

/**
 * Get all secrets in a vault
 * GET /api/v1/secrets?vaultId=xxx
 */
export const getSecrets = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { vaultId } = req.query;

  if (!vaultId) {
    throw new ValidationError(
      ErrorCode.VALIDATION_ERROR,
      "Vault ID is required",
    );
  }

  const prisma = getPrismaClient();

  // Check vault access
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId as string,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: { in: ["VIEW", "USE", "EDIT", "ADMIN"] },
            },
          },
        },
        {
          permissions: {
            some: {
              group: {
                members: {
                  some: { userId: req.user.id },
                },
              },
              permissionLevel: { in: ["VIEW", "USE", "EDIT", "ADMIN"] },
            },
          },
        },
      ],
    },
  });

  if (!vault) {
    throw new NotFoundError(
      ErrorCode.VAULT_NOT_FOUND,
      "Vault not found or insufficient permissions",
    );
  }

  const secrets = await prisma.secret.findMany({
    where: { vaultId: vaultId as string },
    include: {
      key: {
        select: {
          id: true,
          name: true,
        },
      },
      currentVersion: {
        select: {
          versionNumber: true,
          createdAt: true,
        },
      },
      _count: {
        select: { versions: true },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  // Don't return encrypted values or password hashes in list view
  const sanitizedSecrets = secrets.map((secret) => ({
    ...secret,
    hasPassword: !!secret.passwordHash,
    passwordHash: undefined,
  }));

  res.json({
    success: true,
    data: { secrets: sanitizedSecrets, count: secrets.length },
  });
});

/**
 * Get a specific secret (requires password verification if protected)
 * POST /api/v1/secrets/:id/reveal
 */
export const revealSecret = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    const { id } = req.params;
    const { password, vaultPassword, versionNumber } = req.body;

    const prisma = getPrismaClient();

    const secret = await prisma.secret.findUnique({
      where: { id },
      include: {
        vault: {
          select: {
            id: true,
            name: true,
            passwordHash: true,
          },
        },
        key: {
          include: {
            versions: {
              orderBy: { versionNumber: "desc" },
              take: 1,
            },
          },
        },
        versions: {
          where: versionNumber ? { versionNumber } : {},
          orderBy: { versionNumber: "desc" },
          take: 1,
        },
      },
    });

    if (!secret) {
      throw new NotFoundError(ErrorCode.RESOURCE_NOT_FOUND, "Secret not found");
    }

    // Check vault access
    const hasAccess = await prisma.vault.findFirst({
      where: {
        id: secret.vaultId,
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ["USE", "EDIT", "ADMIN"] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: { userId: req.user.id },
                  },
                },
                permissionLevel: { in: ["USE", "EDIT", "ADMIN"] },
              },
            },
          },
        ],
      },
    });

    if (!hasAccess) {
      throw new ForbiddenError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        "Insufficient permissions to access this secret",
      );
    }

    // Three-tier security verification
    // 1. Secret-level password (highest priority)
    if (secret.passwordHash) {
      if (!password) {
        return res.status(403).json({
          success: false,
          error: {
            code: "SECRET_PASSWORD_REQUIRED",
            message: "This secret is protected with a password",
          },
          requiresPassword: "secret",
        });
      }

      const isValidPassword = await bcrypt.compare(
        password,
        secret.passwordHash,
      );
      if (!isValidPassword) {
        await createAuditLog({
          userId: req.user.id,
          action: "READ_SECRET",
          resourceType: "SECRET",
          resourceId: secret.id,
          details: { success: false, reason: "Invalid secret password" },
          ipAddress: req.ip || "unknown",
          userAgent: req.headers["user-agent"] || "unknown",
        });

        throw new ForbiddenError(
          ErrorCode.INVALID_CREDENTIALS,
          "Invalid secret password",
        );
      }
    }
    // 2. Vault-level password (medium priority)
    else if (secret.vault.passwordHash) {
      if (!vaultPassword) {
        return res.status(403).json({
          success: false,
          error: {
            code: "VAULT_PASSWORD_REQUIRED",
            message: "This vault is protected with a password",
          },
          requiresPassword: "vault",
        });
      }

      const isValidVaultPassword = await bcrypt.compare(
        vaultPassword,
        secret.vault.passwordHash,
      );
      if (!isValidVaultPassword) {
        await createAuditLog({
          userId: req.user.id,
          action: "READ_SECRET",
          resourceType: "SECRET",
          resourceId: secret.id,
          details: { success: false, reason: "Invalid vault password" },
          ipAddress: req.ip || "unknown",
          userAgent: req.headers["user-agent"] || "unknown",
        });

        throw new ForbiddenError(
          ErrorCode.INVALID_CREDENTIALS,
          "Invalid vault password",
        );
      }
    }
    // 3. Authentication only (already verified by middleware)

    // Check expiration
    if (secret.expiresAt && new Date() > secret.expiresAt) {
      throw new ForbiddenError(
        ErrorCode.RESOURCE_EXPIRED,
        "This secret has expired",
      );
    }

    const version = secret.versions[0];
    if (!version) {
      throw new NotFoundError(
        ErrorCode.RESOURCE_NOT_FOUND,
        "Secret version not found",
      );
    }

    // Get vault transit key name
    const vaultKeyName = secret.key.versions[0]?.encryptedValue;
    if (!vaultKeyName) {
      throw new Error("Key configuration error");
    }

    // Decrypt using HashiCorp Vault Transit Engine
    const decryptedValue = await encryptionService.decrypt(
      vaultKeyName,
      version.encryptedValue,
    );

    // Update access metadata
    await prisma.secret.update({
      where: { id: secret.id },
      data: {
        lastAccessedAt: new Date(),
        accessCount: { increment: 1 },
      },
    });

    await createAuditLog({
      userId: req.user.id,
      action: "READ_SECRET",
      resourceType: "SECRET",
      resourceId: secret.id,
      details: {
        success: true,
        versionNumber: version.versionNumber,
        authMethod: secret.passwordHash
          ? "secret-password"
          : secret.vault.passwordHash
            ? "vault-password"
            : "auth-only",
      },
      ipAddress: req.ip || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    res.json({
      success: true,
      data: {
        secret: {
          id: secret.id,
          name: secret.name,
          description: secret.description,
          value: decryptedValue,
          metadata: secret.metadata,
          tags: secret.tags,
          versionNumber: version.versionNumber,
          createdAt: secret.createdAt,
          updatedAt: secret.updatedAt,
          expiresAt: secret.expiresAt,
          lastAccessedAt: secret.lastAccessedAt,
          accessCount: secret.accessCount + 1,
        },
      },
    });
  },
);

/**
 * Update a secret (creates a new version)
 * PUT /api/v1/secrets/:id
 */
export const updateSecret = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    const { id } = req.params;
    const {
      value,
      description,
      password,
      metadata,
      tags,
      expiresAt,
      commitMessage,
    } = req.body;

    const prisma = getPrismaClient();

    const secret = await prisma.secret.findUnique({
      where: { id },
      include: {
        vault: {
          select: {
            id: true,
            passwordHash: true,
          },
        },
        key: {
          include: {
            versions: {
              orderBy: { versionNumber: "desc" },
              take: 1,
            },
          },
        },
        versions: {
          orderBy: { versionNumber: "desc" },
          take: 1,
        },
      },
    });

    if (!secret) {
      throw new NotFoundError(ErrorCode.RESOURCE_NOT_FOUND, "Secret not found");
    }

    // Check edit permissions
    const hasAccess = await prisma.vault.findFirst({
      where: {
        id: secret.vaultId,
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ["EDIT", "ADMIN"] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: { userId: req.user.id },
                  },
                },
                permissionLevel: { in: ["EDIT", "ADMIN"] },
              },
            },
          },
        ],
      },
    });

    if (!hasAccess) {
      throw new ForbiddenError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        "Insufficient permissions to edit this secret",
      );
    }

    const currentVersion = secret.versions[0];
    const nextVersionNumber = currentVersion
      ? currentVersion.versionNumber + 1
      : 1;

    // Get vault transit key name
    const vaultKeyName = secret.key.versions[0]?.encryptedValue;
    if (!vaultKeyName) {
      throw new Error("Key configuration error");
    }

    // Prepare update data
    const updateData: any = {};

    if (description !== undefined) updateData.description = description;
    if (metadata !== undefined) updateData.metadata = metadata;
    if (tags !== undefined) updateData.tags = tags;
    if (expiresAt !== undefined)
      updateData.expiresAt = expiresAt ? new Date(expiresAt) : null;

    // Update password if provided
    if (password !== undefined) {
      updateData.passwordHash = password
        ? await bcrypt.hash(password, config.security.bcryptRounds)
        : null;
    }

    // Create new version if value is being updated
    if (value !== undefined) {
      const encryptedValue = await encryptionService.encrypt(
        vaultKeyName,
        value,
      );

      const newVersion = await prisma.secretVersion.create({
        data: {
          secretId: secret.id,
          versionNumber: nextVersionNumber,
          encryptedValue,
          encryptionContext: {
            keyId: secret.keyId,
            vaultKeyName,
            algorithm: "aes256-gcm96",
          },
          commitMessage,
          createdById: req.user.id,
        },
      });

      updateData.currentVersionId = newVersion.id;
    }

    // Update secret
    const updatedSecret = await prisma.secret.update({
      where: { id },
      data: updateData,
      include: {
        vault: {
          select: {
            id: true,
            name: true,
          },
        },
        key: {
          select: {
            id: true,
            name: true,
          },
        },
        currentVersion: {
          select: {
            versionNumber: true,
            createdAt: true,
          },
        },
      },
    });

    await createAuditLog({
      userId: req.user.id,
      action: "UPDATE_SECRET",
      resourceType: "SECRET",
      resourceId: secret.id,
      details: {
        updatedFields: Object.keys(updateData),
        newVersion: value !== undefined ? nextVersionNumber : undefined,
        commitMessage,
      },
      ipAddress: req.ip || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    res.json({
      success: true,
      data: { secret: updatedSecret },
      message: "Secret updated successfully",
    });
  },
);

/**
 * Delete a secret
 * DELETE /api/v1/secrets/:id
 */
export const deleteSecret = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    const { id } = req.params;
    const prisma = getPrismaClient();

    const secret = await prisma.secret.findUnique({
      where: { id },
      include: {
        vault: {
          select: { id: true },
        },
      },
    });

    if (!secret) {
      throw new NotFoundError(ErrorCode.RESOURCE_NOT_FOUND, "Secret not found");
    }

    // Check admin permissions
    const hasAccess = await prisma.vault.findFirst({
      where: {
        id: secret.vaultId,
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: "ADMIN",
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: { userId: req.user.id },
                  },
                },
                permissionLevel: "ADMIN",
              },
            },
          },
        ],
      },
    });

    if (!hasAccess) {
      throw new ForbiddenError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        "Insufficient permissions to delete this secret",
      );
    }

    await prisma.secret.delete({
      where: { id },
    });

    await createAuditLog({
      userId: req.user.id,
      action: "DELETE_SECRET",
      resourceType: "SECRET",
      resourceId: id,
      details: { secretName: secret.name, vaultId: secret.vaultId },
      ipAddress: req.ip || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    res.json({
      success: true,
      message: "Secret deleted successfully",
    });
  },
);

/**
 * Get secret version history
 * GET /api/v1/secrets/:id/versions
 */
export const getSecretVersions = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
    }

    const { id } = req.params;
    const prisma = getPrismaClient();

    const secret = await prisma.secret.findUnique({
      where: { id },
      include: {
        vault: {
          select: { id: true },
        },
      },
    });

    if (!secret) {
      throw new NotFoundError(ErrorCode.RESOURCE_NOT_FOUND, "Secret not found");
    }

    // Check view permissions
    const hasAccess = await prisma.vault.findFirst({
      where: {
        id: secret.vaultId,
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ["VIEW", "USE", "EDIT", "ADMIN"] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: { userId: req.user.id },
                  },
                },
                permissionLevel: { in: ["VIEW", "USE", "EDIT", "ADMIN"] },
              },
            },
          },
        ],
      },
    });

    if (!hasAccess) {
      throw new ForbiddenError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        "Insufficient permissions to view this secret",
      );
    }

    const versions = await prisma.secretVersion.findMany({
      where: { secretId: id },
      select: {
        id: true,
        versionNumber: true,
        commitMessage: true,
        createdAt: true,
        createdBy: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
      },
      orderBy: { versionNumber: "desc" },
    });

    res.json({
      success: true,
      data: { versions, count: versions.length },
    });
  },
);

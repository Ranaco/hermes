/**
 * Key Controller
 * Handles encryption key management and cryptographic operations
 */

import type { Request, Response } from 'express';
import { asyncHandler, AuthenticationError, ValidationError, ErrorCode, NotFoundError } from '@hermes/error-handling';
import getPrismaClient from '../services/prisma.service';
import encryptionService from '../services/encryption.service';
import { createAuditLog } from '../services/audit.service';

/**
 * Create a new encryption key
 * POST /api/v1/keys
 */
export const createKey = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { name, description, vaultId } = req.body;

  if (!name || !vaultId) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Name and vault ID are required');
  }

  const prisma = getPrismaClient();

  // Check if user has permission to manage keys in this vault
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: { in: ['EDIT' as const, 'ADMIN' as const] },
            },
          },
        },
        {
          permissions: {
            some: {
              group: {
                members: {
                  some: {
                    userId: req.user.id,
                  },
                },
              },
              permissionLevel: { in: ['EDIT' as const, 'ADMIN' as const] },
            },
          },
        },
      ],
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  // Generate unique key name for Vault
  const vaultKeyName = `${vaultId}_${name.replace(/\s+/g, '_').toLowerCase()}_${Date.now()}`;

  // Create key in Vault Transit Engine
  await encryptionService.createKey(vaultKeyName);

  // Create key record in database
  const key = await prisma.key.create({
    data: {
      name,
      description,
      vault: {
        connect: { id: vaultId },
      },
      createdBy: {
        connect: { id: req.user.id },
      },
      versions: {
        create: {
          versionNumber: 1,
          encryptedValue: vaultKeyName, // Store vault key name in encrypted value
          encryptionMethod: 'vault-transit',
          createdBy: {
            connect: { id: req.user.id },
          },
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
      versions: true,
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'CREATE',
    resourceType: 'KEY',
    resourceId: key.id,
    details: { keyName: name, vaultId },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.status(201).json({
    success: true,
    data: { key },
    message: 'Encryption key created successfully',
  });
});

/**
 * Get all keys in a vault
 * GET /api/v1/keys?vaultId=xxx
 */
export const getKeys = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { vaultId } = req.query;

  if (!vaultId) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Vault ID is required');
  }

  const prisma = getPrismaClient();

  // Check if user has read permission on the vault
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId as string,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
            },
          },
        },
        {
          permissions: {
            some: {
              group: {
                members: {
                  some: {
                    userId: req.user.id,
                  },
                },
              },
              permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
            },
          },
        },
      ],
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  const keys = await prisma.key.findMany({
    where: { vaultId: vaultId as string },
    include: {
      vault: {
        select: {
          id: true,
          name: true,
        },
      },
      versions: {
        include: {
          createdBy: {
            select: {
              id: true,
              email: true,
              username: true,
            },
          },
        },
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
      _count: {
        select: {
          versions: true,
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({
    success: true,
    data: { keys },
  });
});

/**
 * Get a specific key
 * GET /api/v1/keys/:id
 */
export const getKey = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: {
                      userId: req.user.id,
                    },
                  },
                },
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      vault: {
        select: {
          id: true,
          name: true,
        },
      },
      versions: {
        orderBy: { versionNumber: 'desc' },
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND);
  }

  res.json({
    success: true,
    data: { key },
  });
});

/**
 * Rotate a key (create new version)
 * POST /api/v1/keys/:id/rotate
 */
export const rotateKey = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  // Check if user has permission to manage keys
  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: {
                      userId: req.user.id,
                    },
                  },
                },
                permissionLevel: { in: ['EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 5,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key not found or insufficient permissions');
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (!vaultKeyName) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key version not found');
  }

  // Rotate key in Vault
  await encryptionService.rotateKey(vaultKeyName);

  // Create new version in database
  const latestVersion = key.versions[0];
  const newVersion = await prisma.keyVersion.create({
    data: {
      keyId: key.id,
      versionNumber: latestVersion.versionNumber + 1,
      encryptedValue: vaultKeyName,
      encryptionMethod: 'vault-transit',
      createdById: req.user.id,
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'KEY',
    resourceId: key.id,
    details: { action: 'rotate', versionNumber: newVersion.versionNumber },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    data: { versionNumber: newVersion },
    message: 'Key rotated successfully',
  });
});

/**
 * Encrypt data
 * POST /api/v1/keys/:id/encrypt
 */
export const encryptData = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { plaintext } = req.body;

  if (!plaintext) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Plaintext is required');
  }

  const prisma = getPrismaClient();

  // Check if user has read permission (encrypt requires read)
  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: {
                      userId: req.user.id,
                    },
                  },
                },
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key not found or insufficient permissions');
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (!vaultKeyName) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key version not found');
  }

  // Encrypt using Vault
  const ciphertext = await encryptionService.encrypt(vaultKeyName, plaintext);

  res.json({
    success: true,
    data: { ciphertext },
  });
});

/**
 * Decrypt data
 * POST /api/v1/keys/:id/decrypt
 */
export const decryptData = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { ciphertext } = req.body;

  if (!ciphertext) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Ciphertext is required');
  }

  const prisma = getPrismaClient();

  // Check if user has read permission
  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
          {
            permissions: {
              some: {
                group: {
                  members: {
                    some: {
                      userId: req.user.id,
                    },
                  },
                },
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key not found or insufficient permissions');
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (!vaultKeyName) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key version not found');
  }

  // Decrypt using Vault
  const plaintext = await encryptionService.decrypt(vaultKeyName, ciphertext);

  res.json({
    success: true,
    data: { plaintext },
  });
});

/**
 * Batch encrypt multiple values
 * POST /api/v1/keys/:id/encrypt/batch
 */
export const batchEncrypt = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { plaintexts } = req.body;

  if (!Array.isArray(plaintexts) || plaintexts.length === 0) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Plaintexts array is required');
  }

  const prisma = getPrismaClient();

  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND);
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (!vaultKeyName) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key version not found');
  }

  const ciphertexts = await encryptionService.batchEncrypt(vaultKeyName, plaintexts);

  res.json({
    success: true,
    data: { ciphertexts },
  });
});

/**
 * Batch decrypt multiple values
 * POST /api/v1/keys/:id/decrypt/batch
 */
export const batchDecrypt = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { ciphertexts } = req.body;

  if (!Array.isArray(ciphertexts) || ciphertexts.length === 0) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Ciphertexts array is required');
  }

  const prisma = getPrismaClient();

  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: { in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const] },
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND);
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (!vaultKeyName) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key version not found');
  }

  const plaintexts = await encryptionService.batchDecrypt(vaultKeyName, ciphertexts);

  res.json({
    success: true,
    data: { plaintexts },
  });
});

/**
 * Delete a key
 * DELETE /api/v1/keys/:id
 */
export const deleteKey = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  // Check if user has permission to delete (ADMIN level)
  const key = await prisma.key.findFirst({
    where: {
      id,
      vault: {
        OR: [
          {
            permissions: {
              some: {
                userId: req.user.id,
                permissionLevel: 'ADMIN' as const,
              },
            },
          },
        ],
      },
    },
    include: {
      versions: {
        orderBy: { versionNumber: 'desc' },
        take: 1,
      },
    },
  });

  if (!key) {
    throw new NotFoundError(ErrorCode.KEY_NOT_FOUND, 'Key not found or insufficient permissions');
  }

  const vaultKeyName = key.versions[0]?.encryptedValue;
  if (vaultKeyName) {
    // Delete key from Vault
    await encryptionService.deleteKey(vaultKeyName);
  }

  // Delete key from database (cascade will handle versions)
  await prisma.key.delete({
    where: { id },
  });

  res.json({
    success: true,
    message: 'Key deleted successfully',
  });
});



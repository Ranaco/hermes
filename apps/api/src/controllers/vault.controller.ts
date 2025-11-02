/**
 * Vault Controller
 * Handles vault creation, management, and permissions
 */

import type { Request, Response } from 'express';
import { asyncHandler, AuthenticationError, ValidationError, ErrorCode, NotFoundError, AuthorizationError } from '@hermes/error-handling';
import getPrismaClient from '../services/prisma.service';
import { createAuditLog } from '../services/audit.service';

/**
 * Create a new vault
 * POST /api/v1/vaults
 */
export const createVault = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { name, description, organizationId } = req.body;

  if (!name) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Vault name is required');
  }

  const prisma = getPrismaClient();

  // Determine which organization to use
  let targetOrganizationId = organizationId;

  // If no organizationId provided, get user's first organization or create a default one
  if (!targetOrganizationId) {
    const userWithOrgs = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: {
        organizations: {
          include: {
            organization: true,
          },
          take: 1,
        },
      },
    });

    if (userWithOrgs?.organizations?.[0]) {
      targetOrganizationId = userWithOrgs.organizations[0].organizationId;
    } else {
      // Create a default organization for the user
      const defaultOrg = await prisma.organization.create({
        data: {
          name: `${req.user.email}'s Organization`,
          description: 'Default organization',
          members: {
            create: {
              userId: req.user.id,
              role: 'OWNER',
            },
          },
        },
      });
      targetOrganizationId = defaultOrg.id;
    }
  }

  // If organizationId was provided, verify user is a member
  if (organizationId) {
    const membership = await prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId: req.user.id,
      },
    });

    if (!membership) {
      throw new AuthorizationError(ErrorCode.NOT_ORGANIZATION_MEMBER);
    }
  }

  const vault = await prisma.vault.create({
    data: {
      name,
      description,
      organization: {
        connect: { id: targetOrganizationId },
      },
      createdBy: {
        connect: { id: req.user.id },
      },
      permissions: {
        create: {
          userId: req.user.id,
          permissionLevel: 'ADMIN',
        },
      },
    },
    include: {
      permissions: true,
      organization: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'CREATE',
    resourceType: 'VAULT',
    resourceId: vault.id,
    details: { vaultName: name },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.status(201).json({
    success: true,
    data: { vault },
    message: 'Vault created successfully',
  });
});

/**
 * Get all vaults accessible to user
 * GET /api/v1/vaults
 */
export const getVaults = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { organizationId } = req.query;

  const prisma = getPrismaClient();

  const whereClause = {
    OR: [
      {
        permissions: {
          some: {
            userId: req.user.id,
            permissionLevel: {
              in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const],
            },
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
            permissionLevel: {
              in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const],
            },
          },
        },
      },
    ],
    ...(organizationId ? { organizationId: organizationId as string } : {}),
  };

  const vaults = await prisma.vault.findMany({
    where: whereClause,
    include: {
      organization: {
        select: {
          id: true,
          name: true,
        },
      },
      _count: {
        select: {
          keys: true,
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({
    success: true,
    data: { vaults },
  });
});

/**
 * Get a specific vault
 * GET /api/v1/vaults/:id
 */
export const getVault = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  const vault = await prisma.vault.findFirst({
    where: {
      id,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: {
                in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const],
              },
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
              permissionLevel: {
                in: ['VIEW' as const, 'USE' as const, 'EDIT' as const, 'ADMIN' as const],
              },
            },
          },
        },
      ],
    },
    include: {
      organization: {
        select: {
          id: true,
          name: true,
        },
      },
      permissions: {
        include: {
          user: {
            select: {
              id: true,
              email: true,
              username: true,
              firstName: true,
              lastName: true,
            },
          },
          group: {
            select: {
              id: true,
              name: true,
            },
          },
        },
      },
      _count: {
        select: {
          keys: true,
        },
      },
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND);
  }

  res.json({
    success: true,
    data: { vault },
  });
});

/**
 * Update a vault
 * PATCH /api/v1/vaults/:id
 */
export const updateVault = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { name, description } = req.body;

  const prisma = getPrismaClient();

  // Check if user has write permission (USE, EDIT, or ADMIN level)
  const vault = await prisma.vault.findFirst({
    where: {
      id,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: {
                in: ['USE' as const, 'EDIT' as const, 'ADMIN' as const],
              },
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
              permissionLevel: {
                in: ['USE' as const, 'EDIT' as const, 'ADMIN' as const],
              },
            },
          },
        },
      ],
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  const updateData: Partial<{ name: string; description: string | null }> = {};
  if (name !== undefined) updateData.name = name;
  if (description !== undefined) updateData.description = description;

  const updatedVault = await prisma.vault.update({
    where: { id },
    data: updateData,
    include: {
      organization: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'VAULT',
    resourceId: id,
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    details: { changes: updateData },
  });

  res.json({
    success: true,
    data: { vault: updatedVault },
    message: 'Vault updated successfully',
  });
});

/**
 * Delete a vault
 * DELETE /api/v1/vaults/:id
 */
export const deleteVault = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  // Check if user has delete permission (ADMIN level required)
  const vault = await prisma.vault.findFirst({
    where: {
      id,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: 'ADMIN' as const,
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
              permissionLevel: 'ADMIN' as const,
            },
          },
        },
      ],
    },
    include: {
      _count: {
        select: {
          keys: true,
        },
      },
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  // Delete vault (cascade will handle keys and permissions)
  await prisma.vault.delete({
    where: { id },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'DELETE',
    resourceType: 'VAULT',
    resourceId: id,
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    details: { vaultName: vault.name },
  });

  res.json({
    success: true,
    message: 'Vault deleted successfully',
  });
});

/**
 * Grant vault permissions to a user
 * POST /api/v1/vaults/:id/permissions/users
 */
export const grantUserPermission = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { userId, permissionLevel } = req.body;

  if (!userId || !permissionLevel) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'User ID and permission level are required');
  }

  const prisma = getPrismaClient();

  // Check if current user has permission to manage permissions (ADMIN level)
  const vault = await prisma.vault.findFirst({
    where: {
      id,
      OR: [
        {
          permissions: {
            some: {
              userId: req.user.id,
              permissionLevel: 'ADMIN' as const,
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
              permissionLevel: 'ADMIN' as const,
            },
          },
        },
      ],
    },
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  // Check if target user exists
  const targetUser = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!targetUser) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND);
  }

  // Create or update permission
  const permission = await prisma.vaultPermission.upsert({
    where: {
      userId_vaultId: {
        vaultId: id,
        userId,
      },
    },
    create: {
      vaultId: id,
      userId,
      permissionLevel,
    },
    update: {
      permissionLevel,
    },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
        },
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'VAULT',
    resourceId: id,
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    details: { targetUserId: userId, permissionLevel },
  });

  res.status(201).json({
    success: true,
    data: { permission },
    message: 'Permission granted successfully',
  });
});

/**
 * Revoke vault permissions from a user
 * DELETE /api/v1/vaults/:id/permissions/users/:userId
 */
export const revokeUserPermission = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id, userId } = req.params;

  const prisma = getPrismaClient();

  // Check if current user has permission to manage permissions (ADMIN level)
  const vault = await prisma.vault.findFirst({
    where: {
      id,
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
  });

  if (!vault) {
    throw new NotFoundError(ErrorCode.VAULT_NOT_FOUND, 'Vault not found or insufficient permissions');
  }

  // Delete permission
  await prisma.vaultPermission.delete({
    where: {
      userId_vaultId: {
        vaultId: id,
        userId,
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'DELETE',
    resourceType: 'VAULT',
    resourceId: id,
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    details: { targetUserId: userId },
  });

  res.json({
    success: true,
    message: 'Permission revoked successfully',
  });
});


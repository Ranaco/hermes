/**
 * Organization Controller
 * Handles organization management and membership
 */

import type { Request, Response } from 'express';
import { asyncHandler, AuthenticationError, ValidationError, ErrorCode, NotFoundError, AuthorizationError, ConflictError } from '@hermes/error-handling';
import getPrismaClient from '../services/prisma.service';
import { createAuditLog } from '../services/audit.service';

/**
 * Create a new organization
 * POST /api/v1/organizations
 */
export const createOrganization = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { name, description } = req.body;

  if (!name) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Organization name is required');
  }

  const prisma = getPrismaClient();

  const organization = await prisma.organization.create({
    data: {
      name,
      description,
      members: {
        create: {
          userId: req.user.id,
          role: 'OWNER',
        },
      },
    },
    include: {
      members: {
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
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'CREATE',
    resourceType: 'ORGANIZATION',
    resourceId: organization.id,
    details: { name, description },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.status(201).json({
    success: true,
    data: { organization },
    message: 'Organization created successfully',
  });
});

/**
 * Get organizations user is a member of
 * GET /api/v1/organizations
 */
export const getOrganizations = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const prisma = getPrismaClient();

  const memberships = await prisma.organizationMember.findMany({
    where: {
      userId: req.user.id,
    },
    include: {
      organization: {
        include: {
          _count: {
            select: {
              members: true,
              vaults: true,
            },
          },
        },
      },
    },
  });

  const organizations = memberships.map(m => ({
    ...m.organization,
    userRole: m.role,
  }));

  res.json({
    success: true,
    data: { organizations },
  });
});

/**
 * Get a specific organization
 * GET /api/v1/organizations/:id
 */
export const getOrganization = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
    },
    include: {
      organization: {
        include: {
          members: {
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
          },
          _count: {
            select: {
              vaults: true,
            },
          },
        },
      },
    },
  });

  if (!membership) {
    throw new NotFoundError(ErrorCode.ORGANIZATION_NOT_FOUND);
  }

  res.json({
    success: true,
    data: {
      organization: {
        id: membership.organization.id,
        name: membership.organization.name,
        description: membership.organization.description,
        createdAt: membership.organization.createdAt,
        updatedAt: membership.organization.updatedAt,
        members: membership.organization.members,
        _count: membership.organization._count,
        userRole: membership.role,
      },
    },
  });
});

/**
 * Update organization
 * PATCH /api/v1/organizations/:id
 */
export const updateOrganization = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { name, description } = req.body;

  const prisma = getPrismaClient();

  // Check if user is admin or owner
  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
      role: {
        in: ['ADMIN', 'OWNER'],
      },
    },
  });

  if (!membership) {
    throw new AuthorizationError(ErrorCode.INSUFFICIENT_PERMISSIONS);
  }

  const updateData: Record<string, unknown> = {};
  if (name !== undefined) updateData.name = name;
  if (description !== undefined) updateData.description = description;

  const organization = await prisma.organization.update({
    where: { id },
    data: updateData,
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'UPDATE',
    resourceType: 'ORGANIZATION',
    resourceId: id,
    details: { name, description },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    data: { organization },
    message: 'Organization updated successfully',
  });
});

/**
 * Delete organization
 * DELETE /api/v1/organizations/:id
 */
export const deleteOrganization = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;

  const prisma = getPrismaClient();

  // Only owners can delete
  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
      role: 'OWNER',
    },
  });

  if (!membership) {
    throw new AuthorizationError(ErrorCode.INSUFFICIENT_PERMISSIONS, 'Only owners can delete organizations');
  }

  await prisma.organization.delete({
    where: { id },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'DELETE',
    resourceType: 'ORGANIZATION',
    resourceId: id,
    details: {},
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'Organization deleted successfully',
  });
});

/**
 * Invite user to organization
 * POST /api/v1/organizations/:id/invitations
 */
export const inviteUser = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id } = req.params;
  const { email, role = 'MEMBER' } = req.body;

  if (!email) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Email is required');
  }

  const prisma = getPrismaClient();

  // Check if user is admin or owner
  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
      role: {
        in: ['ADMIN', 'OWNER'],
      },
    },
  });

  if (!membership) {
    throw new AuthorizationError(ErrorCode.INSUFFICIENT_PERMISSIONS);
  }

  // Check if target user exists
  const targetUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (!targetUser) {
    throw new NotFoundError(ErrorCode.USER_NOT_FOUND, 'User not found');
  }

  // Check if already a member
  const existingMember = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: targetUser.id,
    },
  });

  if (existingMember) {
    throw new ConflictError(ErrorCode.VALIDATION_ERROR, 'User is already a member');
  }

  // Add user to organization
  const newMember = await prisma.organizationMember.create({
    data: {
      organizationId: id,
      userId: targetUser.id,
      role,
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
    action: 'CREATE',
    resourceType: 'ORGANIZATION',
    resourceId: id,
    details: { userId: targetUser.id, role },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.status(201).json({
    success: true,
    data: { member: newMember },
    message: 'User added to organization successfully',
  });
});

/**
 * Remove member from organization
 * DELETE /api/v1/organizations/:id/members/:userId
 */
export const removeMember = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id, userId } = req.params;

  const prisma = getPrismaClient();

  // Check if user is admin or owner
  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
      role: {
        in: ['ADMIN', 'OWNER'],
      },
    },
  });

  if (!membership) {
    throw new AuthorizationError(ErrorCode.INSUFFICIENT_PERMISSIONS);
  }

  // Check if target is the last owner
  if (userId !== req.user.id) {
    const targetMembership = await prisma.organizationMember.findFirst({
      where: {
        organizationId: id,
        userId,
      },
    });

    if (targetMembership?.role === 'OWNER') {
      const ownerCount = await prisma.organizationMember.count({
        where: {
          organizationId: id,
          role: 'OWNER',
        },
      });

      if (ownerCount <= 1) {
        throw new ConflictError(
          ErrorCode.PERMISSION_DENIED,
          'Cannot remove the last owner. Transfer ownership first.'
        );
      }
    }
  }

  await prisma.organizationMember.delete({
    where: {
      organizationId_userId: {
        organizationId: id,
        userId,
      },
    },
  });

  await createAuditLog({
    userId: req.user.id,
    action: 'DELETE',
    resourceType: 'ORGANIZATION',
    resourceId: id,
    details: { removedUserId: userId },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    message: 'Member removed successfully',
  });
});

/**
 * Update member role
 * PATCH /api/v1/organizations/:id/members/:userId
 */
export const updateMemberRole = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new AuthenticationError(ErrorCode.UNAUTHORIZED);
  }

  const { id, userId } = req.params;
  const { role } = req.body;

  if (!role) {
    throw new ValidationError(ErrorCode.VALIDATION_ERROR, 'Role is required');
  }

  const prisma = getPrismaClient();

  // Only owners can change roles
  const membership = await prisma.organizationMember.findFirst({
    where: {
      organizationId: id,
      userId: req.user.id,
      role: 'OWNER',
    },
  });

  if (!membership) {
    throw new AuthorizationError(ErrorCode.INSUFFICIENT_PERMISSIONS, 'Only owners can change member roles');
  }

  const updatedMember = await prisma.organizationMember.update({
    where: {
      organizationId_userId: {
        organizationId: id,
        userId,
      },
    },
    data: { role },
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
    resourceType: 'ORGANIZATION',
    resourceId: id,
    details: { targetUserId: userId, newRole: role },
    ipAddress: req.ip || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  });

  res.json({
    success: true,
    data: { member: updatedMember },
    message: 'Member role updated successfully',
  });
});

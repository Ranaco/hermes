import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { getClerkClient, syncUserFromClerk, getUserByClerkId, deleteUserByClerkId } from '../services/clerk.service';
import getPrismaClient from '../services/prisma.service';

// Mock dependencies
jest.mock('../services/prisma.service');
jest.mock('@clerk/clerk-sdk-node', () => ({
  createClerkClient: jest.fn().mockReturnValue({
    users: {
      getUser: jest.fn()
    }
  })
}));
jest.mock('@hermit/logger');

describe('Clerk Service', () => {
  let mockPrisma: any;
  let mockClerkClient: any;

  beforeEach(() => {
    jest.clearAllMocks();
    mockPrisma = {
      user: {
        upsert: jest.fn(),
        findUnique: jest.fn(),
        delete: jest.fn()
      }
    };
    (getPrismaClient as any).mockReturnValue(mockPrisma);
    mockClerkClient = getClerkClient();
  });

  describe('getUserByClerkId', () => {
    it('should return user from Prisma by Clerk ID', async () => {
      const clerkUserId = 'user_123';
      const expectedUser = { id: 'internal_123', clerkId: clerkUserId };
      mockPrisma.user.findUnique.mockResolvedValue(expectedUser);

      const result = await getUserByClerkId(clerkUserId);

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { clerkId: clerkUserId }
      });
      expect(result).toEqual(expectedUser);
    });
  });

  describe('syncUserFromClerk', () => {
    it('should sync a user from Clerk to Prisma', async () => {
      const clerkUserId = 'user_123';
      const clerkUser = {
        id: clerkUserId,
        emailAddresses: [{ emailAddress: 'test@example.com' }],
        username: 'testuser',
        firstName: 'Test',
        lastName: 'User'
      };

      mockClerkClient.users.getUser.mockResolvedValue(clerkUser);
      mockPrisma.user.upsert.mockResolvedValue({ id: 'internal_123', email: 'test@example.com' });

      const result = await syncUserFromClerk(clerkUserId);

      expect(mockClerkClient.users.getUser).toHaveBeenCalledWith(clerkUserId);
      expect(mockPrisma.user.upsert).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
        update: {
          clerkId: clerkUserId,
          firstName: 'Test',
          lastName: 'User'
        },
        create: {
          clerkId: clerkUserId,
          email: 'test@example.com',
          username: 'testuser',
          passwordHash: 'CLERK_MANAGED',
          firstName: 'Test',
          lastName: 'User',
          isEmailVerified: true
        }
      });
      expect(result).toEqual({ id: 'internal_123', email: 'test@example.com' });
    });

    it('should throw error if Clerk user has no email', async () => {
      const clerkUserId = 'user_123';
      const clerkUser = {
        id: clerkUserId,
        emailAddresses: []
      };

      mockClerkClient.users.getUser.mockResolvedValue(clerkUser);

      await expect(syncUserFromClerk(clerkUserId)).rejects.toThrow('Clerk user has no email');
    });
  });

  describe('deleteUserByClerkId', () => {
    it('should delete user from Prisma if found', async () => {
      const clerkUserId = 'user_123';
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'internal_123' });
      mockPrisma.user.delete.mockResolvedValue({ id: 'internal_123' });

      await deleteUserByClerkId(clerkUserId);

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { clerkId: clerkUserId },
        select: { id: true }
      });
      expect(mockPrisma.user.delete).toHaveBeenCalledWith({
        where: { id: 'internal_123' }
      });
    });

    it('should do nothing if user not found', async () => {
      const clerkUserId = 'user_123';
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await deleteUserByClerkId(clerkUserId);

      expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
        where: { clerkId: clerkUserId },
        select: { id: true }
      });
      expect(mockPrisma.user.delete).not.toHaveBeenCalled();
    });
  });
});

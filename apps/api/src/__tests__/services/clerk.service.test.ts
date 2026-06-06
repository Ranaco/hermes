import { jest } from '@jest/globals';
import { verifySession, getUser, verifyToken } from '../../services/clerk.service';

// Mock the clerkClient that was created in the service
jest.mock('@clerk/clerk-sdk-node', () => {
  const mockClerkClient = {
    sessions: {
      getSession: jest.fn(),
    },
    users: {
      getUser: jest.fn(),
    },
    verifyToken: jest.fn(),
  };
  return {
    createClerkClient: jest.fn(() => mockClerkClient),
  };
});

// We need to re-import or get the mocked client to verify calls
import { createClerkClient } from '@clerk/clerk-sdk-node';
const mockClerkClient = (createClerkClient as any)();

describe('ClerkService', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('verifySession', () => {
    it('should call sessions.getSession with the provided token', async () => {
      const token = 'test-token';
      mockClerkClient.sessions.getSession.mockResolvedValue({ id: 'sess_123' });

      const result = await verifySession(token);

      expect(mockClerkClient.sessions.getSession).toHaveBeenCalledWith(token);
      expect(result).toEqual({ id: 'sess_123' });
    });

    it('should throw if sessions.getSession fails', async () => {
      const token = 'invalid-token';
      mockClerkClient.sessions.getSession.mockRejectedValue(new Error('Session not found'));

      await expect(verifySession(token)).rejects.toThrow('Session not found');
    });
  });

  describe('getUser', () => {
    it('should call users.getUser with the provided userId', async () => {
      const userId = 'user_123';
      mockClerkClient.users.getUser.mockResolvedValue({ id: 'user_123', email: 'test@example.com' });

      const result = await getUser(userId);

      expect(mockClerkClient.users.getUser).toHaveBeenCalledWith(userId);
      expect(result).toEqual({ id: 'user_123', email: 'test@example.com' });
    });
  });

  describe('verifyToken', () => {
    it('should call verifyToken with the provided token', async () => {
      const token = 'jwt-token';
      mockClerkClient.verifyToken.mockResolvedValue({ sub: 'user_123' });

      const result = await verifyToken(token);

      expect(mockClerkClient.verifyToken).toHaveBeenCalledWith(token);
      expect(result).toEqual({ sub: 'user_123' });
    });
  });
});

import { createClerkClient } from '@clerk/clerk-sdk-node';
import config from '../config/index';

/**
 * Clerk Service
 * Handles interaction with Clerk for authentication and user management
 */

const clerkClient = createClerkClient({
  secretKey: config.clerk.secretKey,
  publishableKey: config.clerk.publishableKey,
});

/**
 * Verify a session token from Clerk
 * @param token Clerk session token (usually from Authorization header)
 * @returns The verified session object
 */
export const verifySession = async (token: string) => {
  try {
    // In newer Clerk Node SDK, we use clerkClient.authenticateRequest for middleware
    // but for manual verification of a token we can use sessions.verifySession or verifyToken
    return await clerkClient.sessions.getSession(token);
  } catch (error) {
    throw error;
  }
};

/**
 * Get user details from Clerk
 * @param userId Clerk user ID
 * @returns User object
 */
export const getUser = async (userId: string) => {
  return await clerkClient.users.getUser(userId);
};

/**
 * Verify a JWT token issued by Clerk
 * @param token JWT token
 * @returns The decoded payload
 */
export const verifyToken = async (token: string) => {
  return await clerkClient.verifyToken(token);
};

export default clerkClient;

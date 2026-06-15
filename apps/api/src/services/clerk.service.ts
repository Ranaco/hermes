/**
 * Clerk Service
 * Singleton Clerk Client instance and helper methods
 */

import { createClerkClient } from '@clerk/clerk-sdk-node';
import config from '../config';
import { log } from '@hermit/logger';

let clerk: ReturnType<typeof createClerkClient> | null = null;

/**
 * Get Clerk Client instance
 */
export function getClerkClient() {
  if (!clerk) {
    if (!config.clerk.secretKey) {
      log.warn('CLERK_SECRET_KEY is not configured. Clerk operations will fail.');
    }
    
    clerk = createClerkClient({
      secretKey: config.clerk.secretKey,
      publishableKey: config.clerk.publishableKey,
    });
    
    log.info('Clerk client initialized');
  }

  return clerk;
}

/**
 * Sync Clerk user with internal database
 * This is a placeholder for actual synchronization logic
 */
export async function syncUserFromClerk(clerkUserId: string) {
  const clerkClient = getClerkClient();
  
  try {
    const clerkUser = await clerkClient.users.getUser(clerkUserId);
    
    // Here we would typically find or create a user in our Prisma database
    // mapping the clerkUserId to our internal user record.
    
    return clerkUser;
  } catch (error) {
    log.error('Failed to sync user from Clerk', { clerkUserId, error });
    throw error;
  }
}

export default getClerkClient;

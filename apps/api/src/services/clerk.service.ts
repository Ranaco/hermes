/**
 * Clerk Service
 * Singleton Clerk Client instance and helper methods
 */

import { createClerkClient } from '@clerk/clerk-sdk-node';
import config from '../config';
import { log } from '@hermit/logger';
import getPrismaClient from './prisma.service';

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
 */
export async function syncUserFromClerk(clerkUserId: string) {
  const clerkClient = getClerkClient();
  const prisma = getPrismaClient();
  
  try {
    const clerkUser = await clerkClient.users.getUser(clerkUserId);
    const userEmail = clerkUser.emailAddresses[0]?.emailAddress;

    if (!userEmail) {
      log.error('Clerk user has no email', { clerkUserId });
      throw new Error('Clerk user has no email');
    }

    const user = await prisma.user.upsert({
      where: { email: userEmail },
      update: { 
        clerkId: clerkUserId,
        firstName: clerkUser.firstName || undefined,
        lastName: clerkUser.lastName || undefined,
      },
      create: {
        clerkId: clerkUserId,
        email: userEmail,
        username: clerkUser.username || userEmail,
        passwordHash: 'CLERK_MANAGED',
        firstName: clerkUser.firstName || null,
        lastName: clerkUser.lastName || null,
        isEmailVerified: true,
      },
    });
    
    return user;
  } catch (error) {
    log.error('Failed to sync user from Clerk', { clerkUserId, error });
    throw error;
  }
}

export default getClerkClient;

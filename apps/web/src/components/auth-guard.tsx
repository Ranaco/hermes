"use client";

import { useEffect, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useAuth, useUser } from "@clerk/nextjs";
import { useAuthStore } from "@/store/auth.store";

const PROTECTED_PREFIXES = ["/dashboard", "/onboarding", "/invite"];
const GUEST_ONLY = ["/login"];

function isProtected(path: string) {
  return PROTECTED_PREFIXES.some((p) => path === p || path.startsWith(p + "/"));
}

function isGuestOnly(path: string) {
  return GUEST_ONLY.some((p) => path === p || path.startsWith(p + "/"));
}

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isLoaded, userId, getToken } = useAuth();
  const { user: clerkUser } = useUser();
  const pathname = usePathname();
  const router = useRouter();
  const isAuthenticated = !!userId;
  const setUser = useAuthStore((s) => s.setUser);

  useEffect(() => {
    if (isLoaded && clerkUser) {
      setUser({
        id: clerkUser.id,
        email: clerkUser.emailAddresses[0]?.emailAddress || "",
        username: clerkUser.username || "",
        firstName: clerkUser.firstName,
        lastName: clerkUser.lastName,
        isEmailVerified: clerkUser.emailAddresses[0]?.verification?.status === "verified",
        isTwoFactorEnabled: clerkUser.twoFactorEnabled,
      });

      // Sync token to localStorage for axios interceptor
      getToken().then((token) => {
        if (token) localStorage.setItem("auth_token", token);
      });
    } else if (isLoaded && !isAuthenticated) {
      setUser(null);
      localStorage.removeItem("auth_token");
    }
  }, [isLoaded, clerkUser, isAuthenticated, setUser, getToken]);

  useEffect(() => {
    if (!isLoaded) return;

    if (!isAuthenticated && isProtected(pathname)) {
      const returnUrl = encodeURIComponent(pathname);
      router.replace(`/login?returnUrl=${returnUrl}`);
    }

    if (isAuthenticated && isGuestOnly(pathname)) {
      router.replace("/dashboard");
    }
  }, [isLoaded, isAuthenticated, pathname, router]);

  // Show loader while Clerk is loading
  if (!isLoaded) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // Don't render protected content if not authenticated (redirect is pending)
  if (isLoaded && !isAuthenticated && isProtected(pathname)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // Don't render guest pages if authenticated (redirect is pending)
  if (isLoaded && isAuthenticated && isGuestOnly(pathname)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <>{children}</>;
}

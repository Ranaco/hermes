"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowRight,
} from "lucide-react";
import { AuthShell } from "@/components/auth-shell";
import { SignIn, SignUp } from "@clerk/nextjs";

type AuthMode = "signin" | "signup";

const modeCopy = {
  signin: {
    eyebrow: "Sign In",
    title: "Sign in to Hermit",
    description: "Return to your workspace.",
    asideTitle: "Welcome back.",
    asideDescription: "Pick up where you left off.",
    formNote: "Vault prompts happen at reveal time.",
    checklist: [
      "Restores workspace context.",
      "Returns to protected flows.",
      "Keeps audit continuity.",
    ],
  },
  signup: {
    eyebrow: "Sign Up",
    title: "Create your account",
    description: "Account first, then your workspace.",
    asideTitle: "Start here.",
    asideDescription: "Account first. Organization next.",
    formNote: "Next step: organization setup.",
    checklist: [
      "Create your identity.",
      "Name your first organization.",
      "Invite teammates later.",
    ],
  },
} satisfies Record<
  AuthMode,
  {
    eyebrow: string;
    title: string;
    description: string;
    asideTitle: string;
    asideDescription: string;
    formNote: string;
    checklist: string[];
  }
>;

function LoginContent() {
  const searchParams = useSearchParams();
  const returnUrl = searchParams.get("returnUrl") || "/dashboard";
  const [mode, setMode] = useState<AuthMode>("signin");

  const isLogin = mode === "signin";
  const copy = modeCopy[mode];

  return (
    <AuthShell
      eyebrow={copy.eyebrow}
      title={copy.title}
      description={copy.description}
      asideTitle={copy.asideTitle}
      asideDescription={copy.asideDescription}
      features={[]}
      footerNote={copy.formNote}
    >
      <div className="space-y-7">
        <div className="grid gap-4 rounded-[24px] border border-black/5 bg-background/55 p-4 dark:border-white/10 dark:bg-white/[0.03]">
          <div className="flex items-center justify-between gap-4">
            <p className="text-sm font-semibold tracking-tight text-foreground">
              {isLogin ? "Sign in" : "New account"}
            </p>
            <div className="shrink-0 whitespace-nowrap rounded-md border border-border bg-muted/50 px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
              {isLogin ? "Return Flow" : "Setup Flow"}
            </div>
          </div>

          <div className="inline-flex rounded-full border border-black/5 bg-background/80 p-1 dark:border-white/10 dark:bg-white/[0.04]">
            <button
              type="button"
              onClick={() => setMode("signin")}
              className={`rounded-full px-4 py-2 text-sm font-medium transition-colors ${
                isLogin
                  ? "bg-foreground text-background"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => setMode("signup")}
              className={`rounded-full px-4 py-2 text-sm font-medium transition-colors ${
                !isLogin
                  ? "bg-foreground text-background"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Sign up
            </button>
          </div>

          <div className="grid gap-2 sm:grid-cols-3">
            {copy.checklist.map((item) => (
              <div
                key={item}
                className="rounded-[16px] border border-black/5 bg-background/75 px-3 py-3 text-[12px] font-medium leading-5 text-muted-foreground dark:border-white/8 dark:bg-white/[0.025]"
              >
                {item}
              </div>
            ))}
          </div>
        </div>

        <div className="flex justify-center">
          {isLogin ? (
            <SignIn 
              routing="hash" 
              forceRedirectUrl={returnUrl}
              appearance={{
                elements: {
                  rootBox: "w-full",
                  card: "shadow-none border-none bg-transparent p-0",
                  headerTitle: "hidden",
                  headerSubtitle: "hidden",
                  socialButtonsBlockButton: "rounded-2xl border-black/8 dark:border-white/10",
                  formButtonPrimary: "rounded-2xl h-12",
                  formFieldInput: "rounded-2xl h-11 border-black/8 dark:border-white/10 bg-background/70",
                  footer: "hidden"
                }
              }}
            />
          ) : (
            <SignUp 
              routing="hash" 
              forceRedirectUrl="/onboarding"
              appearance={{
                elements: {
                  rootBox: "w-full",
                  card: "shadow-none border-none bg-transparent p-0",
                  headerTitle: "hidden",
                  headerSubtitle: "hidden",
                  socialButtonsBlockButton: "rounded-2xl border-black/8 dark:border-white/10",
                  formButtonPrimary: "rounded-2xl h-12",
                  formFieldInput: "rounded-2xl h-11 border-black/8 dark:border-white/10 bg-background/70",
                  footer: "hidden"
                }
              }}
            />
          )}
        </div>

        <div className="flex flex-col gap-3 border-t border-black/5 pt-5 text-sm dark:border-white/10 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            onClick={() => setMode(isLogin ? "signup" : "signin")}
            className="inline-flex items-center gap-2 text-left font-medium text-primary transition-colors hover:text-primary/80"
          >
            <span>{isLogin ? "New here?" : "Have an account?"}</span>
            <span>{isLogin ? "Create account" : "Sign in"}</span>
            <ArrowRight className="h-4 w-4" />
          </button>
          <Link href="/" className="font-medium text-muted-foreground hover:text-foreground">
            Return to overview
          </Link>
        </div>
      </div>
    </AuthShell>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-background text-muted-foreground">
          Loading...
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-background text-muted-foreground">
          Loading...
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}

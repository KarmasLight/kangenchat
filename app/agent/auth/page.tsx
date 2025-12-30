"use client";

import { useState, useEffect, FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { BACKEND_URL, getAgentSocket } from "@/lib/agentSocket";

const socket = getAgentSocket();

type AgentRole = "ADMIN" | "MANAGER" | "AGENT";

type AgentProfile = {
  id?: string;
  email?: string;
  name?: string;
  displayName?: string;
  phone?: string;
  avatarUrl?: string;
  status?: string;
  role?: AgentRole;
};

export default function AgentAuthPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const resetToken = searchParams.get("token");
  const resetEmailParam = searchParams.get("email") ?? "";
  const [status, setStatus] = useState<string>("");
  const [statusKind, setStatusKind] = useState<"idle" | "info" | "success" | "error">("idle");
  const [loading, setLoading] = useState<boolean>(false);
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [forgotEmail, setForgotEmail] = useState<string>("");
  const [resetPassword, setResetPassword] = useState<string>("");
  const [resetPasswordConfirm, setResetPasswordConfirm] = useState<string>("");

  useEffect(() => {
    try {
      const existingToken = window.localStorage.getItem("agent_token");
      if (existingToken) {
        router.replace("/agent");
      }
    } catch {
      // ignore localStorage access issues
    }
  }, [router]);

  const resetStatus = () => {
    setStatus("");
    setStatusKind("idle");
  };

  const updateStatus = (kind: "info" | "success" | "error", message: string) => {
    setStatusKind(kind);
    setStatus(message);
  };

  const ensureValidEmail = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return false;
    const basicEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return basicEmailRegex.test(trimmed);
  };

  const completeAuth = (token: string, agent: AgentProfile | null | undefined) => {
    try {
      window.localStorage.setItem("agent_token", token);
      if (agent) {
        window.localStorage.setItem("agent_profile", JSON.stringify(agent));
      } else {
        window.localStorage.removeItem("agent_profile");
      }
      window.localStorage.removeItem("selected_session");
    } catch (error) {
      console.error("Error setting local storage:", error);
    }

    socket.auth = { token };
    const proceed = () => {
      socket.emit("agent_ready");
      setStatus("Success! Redirecting...");
      router.replace("/agent");
    };

    if (socket.connected) {
      proceed();
    } else {
      socket.once("connect", proceed);
      socket.connect();
    }
  };

  const handleForgotPassword = async (event?: FormEvent) => {
    event?.preventDefault();
    const targetEmail = (forgotEmail || email).trim();
    if (!ensureValidEmail(targetEmail)) {
      updateStatus("error", "Enter a valid email address.");
      return;
    }
    setLoading(true);
    updateStatus("info", "Sending reset link...");
    try {
      const res = await fetch(`${BACKEND_URL}/password/forgot`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: targetEmail }),
      });
      if (!res.ok) {
        updateStatus("error", "Unable to send reset email. Please try again.");
        return;
      }
      updateStatus("success", "If an account exists for that email, a reset link has been sent.");
    } catch {
      updateStatus("error", "Unable to reach server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (event?: FormEvent) => {
    event?.preventDefault();
    const trimmedEmail = email.trim();
    if (!ensureValidEmail(trimmedEmail)) {
      updateStatus("error", "Enter a valid email address.");
      return;
    }
    if (!password) {
      updateStatus("error", "Password is required.");
      return;
    }

    setLoading(true);
    updateStatus("info", "Logging in...");
    try {
      const res = await fetch(`${BACKEND_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimmedEmail, password }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.token) {
        updateStatus("error", data?.error ? `Login failed: ${data.error}` : "Login failed. Check your credentials and try again.");
        return;
      }
      completeAuth(data.token as string, data.agent as AgentProfile | undefined);
      updateStatus("success", "Success! Redirecting...");
    } catch {
      updateStatus("error", "Unable to reach server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordReset = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!resetToken) {
      updateStatus("error", "Reset link is invalid or has expired.");
      return;
    }
    const trimmed = resetPassword.trim();
    const trimmedConfirm = resetPasswordConfirm.trim();
    if (!trimmed) {
      updateStatus("error", "New password is required.");
      return;
    }
    if (trimmed.length < 8) {
      updateStatus("error", "Password must be at least 8 characters long.");
      return;
    }
    if (trimmed !== trimmedConfirm) {
      updateStatus("error", "Passwords do not match.");
      return;
    }
    setLoading(true);
    updateStatus("info", "Resetting password...");
    try {
      const res = await fetch(`${BACKEND_URL}/password/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: resetToken, email: resetEmailParam || undefined, newPassword: trimmed }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        updateStatus("error", data?.error ?? "Password reset failed. The link may have expired.");
        return;
      }
      updateStatus("success", "Password updated. You can now log in with your new password.");
    } catch {
      updateStatus("error", "Unable to reach server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  if (resetToken) {
    return (
      <div className="min-h-screen w-full bg-gray-100 dark:bg-gray-950 flex items-center justify-center p-6">
        <Card className="w-full max-w-lg">
          <CardHeader>
            <CardTitle className="text-center text-2xl">Reset Password</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handlePasswordReset} className="space-y-3">
              <div>
                <Label htmlFor="reset-email">Email</Label>
                <Input
                  id="reset-email"
                  type="email"
                  autoComplete="email"
                  value={resetEmailParam || email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                />
              </div>
              <div>
                <Label htmlFor="reset-password">New password</Label>
                <Input
                  id="reset-password"
                  type="password"
                  autoComplete="new-password"
                  value={resetPassword}
                  onChange={(event) => setResetPassword(event.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="reset-password-confirm">Confirm new password</Label>
                <Input
                  id="reset-password-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={resetPasswordConfirm}
                  onChange={(event) => setResetPasswordConfirm(event.target.value)}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? "Resetting..." : "Set new password"}
              </Button>
            </form>

            {statusKind !== "idle" && status && (
              <Alert className="mt-4" variant={statusKind === "error" ? "destructive" : "default"}>
                <AlertTitle>
                  {statusKind === "error" ? "Something went wrong" : statusKind === "success" ? "Success" : "Status"}
                </AlertTitle>
                <AlertDescription>{status}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full bg-gray-100 dark:bg-gray-950 flex items-center justify-center p-6">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle className="text-center text-2xl">Agent Access</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-3">
                <div>
                  <Label htmlFor="login-email">Email</Label>
                  <Input
                    id="login-email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="login-password">Password</Label>
                  <Input
                    id="login-password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                  />
                </div>
                <div className="flex justify-end">
                  <button
                    type="button"
                    className="text-xs text-primary underline-offset-2 underline"
                    onClick={() => {
                      setForgotEmail(email);
                      resetStatus();
                    }}
                  >
                    Forgot password?
                  </button>
                </div>
                {forgotEmail && (
                  <form onSubmit={handleForgotPassword} className="space-y-2 border rounded-md p-3 text-xs">
                    <div>
                      <Label htmlFor="forgot-email">Reset email</Label>
                      <Input
                        id="forgot-email"
                        type="email"
                        autoComplete="email"
                        value={forgotEmail}
                        onChange={(event) => setForgotEmail(event.target.value)}
                      />
                    </div>
                    <Button type="submit" size="sm" disabled={loading} className="w-full">
                      {loading ? "Sending..." : "Send reset link"}
                    </Button>
                  </form>
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? "Logging in..." : "Log in"}
                </Button>
              </form>

          {statusKind !== "idle" && status && (
            <Alert className="mt-4" variant={statusKind === "error" ? "destructive" : "default"}>
              <AlertTitle>
                {statusKind === "error" ? "Something went wrong" : statusKind === "success" ? "Success" : "Status"}
              </AlertTitle>
              <AlertDescription>{status}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

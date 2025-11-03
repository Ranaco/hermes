import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { authService, type LoginCredentials, type RegisterData } from "@/services/auth.service";
import { useAuthStore } from "@/store/auth.store";
import { toast } from "sonner";

export function useLogin() {
  const { setUser, setToken } = useAuthStore();

  return useMutation({
    mutationFn: (credentials: LoginCredentials) => authService.login(credentials),
    onSuccess: (data) => {
      setUser(data.user);
      setToken(data.token);
      toast.success("Login successful!");
    },
    onError: () => {
      toast.error("Login failed. Please check your credentials.");
    },
  });
}

export function useRegister() {
  const { setUser, setToken } = useAuthStore();

  return useMutation({
    mutationFn: (data: RegisterData) => authService.register(data),
    onSuccess: (data) => {
      setUser(data.user);
      setToken(data.token);
      toast.success("Registration successful!");
    },
    onError: () => {
      toast.error("Registration failed. Please try again.");
    },
  });
}

export function useLogout() {
  const { logout } = useAuthStore();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: authService.logout,
    onSuccess: () => {
      logout();
      queryClient.clear();
      toast.success("Logged out successfully");
    },
  });
}

export function useCurrentUser() {
  const { isAuthenticated } = useAuthStore();

  return useQuery({
    queryKey: ["currentUser"],
    queryFn: authService.getCurrentUser,
    enabled: isAuthenticated,
  });
}

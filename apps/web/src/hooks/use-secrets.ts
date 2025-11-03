import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { secretService, type CreateSecretData } from "@/services/secret.service";
import { toast } from "sonner";

export function useSecrets(vaultId?: string) {
  return useQuery({
    queryKey: ["secrets", vaultId],
    queryFn: () => secretService.getAll(vaultId),
  });
}

export function useSecret(id: string) {
  return useQuery({
    queryKey: ["secrets", id],
    queryFn: () => secretService.getById(id),
    enabled: !!id,
  });
}

export function useCreateSecret() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateSecretData) => secretService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      toast.success("Secret created successfully");
    },
    onError: () => {
      toast.error("Failed to create secret");
    },
  });
}

export function useUpdateSecret() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      secretService.update(id, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      toast.success("Secret updated successfully");
    },
    onError: () => {
      toast.error("Failed to update secret");
    },
  });
}

export function useDeleteSecret() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => secretService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      toast.success("Secret deleted successfully");
    },
    onError: () => {
      toast.error("Failed to delete secret");
    },
  });
}

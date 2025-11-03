import { apiClient } from "@/lib/api";

export interface Secret {
  id: string;
  key: string;
  value: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  vaultId: string;
}

export interface CreateSecretData {
  key: string;
  value: string;
  vaultId: string;
}

export const secretService = {
  getAll: async (vaultId?: string): Promise<Secret[]> => {
    const response = await apiClient.get("/secrets", {
      params: { vaultId },
    });
    return response.data;
  },

  getById: async (id: string): Promise<Secret> => {
    const response = await apiClient.get(`/secrets/${id}`);
    return response.data;
  },

  create: async (data: CreateSecretData): Promise<Secret> => {
    const response = await apiClient.post("/secrets", data);
    return response.data;
  },

  update: async (id: string, value: string): Promise<Secret> => {
    const response = await apiClient.put(`/secrets/${id}`, { value });
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/secrets/${id}`);
  },
};

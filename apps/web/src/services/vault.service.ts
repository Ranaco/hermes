import { apiClient } from "@/lib/api";

export interface Vault {
  id: string;
  name: string;
  description: string;
  status: "active" | "locked";
  createdAt: string;
  updatedAt: string;
  organizationId: string;
}

export interface CreateVaultData {
  name: string;
  description: string;
  organizationId: string;
}

export const vaultService = {
  getAll: async (): Promise<Vault[]> => {
    const response = await apiClient.get("/vaults");
    return response.data;
  },

  getById: async (id: string): Promise<Vault> => {
    const response = await apiClient.get(`/vaults/${id}`);
    return response.data;
  },

  create: async (data: CreateVaultData): Promise<Vault> => {
    const response = await apiClient.post("/vaults", data);
    return response.data;
  },

  update: async (id: string, data: Partial<CreateVaultData>): Promise<Vault> => {
    const response = await apiClient.put(`/vaults/${id}`, data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/vaults/${id}`);
  },
};

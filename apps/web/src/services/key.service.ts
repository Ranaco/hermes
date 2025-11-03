import { apiClient } from "@/lib/api";

export interface Key {
  id: string;
  name: string;
  type: "encryption" | "signing" | "hmac";
  algorithm: string;
  status: "active" | "inactive" | "rotated";
  createdAt: string;
  updatedAt: string;
  vaultId: string;
}

export interface CreateKeyData {
  name: string;
  type: "encryption" | "signing" | "hmac";
  algorithm: string;
  vaultId: string;
}

export const keyService = {
  getAll: async (): Promise<Key[]> => {
    const response = await apiClient.get("/keys");
    return response.data;
  },

  getById: async (id: string): Promise<Key> => {
    const response = await apiClient.get(`/keys/${id}`);
    return response.data;
  },

  create: async (data: CreateKeyData): Promise<Key> => {
    const response = await apiClient.post("/keys", data);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/keys/${id}`);
  },

  rotate: async (id: string): Promise<Key> => {
    const response = await apiClient.post(`/keys/${id}/rotate`);
    return response.data;
  },

  encrypt: async (keyId: string, plaintext: string): Promise<{ ciphertext: string }> => {
    const response = await apiClient.post(`/keys/${keyId}/encrypt`, { plaintext });
    return response.data;
  },

  decrypt: async (keyId: string, ciphertext: string): Promise<{ plaintext: string }> => {
    const response = await apiClient.post(`/keys/${keyId}/decrypt`, { ciphertext });
    return response.data;
  },
};

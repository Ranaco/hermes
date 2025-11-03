"use client";

import { useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useSecrets, useCreateSecret, useDeleteSecret } from "@/hooks/use-secrets";
import { Plus, Trash2, Search, Lock, Eye, EyeOff } from "lucide-react";
import { formatDateTime } from "@/lib/utils";

export default function SecretsPage() {
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [visibleSecrets, setVisibleSecrets] = useState<Set<string>>(new Set());
  const [newSecret, setNewSecret] = useState({
    key: "",
    value: "",
    vaultId: "",
  });

  const { data: secrets, isLoading } = useSecrets();
  const { mutate: createSecret, isPending: isCreating } = useCreateSecret();
  const { mutate: deleteSecret } = useDeleteSecret();

  const filteredSecrets = secrets?.filter((secret) =>
    secret.key.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const toggleSecretVisibility = (id: string) => {
    const newVisible = new Set(visibleSecrets);
    if (newVisible.has(id)) {
      newVisible.delete(id);
    } else {
      newVisible.add(id);
    }
    setVisibleSecrets(newVisible);
  };

  const handleCreateSecret = (e: React.FormEvent) => {
    e.preventDefault();
    createSecret(newSecret, {
      onSuccess: () => {
        setShowCreateDialog(false);
        setNewSecret({ key: "", value: "", vaultId: "" });
      },
    });
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2">Secrets</h1>
            <p className="text-muted-foreground text-lg">
              Manage your sensitive data
            </p>
          </div>
          <Button
            onClick={() => setShowCreateDialog(!showCreateDialog)}
            className="shadow-md"
            size="lg"
          >
            <Plus className="mr-2 h-5 w-5" />
            Create Secret
          </Button>
        </div>

        {/* Create Secret Form */}
        {showCreateDialog && (
          <Card className="shadow-lg border-primary/20">
            <CardHeader>
              <CardTitle>Create New Secret</CardTitle>
              <CardDescription>Store a new secret securely</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateSecret} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="secret-key">Secret Key</Label>
                  <Input
                    id="secret-key"
                    placeholder="DATABASE_PASSWORD"
                    value={newSecret.key}
                    onChange={(e) => setNewSecret({ ...newSecret, key: e.target.value })}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="secret-value">Secret Value</Label>
                  <Input
                    id="secret-value"
                    type="password"
                    placeholder="your-secret-value"
                    value={newSecret.value}
                    onChange={(e) => setNewSecret({ ...newSecret, value: e.target.value })}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="vault-id">Vault ID</Label>
                  <Input
                    id="vault-id"
                    placeholder="vault-id"
                    value={newSecret.vaultId}
                    onChange={(e) => setNewSecret({ ...newSecret, vaultId: e.target.value })}
                    required
                  />
                </div>
                <div className="flex gap-3 justify-end">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowCreateDialog(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={isCreating}>
                    {isCreating ? "Creating..." : "Create Secret"}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search secrets..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        {/* Secrets List */}
        <div className="grid gap-4">
          {isLoading ? (
            <Card className="shadow-md">
              <CardContent className="py-12 text-center text-muted-foreground">
                Loading secrets...
              </CardContent>
            </Card>
          ) : filteredSecrets && filteredSecrets.length > 0 ? (
            filteredSecrets.map((secret) => (
              <Card key={secret.id} className="shadow-md hover:shadow-lg transition-shadow">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4 flex-1">
                      <div className="p-3 bg-secondary/10 border-2 border-border">
                        <Lock className="h-6 w-6 text-secondary" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-xl font-bold mb-1">{secret.key}</h3>
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline">v{secret.version}</Badge>
                        </div>
                        <div className="flex items-center gap-2 mb-2">
                          <code className="text-sm bg-muted px-3 py-1 border-2 border-border font-mono">
                            {visibleSecrets.has(secret.id)
                              ? secret.value
                              : "••••••••••••••••"}
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => toggleSecretVisibility(secret.id)}
                          >
                            {visibleSecrets.has(secret.id) ? (
                              <EyeOff className="h-4 w-4" />
                            ) : (
                              <Eye className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Updated: {formatDateTime(secret.updatedAt)}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          ID: {secret.id}
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="destructive"
                        size="icon"
                        onClick={() => {
                          if (confirm(`Are you sure you want to delete "${secret.key}"?`)) {
                            deleteSecret(secret.id);
                          }
                        }}
                        title="Delete Secret"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          ) : (
            <Card className="shadow-md">
              <CardContent className="py-12 text-center">
                <Lock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground text-lg">
                  {searchQuery ? "No secrets found matching your search" : "No secrets yet"}
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}

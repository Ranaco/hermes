"use client";

import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useKeys } from "@/hooks/use-keys";
import { useSecrets } from "@/hooks/use-secrets";
import { useVaults } from "@/hooks/use-vaults";
import { Key, Lock, Vault, TrendingUp, Activity } from "lucide-react";

export default function DashboardPage() {
  const { data: keys, isLoading: keysLoading } = useKeys();
  const { data: secrets, isLoading: secretsLoading } = useSecrets();
  const { data: vaults, isLoading: vaultsLoading } = useVaults();

  const stats = [
    {
      name: "Total Keys",
      value: keys?.length || 0,
      icon: Key,
      change: "+12%",
      color: "text-chart-1",
      bg: "bg-chart-1/10",
    },
    {
      name: "Total Secrets",
      value: secrets?.length || 0,
      icon: Lock,
      change: "+8%",
      color: "text-chart-2",
      bg: "bg-chart-2/10",
    },
    {
      name: "Active Vaults",
      value: vaults?.filter((v) => v.status === "active").length || 0,
      icon: Vault,
      change: "+3%",
      color: "text-chart-3",
      bg: "bg-chart-3/10",
    },
    {
      name: "Operations Today",
      value: 1247,
      icon: Activity,
      change: "+18%",
      color: "text-chart-4",
      bg: "bg-chart-4/10",
    },
  ];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Welcome Section */}
        <div>
          <h1 className="text-4xl font-bold mb-2">Dashboard</h1>
          <p className="text-muted-foreground text-lg">
            Welcome back! Here's what's happening with your KMS.
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat) => (
            <Card key={stat.name} className="shadow-md hover:shadow-lg transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {stat.name}
                </CardTitle>
                <div className={`p-2 ${stat.bg} border-2 border-border`}>
                  <stat.icon className={`h-5 w-5 ${stat.color}`} />
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {keysLoading || secretsLoading || vaultsLoading ? (
                    <span className="text-muted-foreground">...</span>
                  ) : (
                    stat.value
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                  <TrendingUp className="h-3 w-3 text-chart-4" />
                  {stat.change} from last month
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Recent Activity */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="shadow-md">
            <CardHeader>
              <CardTitle>Recent Keys</CardTitle>
              <CardDescription>Latest encryption keys created</CardDescription>
            </CardHeader>
            <CardContent>
              {keysLoading ? (
                <div className="text-muted-foreground">Loading...</div>
              ) : keys && keys.length > 0 ? (
                <div className="space-y-3">
                  {keys.slice(0, 5).map((key) => (
                    <div
                      key={key.id}
                      className="flex items-center justify-between p-3 border-2 border-border hover:bg-muted/50 transition-colors"
                    >
                      <div>
                        <p className="font-medium">{key.name}</p>
                        <p className="text-xs text-muted-foreground">{key.type}</p>
                      </div>
                      <div className={`px-2 py-1 text-xs font-medium border-2 border-border ${
                        key.status === "active"
                          ? "bg-chart-4/20 text-chart-4"
                          : "bg-muted text-muted-foreground"
                      }`}>
                        {key.status}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No keys found
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="shadow-md">
            <CardHeader>
              <CardTitle>Active Vaults</CardTitle>
              <CardDescription>Your secure storage vaults</CardDescription>
            </CardHeader>
            <CardContent>
              {vaultsLoading ? (
                <div className="text-muted-foreground">Loading...</div>
              ) : vaults && vaults.length > 0 ? (
                <div className="space-y-3">
                  {vaults.slice(0, 5).map((vault) => (
                    <div
                      key={vault.id}
                      className="flex items-center justify-between p-3 border-2 border-border hover:bg-muted/50 transition-colors"
                    >
                      <div>
                        <p className="font-medium">{vault.name}</p>
                        <p className="text-xs text-muted-foreground truncate max-w-[200px]">
                          {vault.description}
                        </p>
                      </div>
                      <div className={`px-2 py-1 text-xs font-medium border-2 border-border ${
                        vault.status === "active"
                          ? "bg-chart-4/20 text-chart-4"
                          : "bg-destructive/20 text-destructive"
                      }`}>
                        {vault.status}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No vaults found
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
}
